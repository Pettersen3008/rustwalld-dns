use crate::{PolicyController, PublicationError};
use crate::{
    decision_cache::{DecisionKey, DecisionLookup},
    reply,
    telemetry::{QueryEvent, QuerySource, ShadowDecision, Telemetry},
};
use arc_swap::{ArcSwap, ArcSwapOption, Guard};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RecordType},
    serialize::binary::{BinEncodable, BinEncoder},
};
use rustwalld_dns_filter::{Action, Decision};
use rustwalld_dns_policy::{CompiledPolicy, PolicySnapshot, TemporaryMatch};
use rustwalld_dns_resolver::{
    Forwarder, Lookup, ResolutionSource, Resolver, cache::BoundedCache, response_cache::CacheKey,
};
use std::{
    net::IpAddr,
    sync::{Arc, atomic::Ordering},
    time::Instant,
};

/// Transport a query arrived on; it selects the reply size limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    /// Replies honour the client's EDNS payload size, clamped to 512..=1232
    /// bytes, and set TC when truncated.
    Udp,
    /// Replies may use the full DNS message size.
    Tcp,
}

/// Outcome of [`Engine::prepare`], the synchronous part of answering a query.
#[must_use = "a prepared query must be replied to, forwarded or dropped"]
pub enum Prepared {
    /// Send nothing: malformed input, a response message or a client outside
    /// the access list.
    Drop,
    /// A complete wire reply produced without waiting: a refusal, block,
    /// rewrite or response-cache hit.
    Reply(Vec<u8>),
    /// A response-cache miss that must wait on an upstream. Finish it with
    /// [`Engine::forward`], or shed it with [`Engine::reject`].
    Forward(PendingQuery),
}
impl From<Option<Vec<u8>>> for Prepared {
    fn from(reply: Option<Vec<u8>>) -> Self {
        reply.map_or(Self::Drop, Self::Reply)
    }
}

/// A validated, policy-checked query waiting for upstream resolution. It pins
/// the policy generation that admitted it.
pub struct PendingQuery(Box<Pending>);
struct Pending {
    start: Instant,
    client: IpAddr,
    transport: Transport,
    request: Message,
    snapshot: Arc<PolicySnapshot>,
    domain: String,
    qtype: u16,
    decision: Decision,
    decision_cached: bool,
    /// Admitted by a temporary exception, which must still hold afterwards.
    excepted: bool,
    key: CacheKey,
    upstream: Arc<Forwarder>,
}

/// How a query is answered once policy has been applied.
enum Step {
    Local(Message, QuerySource),
    Miss(CacheKey, Arc<Forwarder>),
}

/// Everything known about a query once its reply message exists.
struct Outcome<'a> {
    start: Instant,
    client: IpAddr,
    transport: Transport,
    request: &'a Message,
    policy: &'a CompiledPolicy,
    generation: u64,
    domain: String,
    qtype: u16,
    decision: Decision,
    decision_cached: bool,
    /// The query was admitted by a temporary exception.
    excepted: bool,
    /// That exception, if it is still in force.
    exception: Option<TemporaryMatch<'a>>,
    response: Message,
    source: QuerySource,
}

/// Named bounds for caches and upstream work. Zero cache sizes disable caching.
#[derive(Clone, Copy, Debug)]
pub struct EngineConfig {
    pub cache_entries: usize,
    pub decision_entries: usize,
    pub max_inflight: usize,
}
impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            cache_entries: 4096,
            decision_entries: 16384,
            max_inflight: 256,
        }
    }
}

/// DNS request processor. Policy writes require the separately returned controller.
///
/// ```compile_fail
/// use rustwalld_dns_core::{Engine, PolicySnapshot};
/// use std::sync::Arc;
/// fn bypass(engine: &Engine, snapshot: Arc<PolicySnapshot>) {
///     engine.active.store(snapshot);
/// }
/// ```
pub struct Engine {
    active: Arc<ArcSwap<PolicySnapshot>>,
    shadow: Arc<ArcSwapOption<PolicySnapshot>>,
    pub(crate) resolver: Arc<Resolver>,
    telemetry: Telemetry,
    decisions: BoundedCache<DecisionKey, Decision>,
}
impl Engine {
    /// Construct a serving engine with named limits and fixed initial policy.
    pub fn with_config(
        snapshot: PolicySnapshot,
        config: EngineConfig,
        telemetry: Telemetry,
    ) -> Self {
        Self::controlled(snapshot, config, telemetry).0
    }
    /// Construct a serving engine and a separate policy write capability.
    pub fn controlled(
        snapshot: PolicySnapshot,
        config: EngineConfig,
        telemetry: Telemetry,
    ) -> (Self, PolicyController) {
        let highest = snapshot.generation();
        Self::build(snapshot, None, highest, config, telemetry)
    }
    /// Restore validated durable snapshots into an engine with empty volatile caches.
    /// `highest` must include all durable revisions, including retired ones.
    pub fn restore(
        snapshot: PolicySnapshot,
        shadow: Option<PolicySnapshot>,
        highest: u64,
        config: EngineConfig,
        telemetry: Telemetry,
    ) -> Result<(Self, PolicyController), PublicationError> {
        if highest < snapshot.generation()
            || shadow.as_ref().is_some_and(|s| {
                highest < s.generation() || s.generation() == snapshot.generation()
            })
        {
            return Err(PublicationError::Restore);
        }
        Ok(Self::build(snapshot, shadow, highest, config, telemetry))
    }
    fn build(
        snapshot: PolicySnapshot,
        shadow: Option<PolicySnapshot>,
        highest: u64,
        config: EngineConfig,
        telemetry: Telemetry,
    ) -> (Self, PolicyController) {
        let active = Arc::new(ArcSwap::from_pointee(snapshot));
        let shadow = Arc::new(ArcSwapOption::new(shadow.map(Arc::new)));
        let controller = PolicyController::new(active.clone(), shadow.clone(), highest);
        (
            Self {
                active,
                shadow,
                resolver: Resolver::new(config.cache_entries, config.max_inflight),
                telemetry,
                decisions: BoundedCache::new(config.decision_entries),
            },
            controller,
        )
    }
    /// Whether a publication capability belongs to this engine instance.
    pub fn is_controlled_by(&self, controller: &PolicyController) -> bool {
        controller.controls(&self.active)
    }
    /// Read active policy without a write handle or a full Arc clone.
    #[inline]
    pub fn active(&self) -> Guard<Arc<PolicySnapshot>> {
        self.active.load()
    }
    /// Pin an active snapshot for asynchronous control-plane work.
    pub fn snapshot(&self) -> Arc<PolicySnapshot> {
        self.active.load_full()
    }
    /// Read shadow policy without exposing its write handle.
    #[inline]
    pub fn shadow(&self) -> Guard<Option<Arc<PolicySnapshot>>> {
        self.shadow.load()
    }
    /// Pin a shadow snapshot across asynchronous work.
    pub fn shadow_snapshot(&self) -> Option<Arc<PolicySnapshot>> {
        self.shadow.load_full()
    }
    /// Resolver observations and bounded cache inspection.
    #[inline]
    pub fn resolver(&self) -> &Arc<Resolver> {
        &self.resolver
    }
    /// Nonblocking event delivery and aggregate metrics.
    #[inline]
    pub fn telemetry(&self) -> &Telemetry {
        &self.telemetry
    }
    /// Choose event delivery before sharing this engine between tasks.
    pub fn with_telemetry(mut self, telemetry: Telemetry) -> Self {
        self.telemetry = telemetry;
        self
    }
    /// Answer one wire query: [`Engine::prepare`] followed, for cache misses, by
    /// [`Engine::forward`]. Returns `None` when nothing should be sent.
    pub async fn answer(
        &self,
        bytes: &[u8],
        client: IpAddr,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        match self.prepare(bytes, client, transport) {
            Prepared::Drop => None,
            Prepared::Reply(reply) => Some(reply),
            Prepared::Forward(pending) => self.forward(pending).await,
        }
    }

    /// Parse, validate and apply policy without waiting. Refusals, blocks,
    /// rewrites and response-cache hits are answered here; only cache misses
    /// need [`Engine::forward`]. Servers can therefore bound slow upstream
    /// waits separately from fast local answers.
    pub fn prepare(&self, bytes: &[u8], client: IpAddr, transport: Transport) -> Prepared {
        let client = client.to_canonical();
        let start = Instant::now();
        let snapshot = self.active.load_full();
        if !snapshot.permits(client) {
            return Prepared::Drop;
        }
        let Ok(request) = Message::from_vec(bytes) else {
            return Prepared::Drop;
        };
        if request.metadata.message_type != MessageType::Query {
            return Prepared::Drop;
        }
        self.telemetry
            .metrics
            .requests
            .fetch_add(1, Ordering::Relaxed);
        let question = match accepted_question(&request) {
            Ok(question) => question,
            Err(code) => {
                let response = finalize(&request, reply(&request, code));
                let output = encode(&request, &response, transport);
                if output.is_some() {
                    self.telemetry.metrics.observe(start);
                }
                return output.into();
            }
        };
        let policy = snapshot.select(client).policy;
        let mut domain = canonical_ascii(question.name());
        // Only the trailing root dot is removed, preserving Hickory's escapes
        // within DNS labels.
        if domain.ends_with('.') {
            domain.pop();
        }
        let qtype = u16::from(question.query_type());
        let rewrite = policy.rewrite(&domain, question.query_type());
        let exception = if rewrite.is_none() {
            policy.temporary_allow(&domain, start)
        } else {
            None
        };
        let (decision, decision_cached) = if rewrite.is_some() || exception.is_some() {
            (Decision::ALLOW, false)
        } else {
            self.decide(policy, &domain, snapshot.generation())
        };
        let step = if let Some(records) = rewrite {
            self.telemetry
                .metrics
                .rewrites
                .fetch_add(1, Ordering::Relaxed);
            let mut response = reply(&request, ResponseCode::NoError);
            response.answers = records;
            Step::Local(response, QuerySource::Rewrite)
        } else if decision.action == Action::Block {
            self.telemetry
                .metrics
                .blocked
                .fetch_add(1, Ordering::Relaxed);
            Step::Local(
                reply(&request, ResponseCode::NXDomain),
                QuerySource::Blocked,
            )
        } else if let Some(upstream) = snapshot.upstreams().get(policy.upstream()) {
            match self.resolver.lookup(&request, upstream) {
                Ok(Lookup::Hit(response)) => Step::Local(response, QuerySource::Cache),
                Ok(Lookup::Miss(key)) => Step::Miss(key, upstream.clone()),
                Err(_) => Step::Local(
                    reply(&request, ResponseCode::ServFail),
                    QuerySource::Failure,
                ),
            }
        } else {
            // Compilation validates profile indexes; never panic on the query path.
            Step::Local(
                reply(&request, ResponseCode::ServFail),
                QuerySource::Failure,
            )
        };
        match step {
            Step::Local(response, source) => {
                let excepted = exception.is_some();
                self.finish(Outcome {
                    start,
                    client,
                    transport,
                    request: &request,
                    policy,
                    generation: snapshot.generation(),
                    domain,
                    qtype,
                    decision,
                    decision_cached,
                    excepted,
                    exception,
                    response,
                    source,
                })
                .into()
            }
            Step::Miss(key, upstream) => {
                let excepted = exception.is_some();
                Prepared::Forward(PendingQuery(Box::new(Pending {
                    start,
                    client,
                    transport,
                    request,
                    snapshot,
                    domain,
                    qtype,
                    decision,
                    decision_cached,
                    excepted,
                    key,
                    upstream,
                })))
            }
        }
    }

    /// Resolve a prepared cache miss upstream (coalescing identical misses) and
    /// encode the reply under the generation that admitted the query.
    pub async fn forward(&self, pending: PendingQuery) -> Option<Vec<u8>> {
        let pending = pending.0;
        let resolved = self
            .resolver
            .forward(
                &pending.request,
                pending.key.clone(),
                pending.upstream.clone(),
            )
            .await;
        let (response, source) = match resolved {
            Ok(result) => (
                result.response,
                match result.source {
                    ResolutionSource::Cache => QuerySource::Cache,
                    ResolutionSource::Upstream => QuerySource::Upstream,
                    ResolutionSource::Coalesced => QuerySource::Coalesced,
                },
            ),
            Err(_) => (
                reply(&pending.request, ResponseCode::ServFail),
                QuerySource::Failure,
            ),
        };
        self.complete(pending, response, source)
    }

    /// Answer a prepared cache miss with SERVFAIL without forwarding it, for
    /// servers shedding load when too many queries already wait on upstreams.
    pub fn reject(&self, pending: PendingQuery) -> Option<Vec<u8>> {
        let pending = pending.0;
        let response = reply(&pending.request, ResponseCode::ServFail);
        self.complete(pending, response, QuerySource::Failure)
    }

    fn complete(
        &self,
        pending: Box<Pending>,
        response: Message,
        source: QuerySource,
    ) -> Option<Vec<u8>> {
        let Pending {
            start,
            client,
            transport,
            request,
            snapshot,
            domain,
            qtype,
            decision,
            decision_cached,
            excepted,
            ..
        } = *pending;
        // Selection is deterministic for a pinned generation and client.
        let policy = snapshot.select(client).policy;
        let exception = if excepted {
            policy.temporary_allow(&domain, Instant::now())
        } else {
            None
        };
        self.finish(Outcome {
            start,
            client,
            transport,
            request: &request,
            policy,
            generation: snapshot.generation(),
            domain,
            qtype,
            decision,
            decision_cached,
            excepted,
            exception,
            response,
            source,
        })
    }

    /// Filter decision through the per-generation decision cache.
    fn decide(&self, policy: &CompiledPolicy, domain: &str, generation: u64) -> (Decision, bool) {
        let key = DecisionLookup {
            domain,
            policy: policy.id(),
            generation,
        };
        if let Some(decision) = self.decisions.get(&key) {
            self.telemetry
                .metrics
                .decision_hits
                .fetch_add(1, Ordering::Relaxed);
            return (decision, true);
        }
        let decision = policy.filters().evaluate(domain);
        self.decisions.insert(
            DecisionKey {
                domain: domain.to_owned(),
                policy: key.policy,
                generation,
            },
            decision,
        );
        (decision, false)
    }

    /// Apply exception expiry and TTL limits, evaluate shadow policy, encode the
    /// reply and emit telemetry. Shared by local answers and forwarded misses.
    fn finish(&self, mut outcome: Outcome<'_>) -> Option<Vec<u8>> {
        let metrics = &self.telemetry.metrics;
        let live = outcome.exception.as_ref().and_then(|found| {
            found
                .remaining_ttl(Instant::now())
                .map(|ttl| (found.index, ttl))
        });
        let temporary_exception = if let Some((index, ttl)) = live {
            // Only this client's private response copy is constrained.
            let response = &mut outcome.response;
            for record in response
                .answers
                .iter_mut()
                .chain(&mut response.authorities)
                .chain(&mut response.additionals)
            {
                record.ttl = record.ttl.min(ttl);
            }
            metrics.temporary_allows.fetch_add(1, Ordering::Relaxed);
            Some(index)
        } else {
            if outcome.excepted {
                // An upstream/coalesced wait cannot carry an allow across expiry.
                outcome.decision = outcome.policy.filters().evaluate(&outcome.domain);
                if outcome.decision.action == Action::Block {
                    metrics.blocked.fetch_add(1, Ordering::Relaxed);
                    outcome.response = reply(outcome.request, ResponseCode::NXDomain);
                    outcome.source = QuerySource::Blocked;
                }
            }
            None
        };
        if outcome.source == QuerySource::Failure {
            metrics.failures.fetch_add(1, Ordering::Relaxed);
        }
        let shadow = self.shadow_decision(&outcome);
        let response = finalize(outcome.request, outcome.response);
        let output = encode(outcome.request, &response, outcome.transport)?;
        let latency_us = metrics.observe(outcome.start);
        self.telemetry.emit(QueryEvent {
            client: outcome.client,
            // Matching is finished: move the normalized name into telemetry.
            domain: outcome.domain,
            qtype: outcome.qtype,
            generation: outcome.generation,
            policy: outcome.policy.id(),
            decision: outcome.decision,
            decision_cached: outcome.decision_cached,
            response_code: u16::from(response.metadata.response_code),
            source: outcome.source,
            latency_us,
            shadow,
            temporary_exception,
        });
        Some(output)
    }

    /// How the shadow generation, if any, would have decided this query.
    fn shadow_decision(&self, outcome: &Outcome<'_>) -> Option<ShadowDecision> {
        let shadow = self.shadow.load();
        let shadow = shadow.as_ref()?;
        let selected = shadow.select(outcome.client).policy;
        let rewrite = selected.has_rewrite(&outcome.domain);
        let temporary = if rewrite {
            None
        } else {
            selected.temporary_allow(&outcome.domain, Instant::now())
        };
        let decision = if rewrite || temporary.is_some() {
            Decision::ALLOW
        } else {
            selected.filters().evaluate(&outcome.domain)
        };
        let differs = decision.action != outcome.decision.action
            || rewrite != (outcome.source == QuerySource::Rewrite);
        if differs {
            self.telemetry
                .metrics
                .shadow_differences
                .fetch_add(1, Ordering::Relaxed);
        }
        Some(ShadowDecision {
            generation: shadow.generation(),
            policy: selected.id(),
            decision,
            rewrite,
            differs,
            temporary_exception: temporary.map(|found| found.index),
        })
    }
}

/// The single question of a query this engine serves, or the reply code that
/// refuses it. EDNS options are ignored as RFC 6891 requires: none are
/// forwarded (upstream requests carry a fresh EDNS envelope), so they cannot
/// alter cached content.
fn accepted_question(request: &Message) -> Result<&Query, ResponseCode> {
    if request.metadata.op_code != OpCode::Query {
        return Err(ResponseCode::NotImp);
    }
    let [question] = request.queries.as_slice() else {
        return Err(ResponseCode::FormErr);
    };
    if !request.metadata.recursion_desired
        || question.query_class() != DNSClass::IN
        || matches!(
            question.query_type(),
            RecordType::AXFR | RecordType::IXFR | RecordType::ANY
        )
        || request.signature.is_some()
        || !request.answers.is_empty()
        || !request.authorities.is_empty()
        || !request.additionals.is_empty()
    {
        return Err(ResponseCode::Refused);
    }
    if request.version() != 0 {
        return Err(ResponseCode::BADVERS);
    }
    Ok(question)
}

/// Restore the client's ID, flags, question and EDNS envelope on a reply that
/// may come from a shared cache entry or coalesced flight.
fn finalize(request: &Message, mut response: Message) -> Message {
    response.metadata.id = request.metadata.id;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.checking_disabled = request.metadata.checking_disabled;
    response.metadata.authentic_data = false;
    if request.queries.len() == 1 {
        response.queries.clone_from(&request.queries);
    }
    response.edns = request.edns.as_ref().map(|edns| {
        let mut out = Edns::new();
        out.set_max_payload(edns.max_payload().clamp(512, 1232));
        out.set_dnssec_ok(edns.flags().dnssec_ok);
        out
    });
    response
}

/// Wire-encode a reply within the transport's size limit; UDP replies that do
/// not fit are truncated with TC set.
fn encode(request: &Message, response: &Message, transport: Transport) -> Option<Vec<u8>> {
    let max = match transport {
        Transport::Tcp => u16::MAX,
        Transport::Udp => request.max_payload().clamp(512, 1232),
    };
    let mut output = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut output);
    encoder.set_max_size(max);
    response.emit(&mut encoder).ok()?;
    Some(output)
}

fn canonical_ascii(name: &Name) -> String {
    // Hickory emits ASCII letters literally, and other bytes as escaped
    // punctuation or octal digits. Lowercasing the output therefore preserves
    // its label boundaries and escapes without copying the intermediate Name.
    let mut ascii = name.to_ascii();
    ascii.make_ascii_lowercase();
    ascii
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn canonical_ascii_preserves_hickory_escaping_and_case_semantics() {
        let check = |mut name: Name| {
            for fqdn in [true, false] {
                name.set_fqdn(fqdn);
                assert_eq!(canonical_ascii(&name), name.to_lowercase().to_ascii());
            }
        };
        check(Name::root());
        // Every byte at the start, middle and end of a label, including dots,
        // backslashes, controls, wildcard characters and non-ASCII wire bytes.
        for byte in 0..=u8::MAX {
            for label in [[byte, b'A', b'Z'], [b'A', byte, b'Z'], [b'A', b'Z', byte]] {
                check(Name::from_labels([label.as_slice(), b"ExAmPlE".as_slice()]).unwrap());
            }
            let labels = [
                vec![byte; 63],
                vec![b'A'; 63],
                vec![b'Z'; 63],
                vec![b'B'; 61],
            ];
            check(Name::from_labels(labels.iter().map(Vec::as_slice)).unwrap());
        }
        check(Name::from_labels(std::iter::repeat_n(b"A".as_slice(), 127)).unwrap());
    }
}

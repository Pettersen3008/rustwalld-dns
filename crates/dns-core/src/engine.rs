use crate::{PolicyController, PublicationError};
use crate::{
    decision_cache::{DecisionKey, DecisionLookup},
    reply,
    telemetry::{QueryEvent, QuerySource, ShadowDecision, Telemetry},
};
use arc_swap::{ArcSwap, Guard};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, Name, RecordType},
    serialize::binary::{BinEncodable, BinEncoder},
};
use rustwalld_dns_filter::{Action, Decision};
use rustwalld_dns_policy::PolicySnapshot;
use rustwalld_dns_resolver::{ResolutionSource, Resolver, cache::BoundedCache};
use std::{
    net::IpAddr,
    sync::{Arc, atomic::Ordering},
    time::Instant,
};
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
    shadow: Arc<arc_swap::ArcSwapOption<PolicySnapshot>>,
    pub(crate) resolver: Arc<Resolver>,
    telemetry: Telemetry,
    decisions: BoundedCache<DecisionKey, Decision>,
}
impl Engine {
    /// Construct a serving engine with fixed initial policy and legacy positional limits.
    /// Use `with_config` for named limits, or `controlled` for policy updates.
    pub fn new(
        snapshot: PolicySnapshot,
        cache_entries: usize,
        decision_entries: usize,
        max_inflight: usize,
        telemetry: Telemetry,
    ) -> Self {
        Self::with_config(
            snapshot,
            EngineConfig {
                cache_entries,
                decision_entries,
                max_inflight,
            },
            telemetry,
        )
    }
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
        let shadow = Arc::new(arc_swap::ArcSwapOption::new(shadow.map(Arc::new)));
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
    pub async fn answer(&self, bytes: &[u8], client: IpAddr, tcp: bool) -> Option<Vec<u8>> {
        let client = client.to_canonical();
        let start = Instant::now();
        let snapshot = self.active.load_full();
        if !snapshot.permits(client) {
            return None;
        }
        let request = Message::from_vec(bytes).ok()?;
        if request.metadata.message_type != MessageType::Query {
            return None;
        }
        self.telemetry
            .metrics
            .requests
            .fetch_add(1, Ordering::Relaxed);
        let code = if request.metadata.op_code != OpCode::Query {
            Some(ResponseCode::NotImp)
        } else if request.queries.len() != 1 {
            Some(ResponseCode::FormErr)
        } else if !request.metadata.recursion_desired
            || request.queries[0].query_class() != DNSClass::IN
            || matches!(
                request.queries[0].query_type(),
                RecordType::AXFR | RecordType::IXFR | RecordType::ANY
            )
            || request.signature.is_some()
            || !request.answers.is_empty()
            || !request.authorities.is_empty()
            || !request.additionals.is_empty()
            || request
                .edns
                .as_ref()
                .is_some_and(|edns| !edns.options().as_ref().is_empty())
        {
            Some(ResponseCode::Refused)
        } else if request.version() != 0 {
            Some(ResponseCode::BADVERS)
        } else {
            None
        };
        let mut event = None;
        let mut response = if let Some(code) = code {
            reply(&request, code)
        } else {
            let selected = snapshot.select(client);
            let policy = selected.policy;
            let mut ascii = canonical_ascii(request.queries[0].name());
            let domain = ascii.strip_suffix('.').unwrap_or(&ascii);
            let rewrite = policy.rewrite(domain, request.queries[0].query_type());
            let mut temporary = if rewrite.is_none() {
                policy.temporary_allow(domain, start)
            } else {
                None
            };
            let mut decision_cached = false;
            let mut decision = if rewrite.is_some() || temporary.is_some() {
                Decision::ALLOW
            } else {
                let key = DecisionLookup {
                    domain,
                    policy: policy.id(),
                    generation: snapshot.generation(),
                };
                if let Some(decision) = self.decisions.get(&key) {
                    decision_cached = true;
                    self.telemetry
                        .metrics
                        .decision_hits
                        .fetch_add(1, Ordering::Relaxed);
                    decision
                } else {
                    let decision = policy.filters().evaluate(domain);
                    self.decisions.insert(
                        DecisionKey {
                            domain: domain.to_owned(),
                            policy: key.policy,
                            generation: key.generation,
                        },
                        decision,
                    );
                    decision
                }
            };
            let (mut response, mut source) = if let Some(records) = rewrite {
                self.telemetry
                    .metrics
                    .rewrites
                    .fetch_add(1, Ordering::Relaxed);
                let mut response = reply(&request, ResponseCode::NoError);
                response.answers = records;
                (response, QuerySource::Rewrite)
            } else if decision.action == Action::Block {
                self.telemetry
                    .metrics
                    .blocked
                    .fetch_add(1, Ordering::Relaxed);
                (
                    reply(&request, ResponseCode::NXDomain),
                    QuerySource::Blocked,
                )
            } else {
                match self
                    .resolver
                    .resolve(&request, snapshot.upstreams()[policy.upstream()].clone())
                    .await
                {
                    Ok(result) => (
                        result.response,
                        match result.source {
                            ResolutionSource::Cache => QuerySource::Cache,
                            ResolutionSource::Upstream => QuerySource::Upstream,
                            ResolutionSource::Coalesced => QuerySource::Coalesced,
                        },
                    ),
                    Err(_) => (
                        reply(&request, ResponseCode::ServFail),
                        QuerySource::Failure,
                    ),
                }
            };
            if let Some(found) = &temporary {
                if let Some(ttl) = found.remaining_ttl(Instant::now()) {
                    // Only this client's private response copy is constrained.
                    for record in response
                        .answers
                        .iter_mut()
                        .chain(&mut response.authorities)
                        .chain(&mut response.additionals)
                    {
                        record.ttl = record.ttl.min(ttl);
                    }
                    self.telemetry
                        .metrics
                        .temporary_allows
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    // An upstream/coalesced wait cannot carry an allow across expiry.
                    temporary = None;
                    decision = policy.filters().evaluate(domain);
                    if decision.action == Action::Block {
                        self.telemetry
                            .metrics
                            .blocked
                            .fetch_add(1, Ordering::Relaxed);
                        response = reply(&request, ResponseCode::NXDomain);
                        source = QuerySource::Blocked;
                    }
                }
            }
            if source == QuerySource::Failure {
                self.telemetry
                    .metrics
                    .failures
                    .fetch_add(1, Ordering::Relaxed);
            }
            let shadow = self.shadow.load_full().map(|shadow| {
                let selected = shadow.select(client);
                let rewrite = selected.policy.has_rewrite(domain);
                let temporary = if rewrite {
                    None
                } else {
                    selected.policy.temporary_allow(domain, Instant::now())
                };
                let shadow_decision = if rewrite || temporary.is_some() {
                    Decision::ALLOW
                } else {
                    selected.policy.filters().evaluate(domain)
                };
                let differs = shadow_decision.action != decision.action
                    || rewrite != (source == QuerySource::Rewrite);
                if differs {
                    self.telemetry
                        .metrics
                        .shadow_differences
                        .fetch_add(1, Ordering::Relaxed);
                }
                ShadowDecision {
                    generation: shadow.generation(),
                    policy: selected.policy.id(),
                    decision: shadow_decision,
                    rewrite,
                    differs,
                    temporary_exception: temporary.map(|found| found.index),
                }
            });
            // Matching is finished: move the already-normalized buffer into
            // telemetry rather than copying it. Only the trailing root dot is
            // removed, preserving Hickory's escapes within DNS labels.
            let domain_len = domain.len();
            ascii.truncate(domain_len);
            event = Some(QueryEvent {
                client,
                domain: ascii,
                qtype: u16::from(request.queries[0].query_type()),
                generation: snapshot.generation(),
                policy: policy.id(),
                decision,
                decision_cached,
                response_code: u16::from(response.metadata.response_code),
                source,
                latency_us: 0,
                shadow,
                temporary_exception: temporary.map(|found| found.index),
            });
            response
        };
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
        let max = if tcp {
            u16::MAX
        } else {
            request.max_payload().clamp(512, 1232)
        };
        let mut output = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut output);
        encoder.set_max_size(max);
        response.emit(&mut encoder).ok()?;
        let latency = self.telemetry.metrics.observe(start);
        if let Some(mut event) = event {
            event.latency_us = latency;
            self.telemetry.emit(event);
        }
        Some(output)
    }
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

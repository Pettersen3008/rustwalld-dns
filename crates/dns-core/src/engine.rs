use crate::{
    PolicyController, PublicationError,
    decision_cache::DecisionKey,
    telemetry::{QuerySource, Telemetry},
};
use arc_swap::{ArcSwap, ArcSwapOption, Guard};
use hickory_proto::op::Message;
use rustwalld_dns_filter::Decision;
use rustwalld_dns_policy::{CompiledPolicy, PolicySnapshot, ScheduleEvaluation, TemporaryMatch};
use rustwalld_dns_resolver::{Forwarder, Resolver, cache::BoundedCache, response_cache::CacheKey};
use std::{net::IpAddr, sync::Arc, time::Instant};

mod admission;
mod decision;
mod forwarding;
mod outcome;
mod wire;

/// Transport a query arrived on; it selects the reply size limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
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
    schedule: Option<ScheduleEvaluation>,
    key: CacheKey,
    upstream: Arc<Forwarder>,
    lookup_request: Option<Message>,
    aliases: Option<Vec<hickory_proto::rr::Record>>,
}

/// How a query is answered once policy has been applied.
enum Step {
    Local(Message, QuerySource),
    Miss(
        CacheKey,
        Arc<Forwarder>,
        Option<Message>,
        Option<Vec<hickory_proto::rr::Record>>,
    ),
}

/// Everything known about a query once its reply message exists.
struct Outcome<'a> {
    start: Instant,
    client: IpAddr,
    transport: Transport,
    request: &'a Message,
    policy: &'a CompiledPolicy,
    client_name: Option<&'a str>,
    filter_tags: rustwalld_dns_filter::ClientTags,
    generation: u64,
    domain: String,
    qtype: u16,
    decision: Decision,
    decision_cached: bool,
    /// The query was admitted by a temporary exception.
    excepted: bool,
    schedule: Option<ScheduleEvaluation>,
    /// That exception, if it is still in force.
    exception: Option<TemporaryMatch<'a>>,
    response: Message,
    source: QuerySource,
}

/// Named bounds for caches and upstream work. Zero cache sizes disable caching.
#[derive(Clone, Copy, Debug)]
pub struct EngineConfig {
    /// Response-cache entries.
    pub cache_entries: usize,
    /// Decision-cache entries.
    pub decision_entries: usize,
    /// Distinct upstream lookups in flight at once.
    pub max_inflight: usize,
    /// Validated expired-cache fallback window; disabled by default.
    pub serve_stale: crate::ServeStale,
}
impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            cache_entries: 4096,
            decision_entries: 16384,
            max_inflight: 256,
            serve_stale: crate::ServeStale::default(),
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
                resolver: Resolver::with_stale(
                    config.cache_entries,
                    config.max_inflight,
                    config.serve_stale,
                ),
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
}

#[cfg(test)]
#[path = "engine_schedule_tests.rs"]
mod schedule_tests;

use crate::{
    Forwarder, ResolveError,
    response_cache::{CacheKey, Entry, ResponseCache, ServeStale},
};
use hickory_proto::op::{Edns, Message};
use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Copy)]
enum FlightError {
    Upstream,
    Shutdown,
}
type SharedResult = Option<Result<Arc<(Message, Instant)>, FlightError>>;
type Flights = Arc<Vec<Mutex<HashMap<CacheKey, watch::Receiver<SharedResult>>>>>;
const FLIGHT_SHARDS: usize = 32;
/// Monotonic resolver counters.
#[derive(Default)]
pub struct ResolverMetrics {
    /// Answers served from the response cache.
    cache_hits: AtomicU64,
    /// Misses that joined an identical in-flight lookup.
    coalesced: AtomicU64,
    /// Upstream lookups started.
    upstream_lookups: AtomicU64,
    /// Misses refused because `max_inflight` lookups were running.
    overloads: AtomicU64,
}
/// Plain counter values sampled by [`ResolverMetrics::snapshot`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolverMetricsSnapshot {
    /// Answers served from the response cache.
    pub cache_hits: u64,
    /// Misses that joined an identical in-flight lookup.
    pub coalesced: u64,
    /// Upstream lookups started.
    pub upstream_lookups: u64,
    /// Misses refused because `max_inflight` lookups were running.
    pub overloads: u64,
}
impl ResolverMetrics {
    /// Sample counters with relaxed loads. Values are independent observations,
    /// so concurrent updates can occur between fields; this is not a transaction.
    pub fn snapshot(&self) -> ResolverMetricsSnapshot {
        ResolverMetricsSnapshot {
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            coalesced: self.coalesced.load(Ordering::Relaxed),
            upstream_lookups: self.upstream_lookups.load(Ordering::Relaxed),
            overloads: self.overloads.load(Ordering::Relaxed),
        }
    }
}

/// Bounded response cache plus single-flight forwarding shared by all policies.
pub struct Resolver {
    /// Shared response cache (inspection and diagnostics).
    pub cache: ResponseCache,
    /// Aggregate counters.
    pub metrics: ResolverMetrics,
    flights: Flights,
    hash: RandomState,
    slots: Arc<Semaphore>,
    cancel: CancellationToken,
    serve_stale: ServeStale,
}
/// Where a resolution's answer came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResolutionSource {
    /// The response cache.
    Cache,
    /// An expired response used after all upstreams failed.
    Stale,
    /// A lookup this call started.
    Upstream,
    /// An identical lookup already in flight.
    Coalesced,
}
/// A resolved response with TTLs aged to now.
pub struct Resolution {
    /// Private copy of the response; callers restore their own ID and question.
    pub response: Message,
    /// Where the answer came from.
    pub source: ResolutionSource,
}
/// Outcome of the synchronous cache probe.
pub enum Lookup {
    /// A cached response with TTLs aged to now.
    Hit(Message),
    /// Not cached; pass the key to [`Resolver::forward`].
    Miss(CacheKey),
}
/// What a caller found while holding its flight shard.
enum Admission {
    Cached(Arc<Entry>),
    Waiting(watch::Receiver<SharedResult>),
    Admitted(watch::Sender<SharedResult>, FlightGuard),
}
impl Resolver {
    /// A resolver caching up to `cache_entries` responses and running at most
    /// `max_inflight` distinct upstream lookups at once.
    pub fn new(cache_entries: usize, max_inflight: usize) -> Arc<Self> {
        Self::with_stale(cache_entries, max_inflight, ServeStale::default())
    }
    /// Construct a resolver with a validated opt-in stale fallback. It is used
    /// only after upstream failure, never overload or shutdown.
    pub fn with_stale(
        cache_entries: usize,
        max_inflight: usize,
        serve_stale: ServeStale,
    ) -> Arc<Self> {
        Arc::new(Self {
            cache: ResponseCache::new(cache_entries),
            metrics: ResolverMetrics::default(),
            flights: Arc::new(
                (0..FLIGHT_SHARDS)
                    .map(|_| Mutex::new(HashMap::new()))
                    .collect(),
            ),
            hash: RandomState::new(),
            slots: Arc::new(Semaphore::new(max_inflight)),
            cancel: CancellationToken::new(),
            serve_stale,
        })
    }
    /// Cancel in-flight lookups and refuse new ones.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
    /// Distinct lookups currently in flight.
    pub fn inflight(&self) -> usize {
        self.flights
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum()
    }
    /// Probe the response cache without waiting. Fails only for a request
    /// without a question, which can never be forwarded.
    pub fn lookup(&self, request: &Message, upstream: &Forwarder) -> Result<Lookup, ResolveError> {
        let key = CacheKey::new(request, upstream.id()).ok_or(ResolveError::Encoding)?;
        Ok(match self.cache.get(&key, Instant::now()) {
            Some(response) => {
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                Lookup::Hit(response)
            }
            None => Lookup::Miss(key),
        })
    }
    /// Resolve an accepted client query: cache, then coalescing, then upstream.
    pub async fn resolve(
        self: &Arc<Self>,
        request: &Message,
        upstream: Arc<Forwarder>,
    ) -> Result<Resolution, ResolveError> {
        match self.lookup(request, &upstream)? {
            Lookup::Hit(response) => Ok(Resolution {
                response,
                source: ResolutionSource::Cache,
            }),
            Lookup::Miss(key) => self.forward(request, key, upstream).await,
        }
    }
    /// Resolve a cache miss from [`Resolver::lookup`]. Joins an identical flight
    /// or admits a new bounded one; upstream normalization is deferred until a
    /// flight is admitted, so waiters need no forwarding copy.
    pub async fn forward(
        self: &Arc<Self>,
        request: &Message,
        key: CacheKey,
        upstream: Arc<Forwarder>,
    ) -> Result<Resolution, ResolveError> {
        if self.cancel.is_cancelled() {
            return Err(ResolveError::Unavailable);
        }
        // Default-off keeps the existing miss path free of a new key clone.
        let stale_key = self.serve_stale.enabled().then(|| key.clone());
        let index = self.shard(&key);
        // The shard lock covers only map, cache-pointer and permit operations.
        // Message copies, request construction and spawning happen after it.
        let admission = {
            let mut shard = self.flights[index]
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // A flight caches its result before leaving the map, so rechecking
            // here closes the window in which a duplicate flight could start.
            if let Some(entry) = self.cache.entry(&key, Instant::now()) {
                Admission::Cached(entry)
            } else if let Some(receiver) = shard.get(&key) {
                Admission::Waiting(receiver.clone())
            } else {
                let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                    drop(shard);
                    self.metrics.overloads.fetch_add(1, Ordering::Relaxed);
                    return Err(ResolveError::Unavailable);
                };
                let (sender, receiver) = watch::channel(None);
                shard.insert(key.clone(), receiver);
                // Created under the lock so the entry is removed even if this
                // future is dropped before the flight task is spawned.
                let guard = FlightGuard {
                    flights: self.flights.clone(),
                    index,
                    key: key.clone(),
                    _permit: permit,
                };
                Admission::Admitted(sender, guard)
            }
        };
        let (mut receiver, source) = match admission {
            Admission::Cached(entry) => {
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Resolution {
                    response: entry.materialize(Instant::now()),
                    source: ResolutionSource::Cache,
                });
            }
            Admission::Waiting(receiver) => {
                self.metrics.coalesced.fetch_add(1, Ordering::Relaxed);
                (receiver, ResolutionSource::Coalesced)
            }
            Admission::Admitted(sender, guard) => {
                let receiver = sender.subscribe();
                self.spawn_flight(request, key, upstream, sender, guard);
                (receiver, ResolutionSource::Upstream)
            }
        };
        loop {
            let result = receiver.borrow().clone();
            if let Some(result) = result {
                return match result {
                    Ok(response) => Ok({
                        let elapsed = response.1.elapsed().as_secs();
                        let elapsed = u32::try_from(elapsed).unwrap_or(u32::MAX);
                        let mut message = response.0.clone();
                        for record in message
                            .answers
                            .iter_mut()
                            .chain(&mut message.authorities)
                            .chain(&mut message.additionals)
                        {
                            record.ttl = record.ttl.saturating_sub(elapsed);
                        }
                        Resolution {
                            response: message,
                            source,
                        }
                    }),
                    Err(FlightError::Upstream) if !self.cancel.is_cancelled() => stale_key
                        .as_ref()
                        .and_then(|key| self.cache.stale(key, Instant::now(), self.serve_stale))
                        .map(|response| Resolution {
                            response,
                            source: ResolutionSource::Stale,
                        })
                        .ok_or(ResolveError::Unavailable),
                    Err(_) => Err(ResolveError::Unavailable),
                };
            }
            if receiver.changed().await.is_err() {
                return Err(ResolveError::Unavailable);
            }
        }
    }
    fn shard(&self, key: &CacheKey) -> usize {
        // Reduce in u64 first: the modulus is tiny, so the cast cannot truncate.
        let shard = self.hash.hash_one(key) % self.flights.len() as u64;
        usize::try_from(shard).unwrap_or_default()
    }
    /// Start the owned upstream task. It survives the initiating waiter's
    /// cancellation; its guard removes the flight and releases admission even on
    /// task cancellation or panic.
    fn spawn_flight(
        self: &Arc<Self>,
        request: &Message,
        key: CacheKey,
        upstream: Arc<Forwarder>,
        sender: watch::Sender<SharedResult>,
        guard: FlightGuard,
    ) {
        let mut request = request.clone();
        if let Some(query) = request.queries.first_mut() {
            query.set_name(key.query.name().clone());
        }
        // Client casing, AD and UDP payload size do not partition flights.
        // Use one canonical upstream question/EDNS envelope, then let the
        // engine restore each client's question and transport constraints.
        request.metadata.authentic_data = false;
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(key.dnssec_ok);
        request.edns = Some(edns);
        let resolver = self.clone();
        tokio::spawn(async move {
            let _guard = guard;
            resolver
                .metrics
                .upstream_lookups
                .fetch_add(1, Ordering::Relaxed);
            let result = tokio::select! {
                () = resolver.cancel.cancelled() => Err(FlightError::Shutdown),
                result = upstream.resolve(&request) => result.map_err(|_| FlightError::Upstream),
            };
            let result = result.map(|response| {
                let received = Instant::now();
                resolver.cache.insert(key, response.clone(), received);
                Arc::new((response, received))
            });
            sender.send_replace(Some(result));
        });
    }
}
struct FlightGuard {
    flights: Flights,
    index: usize,
    key: CacheKey,
    _permit: OwnedSemaphorePermit,
}
impl Drop for FlightGuard {
    fn drop(&mut self) {
        self.flights[self.index]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hickory_proto::{
        op::{MessageType, OpCode, Query},
        rr::{Name, RData, Record, RecordType, rdata::A},
    };
    use std::time::Duration;
    #[tokio::test]
    async fn missing_question_never_admits_upstream_work() {
        let resolver = Resolver::new(32, 1);
        let forwarder = Arc::new(
            Forwarder::new(
                vec!["127.0.0.1:9".parse().unwrap()],
                Duration::from_millis(10),
            )
            .unwrap(),
        );
        assert!(matches!(
            resolver.resolve(&Message::query(), forwarder).await,
            Err(ResolveError::Encoding)
        ));
        assert_eq!(resolver.inflight(), 0);
        assert_eq!(resolver.metrics.snapshot().upstream_lookups, 0);
    }
    #[tokio::test]
    async fn delayed_coalesced_waiter_receives_aged_ttls() {
        let resolver = Resolver::new(0, 1);
        let mut request = Message::new(1, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("waiter.test.").unwrap(),
            RecordType::A,
        ));
        let forwarder = Arc::new(
            Forwarder::new(
                vec!["127.0.0.1:9".parse().unwrap()],
                Duration::from_millis(10),
            )
            .unwrap(),
        );
        let key = CacheKey::new(&request, forwarder.id()).unwrap();
        let mut response = request.clone().into_response();
        response.add_answer(Record::from_rdata(
            key.query.name().clone(),
            30,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        response.add_additional(Record::from_rdata(
            Name::from_ascii("other.test.").unwrap(),
            5,
            RData::A(A("192.0.2.2".parse().unwrap())),
        ));
        let index = resolver.shard(&key);
        let (sender, receiver) = watch::channel(None);
        resolver.flights[index]
            .lock()
            .unwrap()
            .insert(key.clone(), receiver);
        let waiter = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.resolve(&request, forwarder).await.unwrap() })
        };
        tokio::task::yield_now().await;
        sender.send_replace(Some(Ok(Arc::new((
            response,
            Instant::now() - Duration::from_secs(7),
        )))));
        let result = waiter.await.unwrap();
        assert_eq!(result.source, ResolutionSource::Coalesced);
        assert_eq!(result.response.answers[0].ttl, 23);
        assert_eq!(result.response.additionals[0].ttl, 0);
        assert_eq!(resolver.metrics.snapshot().upstream_lookups, 0);
    }
}

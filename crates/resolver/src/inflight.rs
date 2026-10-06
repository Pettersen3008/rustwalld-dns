use crate::{
    Forwarder, ResolveError,
    response_cache::{CacheKey, ResponseCache},
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
type SharedResult = Option<Result<Arc<(Message, Instant)>, ()>>;
type Flights = Arc<Vec<Mutex<HashMap<CacheKey, watch::Receiver<SharedResult>>>>>;
#[derive(Default)]
pub struct ResolverMetrics {
    pub cache_hits: AtomicU64,
    pub coalesced: AtomicU64,
    pub upstream_lookups: AtomicU64,
    pub overloads: AtomicU64,
}
pub struct Resolver {
    pub cache: ResponseCache,
    pub metrics: ResolverMetrics,
    flights: Flights,
    hash: RandomState,
    slots: Arc<Semaphore>,
    cancel: CancellationToken,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionSource {
    Cache,
    Upstream,
    Coalesced,
}
pub struct Resolution {
    pub response: Message,
    pub source: ResolutionSource,
}
impl Resolver {
    pub fn new(cache_entries: usize, max_inflight: usize) -> Arc<Self> {
        Arc::new(Self {
            cache: ResponseCache::new(cache_entries),
            metrics: ResolverMetrics::default(),
            flights: Arc::new((0..32).map(|_| Mutex::new(HashMap::new())).collect()),
            hash: RandomState::new(),
            slots: Arc::new(Semaphore::new(max_inflight)),
            cancel: CancellationToken::new(),
        })
    }
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
    pub fn inflight(&self) -> usize {
        self.flights
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum()
    }
    /// Resolve an accepted client query. Upstream normalization is deferred until
    /// a new bounded flight is admitted; cache hits and waiters need no forwarding copy.
    pub async fn resolve(
        self: &Arc<Self>,
        request: &Message,
        profile: usize,
        generation: u64,
        upstream: Arc<Forwarder>,
    ) -> Result<Resolution, ResolveError> {
        if self.cancel.is_cancelled() {
            return Err(ResolveError::Unavailable);
        }
        let key = CacheKey::new(request, profile, generation).ok_or(ResolveError::Encoding)?;
        if let Some(response) = self.cache.get(&key, Instant::now()) {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Resolution {
                response,
                source: ResolutionSource::Cache,
            });
        }
        let index = self.hash.hash_one(&key) as usize % self.flights.len();
        let (mut receiver, source) = {
            let mut shard = self.flights[index]
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(response) = self.cache.get(&key, Instant::now()) {
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Resolution {
                    response,
                    source: ResolutionSource::Cache,
                });
            }
            if let Some(receiver) = shard.get(&key) {
                self.metrics.coalesced.fetch_add(1, Ordering::Relaxed);
                (receiver.clone(), ResolutionSource::Coalesced)
            } else {
                let permit = match self.slots.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        self.metrics.overloads.fetch_add(1, Ordering::Relaxed);
                        return Err(ResolveError::Unavailable);
                    }
                };
                let (sender, receiver) = watch::channel(None);
                shard.insert(key.clone(), receiver.clone());
                let guard = FlightGuard {
                    flights: self.flights.clone(),
                    index,
                    key: key.clone(),
                    _permit: permit,
                };
                let resolver = self.clone();
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
                // Owned task survives the initiating waiter's cancellation; guard removes
                // the flight and releases admission even on task cancellation/panic.
                tokio::spawn(async move {
                    let _guard = guard;
                    resolver
                        .metrics
                        .upstream_lookups
                        .fetch_add(1, Ordering::Relaxed);
                    let result = tokio::select! {_ = resolver.cancel.cancelled()=>Err(ResolveError::Unavailable),result=upstream.resolve(&request)=>result};
                    let result = result
                        .map(|response| {
                            let received = Instant::now();
                            resolver.cache.insert(key, response.clone(), received);
                            Arc::new((response, received))
                        })
                        .map_err(|_| ());
                    sender.send_replace(Some(result));
                });
                (receiver, ResolutionSource::Upstream)
            }
        };
        loop {
            let result = receiver.borrow().clone();
            if let Some(result) = result {
                return result
                    .map(|response| {
                        let elapsed = response.1.elapsed().as_secs().min(u32::MAX as u64) as u32;
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
                    })
                    .map_err(|_| ResolveError::Unavailable);
            }
            if receiver.changed().await.is_err() {
                return Err(ResolveError::Unavailable);
            }
        }
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
            resolver.resolve(&Message::query(), 0, 1, forwarder).await,
            Err(ResolveError::Encoding)
        ));
        assert_eq!(resolver.inflight(), 0);
        assert_eq!(resolver.metrics.upstream_lookups.load(Ordering::Relaxed), 0);
    }
    #[tokio::test]
    async fn delayed_coalesced_waiter_receives_aged_ttls() {
        let resolver = Resolver::new(0, 1);
        let mut request = Message::new(1, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("waiter.test.").unwrap(),
            RecordType::A,
        ));
        let key = CacheKey::new(&request, 0, 1).unwrap();
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
        let index = resolver.hash.hash_one(&key) as usize % resolver.flights.len();
        let (sender, receiver) = watch::channel(None);
        resolver.flights[index]
            .lock()
            .unwrap()
            .insert(key.clone(), receiver);
        let forwarder = Arc::new(
            Forwarder::new(
                vec!["127.0.0.1:9".parse().unwrap()],
                Duration::from_millis(10),
            )
            .unwrap(),
        );
        let waiter = {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.resolve(&request, 0, 1, forwarder).await.unwrap() })
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
        assert_eq!(resolver.metrics.upstream_lookups.load(Ordering::Relaxed), 0);
    }
}

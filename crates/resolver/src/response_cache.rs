use crate::{UpstreamId, cache::BoundedCache};
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::RData,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Response cache and coalescing identity. Policy decisions are made before a
/// query reaches the resolver and blocked/rewritten answers never enter this
/// cache, so the key holds only what can change upstream content: the
/// normalized question, the upstream profile identity and the DO/CD bits.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CacheKey {
    /// The question with a lowercased name.
    pub query: Query,
    /// Content identity of the forwarding profile.
    pub upstream: UpstreamId,
    /// The client's EDNS DO bit.
    pub dnssec_ok: bool,
    /// The client's CD bit.
    pub checking_disabled: bool,
}
impl CacheKey {
    /// `None` when the request has no question.
    pub fn new(request: &Message, upstream: UpstreamId) -> Option<Self> {
        let mut query = request.queries.first()?.clone();
        query.set_name(query.name().to_lowercase());
        Some(Self {
            query,
            upstream,
            dnssec_ok: request.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
            checking_disabled: request.metadata.checking_disabled,
        })
    }
}
pub(crate) struct Entry {
    response: Message,
    inserted: Instant,
    expires: Instant,
}
impl Entry {
    /// A private copy with TTLs aged by whole seconds since insertion.
    pub(crate) fn materialize(&self, now: Instant) -> Message {
        let elapsed = now.saturating_duration_since(self.inserted).as_secs();
        let elapsed = u32::try_from(elapsed).unwrap_or(u32::MAX);
        let mut response = self.response.clone();
        for record in response
            .answers
            .iter_mut()
            .chain(&mut response.authorities)
            .chain(&mut response.additionals)
        {
            record.ttl = record.ttl.saturating_sub(elapsed);
        }
        response
    }
}
/// Bounded cache of upstream responses. Entries expire at their smallest TTL
/// (capped at one day); negative answers need an SOA and use its minimum.
pub struct ResponseCache {
    entries: BoundedCache<CacheKey, Arc<Entry>>,
}
impl ResponseCache {
    /// A cache of at most `capacity` responses; zero disables caching.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: BoundedCache::new(capacity),
        }
    }
    /// A live entry without copying its message; cheap enough under other locks.
    pub(crate) fn entry(&self, key: &CacheKey, now: Instant) -> Option<Arc<Entry>> {
        self.entries.get(key).filter(|entry| now < entry.expires)
    }
    /// A private copy with TTLs aged to `now`, if a live entry exists.
    pub fn get(&self, key: &CacheKey, now: Instant) -> Option<Message> {
        self.entry(key, now).map(|entry| entry.materialize(now))
    }
    /// Cache a cacheable response, returning whether it was stored. Truncated,
    /// signed, SERVFAIL-like, zero-TTL and SOA-less negative replies are not.
    pub fn insert(&self, key: CacheKey, mut response: Message, now: Instant) -> bool {
        if response.metadata.truncation
            || response.signature.is_some()
            || !matches!(
                response.metadata.response_code,
                ResponseCode::NoError | ResponseCode::NXDomain
            )
        {
            return false;
        }
        // NODATA: aliases without a terminal requested RR require a negative SOA.
        let negative = response.metadata.response_code == ResponseCode::NXDomain
            || !response
                .answers
                .iter()
                .any(|r| r.data.record_type() == key.query.query_type());
        let negative_ttl = if negative {
            let Some(ttl) = response
                .authorities
                .iter()
                .filter_map(|r| match &r.data {
                    RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
                    _ => None,
                })
                .min()
            else {
                return false;
            };
            for record in &mut response.authorities {
                if matches!(record.data, RData::SOA(_)) {
                    record.ttl = record.ttl.min(ttl);
                }
            }
            Some(ttl)
        } else {
            None
        };
        let Some(mut ttl) = response
            .all_sections()
            // RFC 2181 section 8: a TTL with the top bit set is treated as zero.
            .map(|r| {
                if r.ttl > i32::MAX.unsigned_abs() {
                    0
                } else {
                    r.ttl
                }
            })
            .min()
        else {
            return false;
        };
        if let Some(negative_ttl) = negative_ttl {
            ttl = ttl.min(negative_ttl);
        }
        // Conservative upper cap and full-message expiry keep RRsets coherent.
        ttl = ttl.min(86400);
        if ttl == 0 {
            return false;
        }
        response.edns = None;
        response.metadata.authentic_data = false;
        self.entries.insert(
            key,
            Arc::new(Entry {
                response,
                inserted: now,
                expires: now + Duration::from_secs(u64::from(ttl)),
            }),
        );
        true
    }
    /// Cached responses, including expired ones not yet evicted.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hickory_proto::{
        op::{MessageType, OpCode},
        rr::{
            Name, Record, RecordType,
            rdata::{A, SOA},
        },
    };
    fn upstream(port: u16) -> UpstreamId {
        crate::Forwarder::new(
            vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))],
            Duration::from_secs(1),
        )
        .unwrap()
        .id()
    }
    fn fixture() -> (CacheKey, Message) {
        let mut request = Message::new(1, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("cache.example.").unwrap(),
            RecordType::A,
        ));
        let key = CacheKey::new(&request, upstream(0)).unwrap();
        let mut response = request.into_response();
        response.add_answer(Record::from_rdata(
            key.query.name().clone(),
            30,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        (key, response)
    }
    #[test]
    fn ttl_decrement_expiry_and_partitioning() {
        let (key, response) = fixture();
        let cache = ResponseCache::new(100);
        let now = Instant::now();
        assert!(cache.insert(key.clone(), response, now));
        assert_eq!(
            cache
                .get(&key, now + Duration::from_secs(7))
                .unwrap()
                .answers[0]
                .ttl,
            23
        );
        assert!(cache.get(&key, now + Duration::from_secs(30)).is_none());
        let mut other = key.clone();
        other.upstream = upstream(1);
        assert!(cache.get(&other, now).is_none());
        other = key.clone();
        other.dnssec_ok = true;
        assert!(cache.get(&other, now).is_none());
        other = key;
        other.checking_disabled = true;
        assert!(cache.get(&other, now).is_none());
    }
    #[test]
    fn negative_requires_soa_and_uses_minimum() {
        let (key, mut response) = fixture();
        response.answers.clear();
        response.metadata.response_code = ResponseCode::NXDomain;
        let cache = ResponseCache::new(100);
        let now = Instant::now();
        assert!(!cache.insert(key.clone(), response.clone(), now));
        response.add_authority(Record::from_rdata(
            Name::from_ascii("example.").unwrap(),
            90,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.example.").unwrap(),
                Name::from_ascii("admin.example.").unwrap(),
                1,
                60,
                60,
                600,
                10,
            )),
        ));
        assert!(cache.insert(key.clone(), response, now));
        assert_eq!(
            cache
                .get(&key, now + Duration::from_secs(3))
                .unwrap()
                .authorities[0]
                .ttl,
            7
        );
        assert!(cache.get(&key, now + Duration::from_secs(10)).is_none());
    }
    #[test]
    fn zero_ttl_servfail_and_truncated_not_cached() {
        let (key, mut response) = fixture();
        let cache = ResponseCache::new(100);
        let now = Instant::now();
        response.answers[0].ttl = 0;
        assert!(!cache.insert(key.clone(), response.clone(), now));
        response.answers[0].ttl = 60;
        response.metadata.truncation = true;
        assert!(!cache.insert(key.clone(), response.clone(), now));
        response.metadata.truncation = false;
        response.metadata.response_code = ResponseCode::ServFail;
        assert!(!cache.insert(key, response, now));
    }
}

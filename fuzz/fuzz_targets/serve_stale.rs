#![no_main]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use libfuzzer_sys::fuzz_target;
use rustwalld_dns_resolver::{
    Forwarder,
    response_cache::{CacheKey, ResponseCache, ServeStale},
};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() < 8 || bytes.len() > 65_543 {
        return;
    }
    let age = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 172_801;
    let maximum = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) % 172_801;
    let policy = ServeStale::new(Duration::from_secs(u64::from(maximum)));
    assert_eq!(policy.is_ok(), maximum <= 86_400);
    let Ok(policy) = policy else {
        return;
    };
    let Ok(response) = Message::from_vec(&bytes[8..]) else {
        return;
    };
    let Ok(name) = Name::from_ascii("stale.test.") else {
        return;
    };
    let mut query = Message::query();
    query.add_query(Query::query(name, RecordType::A));
    let Ok(upstream) = Forwarder::new(
        vec![SocketAddr::from(([127, 0, 0, 1], 9))],
        Duration::from_secs(1),
    ) else {
        return;
    };
    let Some(key) = CacheKey::new(&query, upstream.id()) else {
        return;
    };
    let cache = ResponseCache::new(1);
    let now = Instant::now();
    let mut previous = query.into_response();
    previous.add_answer(Record::from_rdata(
        key.query.name().clone(),
        1,
        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
    ));
    cache.insert(key.clone(), previous, now);
    let invalid = response.metadata.truncation
        || response.signature.is_some()
        || !matches!(
            response.metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        );
    cache.insert(key.clone(), response, now);
    if invalid {
        assert!(cache.get(&key, now).is_some());
    }
    let aged = now + Duration::from_secs(u64::from(age));
    if let Some(stale) = cache.stale(&key, aged, policy) {
        assert!(maximum > 0);
        assert!(cache.get(&key, aged).is_none());
        assert!(stale.all_sections().all(|record| record.ttl == 30));
        assert!(!stale.metadata.authentic_data);
    }
    assert!(
        cache
            .stale(
                &key,
                now + Duration::from_secs(86_400 + u64::from(maximum)),
                policy
            )
            .is_none()
    );
    let mut other = key.clone();
    other.dnssec_ok = !other.dnssec_ok;
    assert!(cache.stale(&other, aged, policy).is_none());
    assert!(cache.len() <= 1);
});

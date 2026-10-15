#![no_main]
use libfuzzer_sys::fuzz_target;
use rustwalld_dns_policy::{LocalRecord, PolicyConfigSet, PolicySnapshot};
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 4096 {
        return;
    }
    let Ok(records) = serde_json::from_slice::<Vec<LocalRecord>>(bytes) else {
        return;
    };
    if records.len() > 32 {
        return;
    }
    let encoded = serde_json::to_vec(&records).unwrap();
    assert_eq!(
        serde_json::from_slice::<Vec<LocalRecord>>(&encoded).unwrap(),
        records
    );
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.policies[0].dns_records = records;
    let _ = PolicySnapshot::compile(config, 1);
});

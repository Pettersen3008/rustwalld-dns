#![no_main]
use libfuzzer_sys::fuzz_target;
use rustwalld_dns_resolver::cache::{BoundedCache, Equivalent};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Key {
    domain: String,
    policy: u8,
    generation: u8,
}
#[derive(Hash)]
struct Lookup<'a> {
    domain: &'a str,
    policy: u8,
    generation: u8,
}
impl Equivalent<Key> for Lookup<'_> {
    fn equivalent(&self, key: &Key) -> bool {
        self.domain == key.domain && self.policy == key.policy && self.generation == key.generation
    }
}

fuzz_target!(|bytes: &[u8]| {
    if bytes.is_empty() || bytes.len() > 4096 {
        return;
    }
    let capacity = usize::from(bytes[0] % 129);
    let cache = BoundedCache::new(capacity);
    for operation in bytes[1..].chunks(20) {
        if operation.len() < 3 {
            continue;
        }
        let key = Key {
            domain: String::from_utf8_lossy(&operation[3..]).into_owned(),
            policy: operation[1],
            generation: operation[2],
        };
        if operation[0] % 3 == 0 {
            cache.insert(key.clone(), key.clone());
        }
        let lookup = Lookup {
            domain: &key.domain,
            policy: key.policy,
            generation: key.generation,
        };
        let borrowed = cache.get(&lookup);
        assert_eq!(borrowed, cache.get(&key));
        if let Some(value) = borrowed {
            assert_eq!(value, key);
        }
        assert!(cache.len() <= capacity);
    }
});

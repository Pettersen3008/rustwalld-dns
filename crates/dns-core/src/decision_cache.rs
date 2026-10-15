use rustwalld_dns_resolver::cache::Equivalent;
#[derive(Clone, Hash, Eq, PartialEq)]
pub(crate) struct DecisionKey {
    pub(crate) domain: String,
    /// Validated policy ID shifted left one, with the service-off variant in bit 0.
    pub(crate) policy: usize,
    pub(crate) generation: u64,
    pub(crate) qtype: u16,
    pub(crate) client_class: u64,
}
// Keep field order and Hash semantics identical to DecisionKey. Only cache
// misses need an owned domain; policy/generation are always part of lookup.
#[derive(Hash)]
pub(crate) struct DecisionLookup<'a> {
    pub(crate) domain: &'a str,
    pub(crate) policy: usize,
    pub(crate) generation: u64,
    pub(crate) qtype: u16,
    pub(crate) client_class: u64,
}
impl Equivalent<DecisionKey> for DecisionLookup<'_> {
    fn equivalent(&self, key: &DecisionKey) -> bool {
        self.domain == key.domain
            && self.policy == key.policy
            && self.generation == key.generation
            && self.qtype == key.qtype
            && self.client_class == key.client_class
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rustwalld_dns_resolver::cache::BoundedCache;
    use std::{collections::hash_map::RandomState, hash::BuildHasher};

    #[test]
    fn borrowed_decisions_hash_like_owned_keys_and_keep_all_partitions() {
        let hash = RandomState::new();
        eprintln!("decision_key_bytes={}", std::mem::size_of::<DecisionKey>());
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        for domain in [
            "",
            "example",
            "sub.example",
            "a\\.b.example",
            "a\\\\b.example",
            "\\000\\377.example",
            "xn--bcher-kva.example",
            &longest,
        ] {
            for policy in [0, 1, usize::MAX] {
                for generation in [0, 1, u64::MAX] {
                    let owned = DecisionKey {
                        domain: domain.into(),
                        policy,
                        generation,
                        qtype: 1,
                        client_class: 0,
                    };
                    let borrowed = DecisionLookup {
                        domain,
                        policy,
                        generation,
                        qtype: 1,
                        client_class: 0,
                    };
                    assert!(borrowed.equivalent(&owned));
                    assert!(
                        !DecisionLookup {
                            client_class: 1,
                            ..borrowed
                        }
                        .equivalent(&owned)
                    );
                    assert!(
                        !DecisionLookup {
                            qtype: 28,
                            ..borrowed
                        }
                        .equivalent(&owned)
                    );
                    assert_eq!(hash.hash_one(&owned), hash.hash_one(&borrowed));
                    assert!(
                        !DecisionLookup {
                            policy: policy.wrapping_add(1),
                            ..borrowed
                        }
                        .equivalent(&owned)
                    );
                    assert!(
                        !DecisionLookup {
                            generation: generation.wrapping_add(1),
                            ..borrowed
                        }
                        .equivalent(&owned)
                    );
                    assert!(
                        !DecisionLookup {
                            domain: "different.test",
                            ..borrowed
                        }
                        .equivalent(&owned)
                    );
                    let cache = BoundedCache::new(128);
                    cache.insert(owned, 42);
                    assert_eq!(cache.get(&borrowed), Some(42));
                    assert_eq!(
                        cache.get(&DecisionLookup {
                            policy: policy.wrapping_add(1),
                            ..borrowed
                        }),
                        None
                    );
                    assert_eq!(
                        cache.get(&DecisionLookup {
                            generation: generation.wrapping_add(1),
                            ..borrowed
                        }),
                        None
                    );
                    assert_eq!(
                        cache.get(&DecisionLookup {
                            domain: "different.test",
                            ..borrowed
                        }),
                        None
                    );
                }
            }
        }
    }
}

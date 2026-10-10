//! Bounded sharded caches with CLOCK (second-chance) eviction. Locks cover only
//! table operations, never awaits or I/O.
//!
//! Each key is hashed once with a randomized hasher (names are client
//! controlled); middle bits select the shard and the full hash indexes that
//! shard's table. A hit marks its slot referenced; eviction sweeps a hand over
//! the fixed slot array, clearing references until it finds an unreferenced
//! victim. Unlike FIFO, entries in active use survive a stream of one-off
//! insertions, while the bound stays exact and no per-entry list is kept.
pub use hashbrown::Equivalent;
use hashbrown::HashTable;
use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hash},
    sync::Mutex,
};

const MAX_SHARDS: usize = 32;

/// Fixed-capacity concurrent cache; see the module documentation.
pub struct BoundedCache<K, V> {
    shards: Vec<Mutex<Shard<K, V>>>,
    hash: RandomState,
}
struct Slot<K, V> {
    key: K,
    value: V,
    hash: u64,
    referenced: bool,
}
struct Shard<K, V> {
    /// Indexes into `slots`, located by each slot's stored hash.
    index: HashTable<usize>,
    slots: Vec<Slot<K, V>>,
    hand: usize,
    capacity: usize,
}
impl<K: Eq + Hash, V: Clone> BoundedCache<K, V> {
    /// A cache holding at most `capacity` entries; zero disables caching.
    pub fn new(capacity: usize) -> Self {
        let count = capacity.clamp(1, MAX_SHARDS);
        let shards = (0..count)
            .map(|i| {
                Mutex::new(Shard {
                    index: HashTable::new(),
                    slots: Vec::new(),
                    hand: 0,
                    capacity: capacity / count + usize::from(i < capacity % count),
                })
            })
            .collect();
        Self {
            shards,
            hash: RandomState::new(),
        }
    }
    /// Borrowed keys must hash identically to equivalent owned keys, including
    /// every namespace/generation field, for both shard and table selection.
    fn locate<Q: Hash + ?Sized>(&self, key: &Q) -> (u64, &Mutex<Shard<K, V>>) {
        let hash = self.hash.hash_one(key);
        // The table uses the low bits for buckets and the top seven as tags;
        // choose the shard from bits in between so they stay independent.
        let index = (hash >> 32) % self.shards.len() as u64;
        let shard = &self.shards[usize::try_from(index).unwrap_or_default()];
        (hash, shard)
    }
    /// A clone of the value for `key`, marking it recently used.
    pub fn get<Q: Hash + Equivalent<K> + ?Sized>(&self, key: &Q) -> Option<V> {
        let (hash, shard) = self.locate(key);
        let mut shard = shard.lock().unwrap_or_else(|e| e.into_inner());
        let Shard { index, slots, .. } = &mut *shard;
        let slot = *index.find(hash, |&slot| key.equivalent(&slots[slot].key))?;
        let slot = &mut slots[slot];
        slot.referenced = true;
        Some(slot.value.clone())
    }
    /// Insert or replace `key`, evicting a not-recently-used entry when full.
    pub fn insert(&self, key: K, value: V) {
        let (hash, shard) = self.locate(&key);
        let mut shard = shard.lock().unwrap_or_else(|e| e.into_inner());
        let Shard {
            index,
            slots,
            hand,
            capacity,
        } = &mut *shard;
        if *capacity == 0 {
            return;
        }
        if let Some(&slot) = index.find(hash, |&slot| slots[slot].key == key) {
            let slot = &mut slots[slot];
            slot.value = value;
            slot.referenced = true;
            return;
        }
        let entry = Slot {
            key,
            value,
            hash,
            referenced: false,
        };
        let position = if slots.len() < *capacity {
            slots.push(entry);
            slots.len() - 1
        } else {
            // Every referenced slot the hand passes loses its reference, so the
            // sweep ends within one revolution.
            while slots[*hand].referenced {
                slots[*hand].referenced = false;
                *hand = (*hand + 1) % slots.len();
            }
            let victim = *hand;
            *hand = (victim + 1) % slots.len();
            if let Ok(found) = index.find_entry(slots[victim].hash, |&slot| slot == victim) {
                found.remove();
            }
            // The old key and value drop here, still under the shard lock;
            // cached values are cheap to drop (Arc or Copy).
            slots[victim] = entry;
            victim
        };
        index.insert_unique(hash, position, |&slot| slots[slot].hash);
    }
    /// Remove a key, returning its value and immediately releasing its cache slot.
    pub fn remove<Q: Hash + Equivalent<K> + ?Sized>(&self, key: &Q) -> Option<V> {
        let (hash, shard) = self.locate(key);
        let mut shard = shard.lock().unwrap_or_else(|e| e.into_inner());
        let Shard {
            index, slots, hand, ..
        } = &mut *shard;
        let found = index
            .find_entry(hash, |&slot| key.equivalent(&slots[slot].key))
            .ok()?;
        let position = found.remove().0;
        let last = slots.len() - 1;
        let removed = slots.swap_remove(position);
        if position < slots.len() {
            if let Some(slot) = index.find_mut(slots[position].hash, |&slot| slot == last) {
                *slot = position;
            }
            if *hand == last {
                *hand = position;
            }
        } else if *hand >= slots.len() {
            *hand = 0;
        }
        Some(removed.value)
    }
    /// Entries currently cached (locks each shard briefly).
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).slots.len())
            .sum()
    }
    /// Whether no entries are cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hasher;
    #[test]
    fn hard_bound_and_disabled() {
        let cache = BoundedCache::new(17);
        for key in 0..10000 {
            cache.insert(key, key);
            assert!(cache.len() <= 17);
        }
        let cache = BoundedCache::new(0);
        cache.insert(1, 1);
        assert!(cache.is_empty());
    }
    #[test]
    fn borrowed_strings_replace_values_and_evict_when_full() {
        let cache = BoundedCache::new(1);
        cache.insert("a.test".to_owned(), 1);
        assert_eq!(cache.get("a.test"), Some(1));
        cache.insert("a.test".to_owned(), 2);
        assert_eq!(cache.get("a.test"), Some(2));
        cache.insert("b.test".to_owned(), 3);
        assert_eq!(cache.get("a.test"), None);
        assert_eq!(cache.get("b.test"), Some(3));
        let disabled = BoundedCache::new(0);
        disabled.insert("a.test".to_owned(), 1);
        assert_eq!(disabled.get("a.test"), None);
    }
    #[derive(Clone, Eq, PartialEq)]
    pub(super) struct CollisionKey(pub(super) String);
    pub(super) struct CollisionLookup<'a>(pub(super) &'a str);
    impl Hash for CollisionKey {
        fn hash<H: Hasher>(&self, state: &mut H) {
            state.write_u8(0);
        }
    }
    impl Hash for CollisionLookup<'_> {
        fn hash<H: Hasher>(&self, state: &mut H) {
            state.write_u8(0);
        }
    }
    impl Equivalent<CollisionKey> for CollisionLookup<'_> {
        fn equivalent(&self, key: &CollisionKey) -> bool {
            self.0 == key.0
        }
    }
    #[test]
    fn colliding_borrowed_keys_keep_identity_and_second_chance_order() {
        // All keys select the same shard, with exactly two available entries.
        let cache = BoundedCache::new(64);
        cache.insert(CollisionKey("a".into()), 1);
        cache.insert(CollisionKey("b".into()), 2);
        cache.insert(CollisionKey("a".into()), 3);
        assert_eq!(cache.get(&CollisionLookup("a")), Some(3));
        assert_eq!(cache.get(&CollisionLookup("b")), Some(2));
        assert_eq!(cache.get(&CollisionLookup("c")), None);
        // Both entries were referenced: the hand clears both, then evicts the
        // first slot it revisits.
        cache.insert(CollisionKey("c".into()), 4);
        assert_eq!(cache.get(&CollisionLookup("a")), None);
        assert_eq!(cache.get(&CollisionLookup("b")), Some(2));
        assert_eq!(cache.get(&CollisionLookup("c")), Some(4));
        assert_eq!(cache.len(), 2);
        // "b" and "c" were both just read; the hand (now at "b") clears both
        // references and evicts "b".
        cache.insert(CollisionKey("d".into()), 5);
        assert_eq!(cache.get(&CollisionLookup("b")), None);
        // Reading "c" again gives it a second chance over the unread "d".
        assert_eq!(cache.get(&CollisionLookup("c")), Some(4));
        cache.insert(CollisionKey("e".into()), 6);
        assert_eq!(cache.get(&CollisionLookup("d")), None);
        assert_eq!(cache.get(&CollisionLookup("c")), Some(4));
        assert_eq!(cache.get(&CollisionLookup("e")), Some(6));
        assert_eq!(cache.len(), 2);
    }
    #[test]
    fn referenced_entries_survive_one_off_insertions() {
        // Each shard holds four entries; a hot key read between insertions is
        // always referenced when the hand reaches it. FIFO would evict it.
        let cache = BoundedCache::new(128);
        cache.insert(u64::MAX, 0);
        for key in 0..10_000 {
            assert_eq!(cache.get(&u64::MAX), Some(0), "hot entry evicted at {key}");
            cache.insert(key, key);
            assert!(cache.len() <= 128);
        }
        // An entry never read again is eventually replaced.
        assert_eq!(cache.get(&0), None);
    }
    #[test]
    fn concurrent_borrowed_reads_and_evictions_remain_bounded() {
        let cache = BoundedCache::new(97);
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let cache = &cache;
                scope.spawn(move || {
                    for index in 0..1000 {
                        let domain = format!("{index}.client-{worker}.test");
                        cache.insert(domain.clone(), domain.clone());
                        if let Some(value) = cache.get(domain.as_str()) {
                            assert_eq!(value, domain);
                        }
                        assert!(cache.len() <= 97);
                    }
                });
            }
        });
        assert!(cache.len() <= 97);
    }
    #[test]
    fn removing_colliding_slots_preserves_other_entries_and_allows_regrowth() {
        let cache = BoundedCache::new(96);
        for (key, value) in [("a", 1), ("b", 2), ("c", 3)] {
            cache.insert(CollisionKey(key.into()), value);
        }
        assert_eq!(cache.remove(&CollisionLookup("b")), Some(2));
        assert_eq!(cache.get(&CollisionLookup("a")), Some(1));
        assert_eq!(cache.get(&CollisionLookup("c")), Some(3));
        assert_eq!(cache.remove(&CollisionLookup("b")), None);
        assert_eq!(cache.remove(&CollisionLookup("c")), Some(3));
        assert_eq!(cache.remove(&CollisionLookup("a")), Some(1));
        assert!(cache.is_empty());
        for key in ["d", "e", "f", "g"] {
            cache.insert(CollisionKey(key.into()), 4);
        }
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get(&CollisionLookup("g")), Some(4));
    }
}

#[cfg(test)]
mod properties {
    #![allow(clippy::unwrap_used)]
    use super::{
        tests::{CollisionKey, CollisionLookup},
        *,
    };
    use proptest::{prelude::*, test_runner::FileFailurePersistence};
    use std::collections::{BTreeMap, VecDeque};

    struct ClockModel {
        capacity: usize,
        ring: VecDeque<(u8, u16, bool)>,
    }
    impl ClockModel {
        fn get(&mut self, key: u8) -> Option<u16> {
            let entry = self.ring.iter_mut().find(|entry| entry.0 == key)?;
            entry.2 = true;
            Some(entry.1)
        }
        fn insert(&mut self, key: u8, value: u16) {
            if self.capacity == 0 {
                return;
            }
            if let Some(entry) = self.ring.iter_mut().find(|entry| entry.0 == key) {
                *entry = (key, value, true);
                return;
            }
            if self.ring.len() == self.capacity {
                loop {
                    let (key, value, referenced) = self.ring.pop_front().unwrap();
                    if !referenced {
                        break;
                    }
                    self.ring.push_back((key, value, false));
                }
            }
            self.ring.push_back((key, value, false));
        }
    }
    fn config() -> ProptestConfig {
        ProptestConfig {
            cases: std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(128),
            failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../target/review/property-tests/cache-regressions.txt"
            )))),
            ..Default::default()
        }
    }
    proptest! {
        #![proptest_config(config())]
        #[test]
        fn clock_matches_a_rotating_queue_reference(
            capacity in 0_usize..13,
            operations in prop::collection::vec((0_u8..3,0_u8..32,any::<u16>()),0..300),
        ) {
            // Every key collides into one uniform shard, so the independent
            // model needs neither a hash table nor slot indices/clock hand.
            let cache = BoundedCache::new(capacity * MAX_SHARDS);
            let mut model = ClockModel { capacity, ring: VecDeque::new() };
            for (operation,key,value) in operations {
                let domain = key.to_string();
                if operation < 2 {
                    cache.insert(CollisionKey(domain),value);
                    model.insert(key,value);
                } else {
                    prop_assert_eq!(cache.get(&CollisionLookup(&domain)),model.get(key));
                }
                prop_assert_eq!(cache.len(),model.ring.len());
            }
        }
        #[test]
        fn remove_replace_and_regrow_match_a_plain_map(
            enabled in any::<bool>(),
            operations in prop::collection::vec((0_u8..3,0_u8..16,any::<u16>()),0..300),
        ) {
            // Enough room for the complete key domain; removal and borrowed
            // identity are checked exactly, independent of eviction choices.
            let cache = BoundedCache::new(if enabled { 16 * MAX_SHARDS } else { 0 });
            let mut model = BTreeMap::new();
            for (operation,key,value) in operations {
                let domain = key.to_string();
                match operation {
                    0 => {
                        cache.insert(CollisionKey(domain),value);
                        if enabled { model.insert(key,value); }
                    }
                    1 => prop_assert_eq!(cache.remove(&CollisionLookup(&domain)),model.remove(&key)),
                    _ => prop_assert_eq!(cache.get(&CollisionLookup(&domain)),model.get(&key).copied()),
                }
                prop_assert_eq!(cache.len(),model.len());
            }
        }
    }
}

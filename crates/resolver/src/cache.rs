//! Bounded FIFO shards. Locks cover only map operations, never awaits or I/O.
pub use hashbrown::Equivalent;
use hashbrown::HashMap;
use std::{
    collections::{VecDeque, hash_map::RandomState},
    hash::{BuildHasher, Hash},
    sync::Mutex,
};

pub struct BoundedCache<K, V> {
    shards: Vec<Mutex<Shard<K, V>>>,
    hash: RandomState,
}
struct Shard<K, V> {
    entries: HashMap<K, V, RandomState>,
    order: VecDeque<K>,
    capacity: usize,
}
impl<K: Eq + Hash + Clone, V: Clone> BoundedCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        let count = capacity.clamp(1, 32);
        let shards = (0..count)
            .map(|i| {
                Mutex::new(Shard {
                    // Preserve randomized hashing for client-controlled names.
                    entries: HashMap::with_hasher(RandomState::new()),
                    order: VecDeque::new(),
                    capacity: capacity / count + usize::from(i < capacity % count),
                })
            })
            .collect();
        Self {
            shards,
            hash: RandomState::new(),
        }
    }
    fn shard<Q: Hash + ?Sized>(&self, key: &Q) -> usize {
        self.hash.hash_one(key) as usize % self.shards.len()
    }
    /// Borrowed keys must hash identically to equivalent owned keys, including
    /// every namespace/generation field, for both shard and map selection.
    pub fn get<Q: Hash + Equivalent<K> + ?Sized>(&self, key: &Q) -> Option<V> {
        self.shards[self.shard(key)]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .get(key)
            .cloned()
    }
    pub fn insert(&self, key: K, value: V) {
        let mut shard = self.shards[self.shard(&key)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if shard.capacity == 0 {
            return;
        }
        if let Some(entry) = shard.entries.get_mut(&key) {
            *entry = value;
            return;
        }
        while shard.entries.len() >= shard.capacity {
            if let Some(old) = shard.order.pop_front() {
                shard.entries.remove(&old);
            } else {
                return;
            }
        }
        shard.order.push_back(key.clone());
        shard.entries.insert(key, value);
    }
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).entries.len())
            .sum()
    }
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
    fn borrowed_strings_replace_values_and_expire_fifo_entries() {
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
    struct CollisionKey(String);
    struct CollisionLookup<'a>(&'a str);
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
    fn colliding_borrowed_keys_keep_identity_and_fifo_order() {
        // All keys select the same shard, with exactly two available entries.
        let cache = BoundedCache::new(64);
        cache.insert(CollisionKey("a".into()), 1);
        cache.insert(CollisionKey("b".into()), 2);
        cache.insert(CollisionKey("a".into()), 3);
        assert_eq!(cache.get(&CollisionLookup("a")), Some(3));
        assert_eq!(cache.get(&CollisionLookup("b")), Some(2));
        assert_eq!(cache.get(&CollisionLookup("c")), None);
        cache.insert(CollisionKey("c".into()), 4);
        assert_eq!(cache.get(&CollisionLookup("a")), None);
        assert_eq!(cache.get(&CollisionLookup("b")), Some(2));
        assert_eq!(cache.get(&CollisionLookup("c")), Some(4));
        assert_eq!(cache.len(), 2);
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
}

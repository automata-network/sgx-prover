use std::prelude::v1::*;

use base::format::debug;
use eth_types::SH256;
use std::collections::BTreeMap;
use std::fmt::Debug;

use rlp::{Decodable, Encodable};

use super::{Trie, TrieUpdate};

pub trait CacheKey {
    type Key: Clone + Debug + Ord;
    fn bytes(k: &Self::Key) -> Vec<u8>;
}


#[derive(Debug, Clone)]
pub struct TrieCache<T, K, V>
where
    T: Trie,
    K: AsRef<[u8]> + Clone + Debug + Ord,
    V: Decodable + Encodable + Default + Debug + Clone,
{
    raw: T,
    pub cache: BTreeMap<K, V>,
    pub dirty: BTreeMap<K, ()>,
}

impl<T, K, V> From<T> for TrieCache<T, K, V>
where
    T: Trie,
    K: AsRef<[u8]> + Clone + Debug + Ord,
    V: Decodable + Encodable + Default + Debug + Clone,
{
    fn from(raw: T) -> Self {
        Self {
            raw,
            cache: BTreeMap::new(),
            dirty: BTreeMap::new(),
        }
    }
}

impl<T, K, V> TrieCache<T, K, V>
where
    T: Trie,
    K: AsRef<[u8]> + Clone + Debug + Ord,
    V: Decodable + Encodable + Default + Debug + Clone,
{
    pub fn new(raw: T) -> Self {
        let cache = BTreeMap::new();
        let dirty = BTreeMap::new();
        Self { raw, cache, dirty }
    }

    pub fn raw(&self) -> &T {
        &self.raw
    }

    pub fn root_hash(&self) -> SH256 {
        *self.raw.root_hash()
    }

    pub fn mark_dirty(&mut self, k: &K) {
        self.dirty.insert(k.clone(), ());
    }

    pub fn is_dirty(&self, k: &K) -> bool {
        self.dirty.contains_key(k)
    }

    pub fn revert(&mut self, root: SH256) -> bool {
        if self.raw.root_hash() == &root && self.dirty.len() == 0 {
            return false;
        }

        self.cache.clear();
        self.dirty.clear();
        self.raw = self.raw.new_root(root);
        return true;
    }

    pub fn get_cloned<S, F>(&mut self, db: &mut T::DB, k: &K) -> Result<V, String> {
        self.with_key(db, k, |ctx| ctx.val.clone())
    }

    pub fn with_key<F, O>(&mut self, db: &mut T::DB, k: &K, f: F) -> Result<O, String>
    where
        F: FnOnce(TrieCacheCtx<'_, T, V, T::DB>) -> O,
    {
        if let Some(v) = self.cache.get_mut(k) {
            let mut dirty = false;
            let ctx = TrieCacheCtx::new(&mut self.raw, v, &mut dirty, db);
            let out = f(ctx);
            if dirty {
                self.dirty.insert(k.clone(), ());
            }
            return Ok(out);
        }
        let data = self.raw.get(db, k.as_ref())?;
        let data: V = if data.len() == 0 {
            V::default()
        } else {
            rlp::decode(&data).map_err(debug)?
        };
        let v = self.cache.entry(k.clone()).or_insert(data);
        let mut dirty = false;
        let ctx = TrieCacheCtx::new(&mut self.raw, v, &mut dirty, db);
        let out = f(ctx);
        if dirty {
            self.dirty.insert(k.clone(), ());
        }
        return Ok(out);
    }

    pub fn try_with_key<F, O>(&mut self, db: &mut T::DB, k: &K, f: F) -> Result<Option<O>, String>
    where
        F: FnOnce(TrieCacheCtx<'_, T, V, T::DB>) -> O,
    {
        if let Some(v) = self.cache.get_mut(k) {
            let mut dirty = false;
            let ctx = TrieCacheCtx::new(&mut self.raw, v, &mut dirty, db);
            let out = f(ctx);
            if dirty {
                self.dirty.insert(k.clone(), ());
            }
            return Ok(Some(out));
        }
        let origin_key = k.as_ref();
        match self.raw.try_get(db, &origin_key) {
            Some(data) => {
                let data: V = if data.len() == 0 {
                    V::default()
                } else {
                    rlp::decode(&data).map_err(debug)?
                };
                let v = self.cache.entry(k.clone()).or_insert(data);
                let mut dirty = false;
                let ctx = TrieCacheCtx::new(&mut self.raw, v, &mut dirty, db);
                let out = f(ctx);
                if dirty {
                    self.dirty.insert(k.clone(), ());
                }
                return Ok(Some(out));
            }
            None => return Ok(None),
        }
    }

    pub fn flush(&mut self, db: &mut T::DB) -> Result<(), Vec<SH256>> {
        let mut updates = Vec::with_capacity(self.dirty.len());
        let keys: Vec<_> = self.dirty.keys().map(Clone::clone).collect();
        for k in &keys {
            let data = match self.cache.get(k) {
                None => Vec::new(),
                Some(v) => rlp::encode(v).into(),
            };
            updates.push((k.as_ref(), data));
        }
        let results = self.raw.update(db, updates);
        assert_eq!(results.len(), keys.len());
        let mut missing = Vec::with_capacity(self.dirty.len());
        for (idx, result) in results.into_iter().enumerate() {
            match result {
                TrieUpdate::Missing(node) => missing.push(node),
                TrieUpdate::Success => {}
            }
            self.dirty.remove(&keys[idx]);
        }
        if missing.len() > 0 {
            Err(missing)
        } else {
            Ok(())
        }
    }
}

pub struct TrieCacheCtx<'a, T, V, D> {
    pub raw: &'a mut T,
    pub val: &'a mut V,
    pub dirty: &'a mut bool,
    pub db:  &'a mut D,
}

impl<'a, T, V, D> TrieCacheCtx<'a, T, V, D> {
    pub fn new(raw: &'a mut T, val: &'a mut V, dirty: &'a mut bool, db: &'a mut D) -> Self {
        Self { val, raw, dirty, db }
    }
}

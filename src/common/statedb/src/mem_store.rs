use core::marker::PhantomData;
use std::prelude::v1::*;

use base::lru::LruMap;
use eth_types::{HexBytes, SH256};

use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::NodeDB;

#[derive(Debug, Clone)]
pub struct MemStore<T, H: Hasher<T>> {
    codes: Arc<Mutex<LruMap<SH256, Arc<HexBytes>>>>,
    kv: Arc<Mutex<LruMap<SH256, Arc<T>>>>,
    staging: BTreeMap<SH256, Arc<T>>,
    _phantom: PhantomData<H>,
}

impl<T, H: Hasher<T>> MemStore<T, H> {
    pub fn new(limit: usize) -> Self {
        Self {
            codes: Arc::new(Mutex::new(LruMap::new(limit))),
            kv: Arc::new(Mutex::new(LruMap::new(limit))),
            staging: BTreeMap::new(),
            _phantom: PhantomData,
        }
    }

    pub fn clear(&self) {
        let mut kv = self.kv.lock().unwrap();
        kv.clear();
    }
}

pub trait Hasher<T> {
    fn hash(n: &T) -> SH256;
}

impl<T, H: Hasher<T>> NodeDB for MemStore<T, H> {
    type Node = T;

    fn fork(&self) -> Self {
        Self {
            codes: self.codes.clone(),
            kv: self.kv.clone(),
            staging: BTreeMap::new(),
            _phantom: PhantomData,
        }
    }

    fn get(&self, index: &SH256) -> Option<Arc<Self::Node>> {
        let result = if let Some(node) = self.staging.get(index) {
            Some(node.clone())
        } else {
            let mut kv = self.kv.lock().unwrap();
            let data = kv.get(index).cloned();
            data
        };
        // glog::info!("store get: {:?} -> {:?}", index, result);
        result
    }

    fn add_node(&mut self, node: &Arc<Self::Node>) {
        match self.staging.entry(H::hash(&node)) {
            Entry::Occupied(_) => {}
            Entry::Vacant(entry) => {
                entry.insert(node.clone());
            }
        }
    }

    fn set_code(&mut self, hash: SH256, code: Cow<HexBytes>) {
        let mut codes = self.codes.lock().unwrap();
        codes.insert(hash, Arc::new(code.into_owned()));
    }

    fn get_code(&mut self, hash: &SH256) -> Option<Arc<HexBytes>> {
        let mut codes = self.codes.lock().unwrap();
        codes.get(hash).map(|v| v.clone())
    }

    fn remove_staging_node(&mut self, node: &Arc<Self::Node>) {
        self.staging.remove(&H::hash(&node));
    }

    fn staging(&mut self, node: Self::Node) -> Arc<Self::Node> {
        let node = Arc::new(node);
        self.add_node(&node);
        node
    }

    fn commit(&mut self) -> usize {
        let start = Instant::now();
        let mut kv = self.kv.lock().unwrap();
        let old_len = kv.len();
        let commit_len = self.staging.len();
        let outs = kv.append(&mut self.staging);
        for item in outs {
            let cnt = Arc::strong_count(&item);
            if cnt > 1 {
                glog::info!("evited: {}", cnt);
            }
        }
        glog::debug!(
            exclude:"dry_run",
            target: "store",
            "commit items: {}, old: {}, using time: {:?}",
            commit_len,
            old_len,
            start.elapsed()
        );
        commit_len
    }
}

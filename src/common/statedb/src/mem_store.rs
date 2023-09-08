use std::prelude::v1::*;

use crate::{TrieNode, TrieStorageNode};
use base::lru::LruMap;
use eth_types::{HexBytes, SH256};

use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct TrieMemStore {
    kv: Arc<Mutex<LruMap<SH256, Arc<TrieStorageNode>>>>,
    staging: BTreeMap<SH256, Arc<TrieStorageNode>>,
}

impl TrieMemStore {
    pub fn new(limit: usize) -> Self {
        Self {
            kv: Arc::new(Mutex::new(LruMap::new(limit))),
            staging: BTreeMap::new(),
        }
    }

    pub fn clear(&self) {
        let mut kv = self.kv.lock().unwrap();
        kv.clear();
    }
}

impl TrieStore for TrieMemStore {
    type StorageNode = TrieStorageNode;
    type Node = TrieNode;

    fn fork(&self) -> Self {
        Self {
            kv: self.kv.clone(),
            staging: BTreeMap::new(),
        }
    }

    fn get(&self, index: &SH256) -> Option<Arc<TrieStorageNode>> {
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

    fn add_node(&mut self, node: &Arc<TrieStorageNode>) {
        match self.staging.entry(node.hash) {
            Entry::Occupied(_) => {}
            Entry::Vacant(entry) => {
                entry.insert(node.clone());
            }
        }
    }

    fn add_nodes(&mut self, nodes: Vec<Self::Node>) {
        for item in nodes {
            match item.embedded() {
                Some(node) => self.add_node(node),
                None => {}
            }
        }
    }

    fn set_code(&mut self, hash: SH256, code: Cow<HexBytes>) -> Arc<TrieStorageNode> {
        match self.get(&hash) {
            Some(n) => n.clone(),
            None => {
                let mut node = TrieStorageNode::value(code.into_owned());
                node.hash = hash;
                let node = Arc::new(node);
                self.add_node(&node);
                node
            }
        }
    }

    fn get_code(&mut self, hash: &SH256) -> Option<HexBytes> {
        match self.get(hash) {
            Some(n) => Some(n.get_value().unwrap().into()),
            None => None,
        }
    }

    fn remove_staging_node(&mut self, node: &Arc<TrieStorageNode>) {
        self.staging.remove(&node.hash);
    }

    fn staging(&mut self, node: TrieNode) -> TrieNode {
        match node.embedded() {
            Some(node) => self.add_node(node),
            None => {}
        }
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
        glog::info!(exclude:"dry_run",
            "commit items: {}, old: {}, using time: {:?}",
            commit_len,
            old_len,
            start.elapsed()
        );
        commit_len
    }
}

pub trait TrieStore {
    type StorageNode;
    type Node;
    fn fork(&self) -> Self;
    fn get(&self, index: &SH256) -> Option<Arc<Self::StorageNode>>;
    fn add_node(&mut self, node: &Arc<Self::StorageNode>);
    fn add_nodes(&mut self, nodes: Vec<Self::Node>);
    fn get_code(&mut self, hash: &SH256) -> Option<HexBytes>;
    fn set_code(&mut self, hash: SH256, code: Cow<HexBytes>) -> Arc<Self::StorageNode>;
    fn remove_staging_node(&mut self, node: &Arc<Self::StorageNode>);
    fn staging(&mut self, node: Self::Node) -> Self::Node;
    fn commit(&mut self) -> usize;
}

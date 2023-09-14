use std::prelude::v1::*;

use eth_types::SU256;

use crate::{Error, Hash, Node};
use std::collections::BTreeMap;
use std::sync::Arc;

pub trait Database {
    fn get_node(&self, key: &Hash) -> Result<Option<Arc<Node>>, Error>;
    fn update_node(&mut self, node: Node) -> Result<Arc<Node>, Error>;
    fn update_preimage(&mut self, preimage: &[u8], hash_field: &SU256);
}

pub struct MemDB {
    map: BTreeMap<Hash, Arc<Node>>,
}

impl MemDB {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}

impl Database for MemDB {
    fn update_preimage(&mut self, _preimage: &[u8], _hash_field: &SU256) {}

    fn get_node(&self, key: &Hash) -> Result<Option<Arc<Node>>, Error> {
        Ok(self.map.get(key).map(|n| n.clone()))
    }

    fn update_node(&mut self, node: Node) -> Result<Arc<Node>, Error> {
        let node = Arc::new(node);
        self.map.insert(*node.hash(), node.clone());
        Ok(node.clone())
    }
}

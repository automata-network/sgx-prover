use std::prelude::v1::*;

use crate::{Error, Hash, HashScheme, Node};
use poseidon_rs::Fr;
use std::collections::BTreeMap;
use std::sync::Arc;

pub trait Database {
    type Node;
    fn get_node(&self, key: &Hash) -> Result<Option<Arc<Self::Node>>, Error>;
    fn update_node(&mut self, node: Self::Node) -> Result<Arc<Self::Node>, Error>;
    fn update_preimage(&mut self, preimage: &[u8], hash_field: &Fr);
}

pub struct MemDB<H: HashScheme> {
    map: BTreeMap<Hash, Arc<Node<H>>>,
}

impl<H: HashScheme> MemDB<H> {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}

impl<H: HashScheme> Database for MemDB<H> {
    type Node = Node<H>;
    fn update_preimage(&mut self, _preimage: &[u8], _hash_field: &Fr) {}

    fn get_node(&self, key: &Hash) -> Result<Option<Arc<Self::Node>>, Error> {
        Ok(self.map.get(key).map(|n| n.clone()))
    }

    fn update_node(&mut self, node: Self::Node) -> Result<Arc<Self::Node>, Error> {
        let node = Arc::new(node);
        self.map.insert(*node.hash(), node.clone());
        Ok(node.clone())
    }
}

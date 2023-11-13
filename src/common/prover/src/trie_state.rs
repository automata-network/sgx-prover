use std::prelude::v1::*;

use base::format::debug;
use crypto::keccak_hash;
use eth_types::{HexBytes, SH256, SU256};
use statedb::{MemStore, NodeDB, Trie, TrieState, TrieUpdate};
use std::borrow::Cow;
use std::sync::Arc;
use zktrie::{decode_smt_proofs, Byte32, Hash, PoseidonHash, TrieData};

type Node = zktrie::Node<PoseidonHash>;

#[derive(Clone, Debug)]
pub struct NodeHasher;
impl statedb::Hasher<Node> for NodeHasher {
    fn hash(n: &Node) -> SH256 {
        hash_to_h256(n.hash())
    }
}

fn hash_to_h256(hash: &Hash) -> SH256 {
    SU256::from_big_endian(&hash.bytes()).into()
}

pub type ZkTrieState = TrieState<ZkTrie, Database>;

pub fn new_zktrie_state(root: SH256, db: Database) -> ZkTrieState {
    let root = Hash::from_bytes(root.as_bytes());
    let trie = ZkTrie::new(root);
    let state = TrieState::new(trie, db);
    state
}

pub struct Database {
    db: statedb::MemStore<Node, NodeHasher>,
}

impl Database {
    pub fn new(cap: usize) -> Self {
        Self {
            db: MemStore::new(cap),
        }
    }

    pub fn resume_code(&mut self, code: &[u8]) {
        let hash = keccak_hash(code).into();
        self.db.set_code(hash, Cow::Owned(code.into()));
    }

    pub fn resume_node(&mut self, node: &[u8]) {
        match decode_smt_proofs::<PoseidonHash>(node) {
            Ok(Some(n)) => {
                let n = Arc::new(n);
                self.add_node(&n);
            }
            Ok(None) => {} // magic node
            Err(err) => {
                glog::error!("decode node string fail: {:?}", err);
            }
        };
    }

    pub fn resume_proofs(&mut self, proofs: &[HexBytes]) -> Option<Arc<Node>> {
        for proof in proofs {
            match decode_smt_proofs::<PoseidonHash>(&proof) {
                Ok(Some(n)) => {
                    let n = Arc::new(n);
                    self.add_node(&n);
                    if n.is_empty() {
                        return Some(n);
                    }
                }
                Ok(None) => {} // magic node
                Err(err) => {
                    glog::error!("decode proof string fail: {:?}", err);
                }
            };
        }
        None
    }
}

impl zktrie::Database for Database {
    type Node = Node;
    fn update_preimage(&mut self, _preimage: &[u8], _hash_field: &zktrie::Fr) {}
    fn get_node(&self, key: &zktrie::Hash) -> Result<Option<Arc<Node>>, zktrie::Error> {
        Ok(self.db.get(&hash_to_h256(key)))
    }

    fn update_node(&mut self, node: Node) -> Result<Arc<Node>, zktrie::Error> {
        let node = Arc::new(node);
        self.db.add_node(&node);
        Ok(node)
    }
}

impl statedb::NodeDB for Database {
    type Node = Node;

    fn add_node(&mut self, node: &Arc<Self::Node>) {
        self.db.add_node(node)
    }

    fn commit(&mut self) -> usize {
        self.db.commit()
    }

    fn fork(&self) -> Self {
        Database { db: self.db.fork() }
    }

    fn get(&self, index: &SH256) -> Option<Arc<Self::Node>> {
        self.db.get(index)
    }

    fn get_code(&mut self, hash: &SH256) -> Option<Arc<HexBytes>> {
        self.db.get_code(hash)
    }

    fn remove_staging_node(&mut self, node: &Arc<Self::Node>) {
        self.db.remove_staging_node(node)
    }

    fn set_code(&mut self, hash: SH256, code: Cow<HexBytes>) {
        self.db.set_code(hash, code);
    }

    fn staging(&mut self, node: Self::Node) -> Arc<Self::Node> {
        self.db.staging(node)
    }
}

pub struct ZkTrie {
    raw: zktrie::ZkTrie<PoseidonHash>,
}

impl ZkTrie {
    pub fn new(root: Hash) -> Self {
        const NODE_KEY_VALID_BYTES: usize = 31;
        let max_level = NODE_KEY_VALID_BYTES * 8;
        Self {
            raw: zktrie::ZkTrie::new(max_level, root),
        }
    }
}

impl Trie for ZkTrie {
    type DB = Database;
    fn get(&self, db: &mut Self::DB, key: &[u8]) -> Result<Vec<u8>, String> {
        let data = self.raw.get_data(db, key).map_err(debug)?;
        Ok(match data {
            TrieData::Node(n) => n.data().into(),
            TrieData::NotFound => Vec::new(),
        })
    }

    fn new_root(&self, new_root: SH256) -> Self {
        Self::new(Hash::from_bytes(new_root.as_bytes()))
    }

    fn root_hash(&self) -> SH256 {
        self.raw.hash().bytes().into()
    }

    fn try_get(&self, db: &mut Self::DB, key: &[u8]) -> Option<Vec<u8>> {
        match self.raw.get_data(db, key) {
            Ok(item) => Some(item.get().to_owned()),
            Err(err) => {
                glog::error!("get key[{}] fail: {:?}", HexBytes::from(key), err);
                None
            }
        }
    }

    fn update(&mut self, db: &mut Self::DB, updates: Vec<(&[u8], Vec<u8>)>) -> Vec<TrieUpdate> {
        let mut result = Vec::with_capacity(updates.len());
        for (key, v) in updates {
            assert!(matches!(key.len(), 32 | 20));
            if v.len() == 0 {
                let delete_result = match self.raw.delete(db, key) {
                    Ok(_) => TrieUpdate::Success,
                    Err(zktrie::Error::NodeNotFound((i, node))) => {
                        glog::info!("node not found: {},{:?}", i, node);
                        TrieUpdate::Missing(hash_to_h256(&node))
                    }
                    Err(zktrie::Error::KeyNotFound) => TrieUpdate::Success,
                    Err(err) => panic!("should not have error: {:?}", err),
                };
                result.push(delete_result);
                continue;
            }
            let v_flag = if v.len() == 160 { 8 } else { 1 };
            let v2 = Byte32::from_vec_bytes(&v);
            let update_result = match self.raw.update(db, key, v_flag, v2) {
                Ok(_) => TrieUpdate::Success,
                Err(zktrie::Error::NodeNotFound((_, node))) => {
                    TrieUpdate::Missing(node.bytes().into())
                }
                Err(err) => panic!("should not have error: {:?}", err),
            };
            result.push(update_result);
        }
        result
    }
}

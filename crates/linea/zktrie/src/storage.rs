use alloy::primitives::{Address, Bytes, B256};
use lazy_static::lazy_static;
use linea_mimc::keccak_hash;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

use crate::{
    mimc_safe, trie_hash, utils, Database, Error, LeafOpening, Node, NodeValue, Trace, EMPTY_DB,
    EMPTY_TRIE_NODE, EMPTY_TRIE_NODE_HASH, ZK_TRIE_DEPTH,
};

#[derive(Debug)]
pub struct PrefixDB {
    prefix: Address,
    raw: Arc<Mutex<MemStore>>,
}

impl PrefixDB {
    pub fn new(prefix: Address, raw: Arc<Mutex<MemStore>>) -> Self {
        Self { prefix, raw }
    }

    pub fn unwrap(self) -> Option<MemStore> {
        let raw = Arc::try_unwrap(self.raw).ok()?;
        let n = raw.into_inner().unwrap();
        Some(n)
    }

    pub fn new_prefix(&self, prefix: Address) -> Self {
        PrefixDB {
            prefix,
            raw: self.raw.clone(),
        }
    }
}

impl Database for PrefixDB {
    type Node = Node;
    fn get_code(&self, hash: &B256) -> Option<Arc<Bytes>> {
        let raw = self.raw.lock().unwrap();
        raw.get_code(hash)
    }

    fn set_code(&mut self, hash: B256, code: Arc<Bytes>) {
        let mut raw = self.raw.lock().unwrap();
        raw.set_code(hash, code)
    }

    fn get_nearest_keys(&self, root: &B256, k: &B256) -> Result<KeyRange, Error> {
        let raw = self.raw.lock().unwrap();
        raw.get_nearest_keys(self.prefix, root, k)
    }

    fn get_node(&self, key: &B256) -> Result<Option<Arc<Self::Node>>, Error> {
        let raw = self.raw.lock().unwrap();
        raw.get_node(key)
    }

    fn remove_index(&mut self, k: &B256) {
        let mut raw = self.raw.lock().unwrap();
        raw.remove_index(k)
    }

    fn update_index(&mut self, k: B256, v: FlattenedLeaf) {
        let mut raw = self.raw.lock().unwrap();
        raw.update_index(k, v)
    }

    fn update_node(&mut self, key: B256, node: Self::Node) -> Result<Arc<Self::Node>, Error> {
        let mut raw = self.raw.lock().unwrap();
        raw.update_node(key, node)
    }
}

#[derive(Debug)]
pub struct MemStore {
    use_static_data: bool,
    nodes: BTreeMap<B256, Arc<Node>>,
    index: LevelMap,
    staging: BTreeMap<B256, FlattenedLeaf>,
    codes: BTreeMap<B256, Arc<Bytes>>,
}

#[derive(Debug)]
pub struct LevelMap {
    vals: BTreeMap<B256, BTreeMap<(Address, B256), KeyRange>>,
}

impl LevelMap {
    pub fn from_traces(traces: &[Trace]) -> Result<Self, Error> {
        let mut idx = 0;
        let mut base = LevelMap::new();
        while idx < traces.len() {
            let trace = &traces[idx];
            let prefix = utils::parse_prefix(trace.location());
            let top_hash = trace.old_top_hash();
            let root_map = base.vals.entry(top_hash).or_insert_with(|| BTreeMap::new());
            let hkey = if trace.location().len() == 0 {
                // account key
                trie_hash(trace.key())?
            } else {
                // storage slot
                mimc_safe(&trace.key())?
            };
            root_map.insert((prefix, hkey), trace.key_range());

            idx += 1;
        }
        Ok(base)
    }

    pub fn new() -> Self {
        Self {
            vals: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FlattenedLeaf {
    pub leaf_index: u64,
    pub leaf_value: Bytes,
}

lazy_static! {
    pub static ref FLATTENED_LEAF_HEAD: FlattenedLeaf = FlattenedLeaf {
        leaf_index: 0,
        leaf_value: LeafOpening::head().hval.0.to_vec().into(),
    };
    pub static ref FLATTENED_LEAF_TAIL: FlattenedLeaf = FlattenedLeaf {
        leaf_index: 1,
        leaf_value: LeafOpening::tail().hval.0.to_vec().into(),
    };
}

impl FlattenedLeaf {
    pub fn head() -> &'static Self {
        &FLATTENED_LEAF_HEAD
    }

    pub fn tail() -> &'static Self {
        &FLATTENED_LEAF_TAIL
    }

    pub fn new(leaf_index: u64, leaf_value: Bytes) -> Self {
        Self {
            leaf_index,
            leaf_value,
        }
    }

    pub fn leaf_path(&self) -> [u8; ZK_TRIE_DEPTH + 2] {
        utils::get_leaf_path(self.leaf_index)
    }
}

impl MemStore {
    pub fn new() -> Self {
        Self {
            use_static_data: true,
            codes: BTreeMap::new(),
            nodes: BTreeMap::new(),
            index: LevelMap::new(),
            staging: BTreeMap::new(),
        }
    }

    pub(crate) fn new_on_init() -> Self {
        let mut ms = Self::new();
        ms.use_static_data = false;
        ms
    }

    pub fn from_traces(traces: &[Trace]) -> Result<Self, Error> {
        Ok(Self {
            use_static_data: true,
            codes: BTreeMap::new(),
            nodes: trace_nodes(traces),
            index: LevelMap::from_traces(traces)?,
            staging: BTreeMap::new(),
        })
    }

    pub fn add_codes(&mut self, codes: Vec<Bytes>) {
        for code in codes {
            let hash = keccak_hash(&code);
            self.codes.insert(hash.into(), Arc::new(code));
        }
    }

    fn build_node_branch_uncheck(
        &self,
        trie_path: &[u8],
        mut siblings: &[Bytes],
        fallback: bool,
        // siblings:
        //   root
        //   subProof
        //   leaf(leafOpening)
    ) -> Result<Vec<Node>, Error> {
        let mut out = Vec::new();
        let leaf_value = &siblings[siblings.len() - 1];
        siblings = &siblings[..siblings.len() - 1];
        let mut leaf = Node::new(NodeValue::parse_leaf(
            vec![trie_path[trie_path.len() - 1]].into(),
            leaf_value.clone(),
        ));
        let mut leaf_hash = *leaf.hash();
        out.push(leaf);

        let sibling_leaf_idx = siblings.len() - 1;
        for (idx, sibling_bytes) in siblings.into_iter().enumerate().rev() {
            if idx == 0 {
                let root = Node::new(
                    NodeValue::parse_root(&sibling_bytes).map_err(Error::ParseRootFromSibling())?,
                );
                out.push(root);
                break;
            }
            let sibling = if idx == sibling_leaf_idx {
                let leaf = if !fallback {
                    Node::new(NodeValue::parse_leaf(
                        vec![trie_path[trie_path.len() - 1]].into(),
                        sibling_bytes.clone(),
                    ))
                } else {
                    Node::new(NodeValue::EmptyLeaf)
                };
                leaf
            } else {
                Node::new(
                    NodeValue::parse_branch(&sibling_bytes)
                        .map_err(Error::ParseBranchNode(&idx))?,
                )
            };
            let sibling_hash = *sibling.hash();
            leaf = Node::raw_branch_auto(trie_path[idx], leaf_hash, sibling_hash);
            leaf_hash = *leaf.hash();
            out.push(sibling);
            out.push(leaf);
        }
        Ok(out)
    }

    fn build_node_branch(&self, leaf_index: u64, siblings: &[Bytes]) -> Result<Vec<Node>, Error> {
        let mut fallback = false;
        log::trace!("{:?}", siblings);
        let trie_path = utils::get_leaf_path(leaf_index);
        assert_eq!(siblings.len(), trie_path.len());

        loop {
            let out = self.build_node_branch_uncheck(&trie_path, siblings, fallback)?;
            // TODO: sanity check for node hashes

            let leaf_hash = *out[out.len() - 2].hash();
            let root = out.last().unwrap().raw().branch().unwrap();

            if leaf_hash != root.right {
                // glog::info!("{:?}", siblings);
                // glog::info!("leaf: {:?}", LeafOpening::parse(leaf_value));
                // glog::info!("leaf-sibling: {:?}", LeafOpening::parse(&siblings[siblings.len()-1]));
                if !fallback {
                    fallback = true;
                    continue;
                }

                for (idx, node) in out.iter().enumerate() {
                    log::trace!("[{}] {:?}", idx, node);
                }
                let next_free_node = utils::parse_node_index(root.left.as_slice());
                return Err(Error::InvalidProof {
                    got_sub_root: leaf_hash,
                    want_sub_root: root.right,
                    got_top_root: *Node::root_node(next_free_node, leaf_hash).hash(),
                });
            }

            return Ok(out);
        }
    }

    pub fn add_non_inclusion_proof(
        &mut self,
        prefix: Address,
        left_leaf_index: u64,
        right_leaf_index: u64,
        key: &Bytes,
        hkey: B256,
        left_siblings: &[Bytes],
        right_siblings: &[Bytes],
    ) -> Result<B256, Error> {
        let right_nodes = self
            .build_node_branch(right_leaf_index, right_siblings)
            .map_err(Error::BuildNonInclusionProofRight(&prefix, &key))?;
        let left_nodes = self
            .build_node_branch(left_leaf_index, left_siblings)
            .map_err(Error::BuildNonInclusionProofLeft(&prefix, &key))?;
        let root_hash = left_nodes.last().map(|n| *n.hash()).unwrap();
        for node in left_nodes {
            self.nodes.insert(*node.hash(), Arc::new(node));
        }
        for node in right_nodes {
            self.nodes.insert(*node.hash(), Arc::new(node));
        }
        log::trace!(
            "add index root={:?} prefix={:?} hkey={:?}",
            root_hash,
            prefix,
            hkey
        );
        self.index
            .vals
            .entry(root_hash)
            .or_insert_with(|| BTreeMap::new())
            .entry((prefix, hkey))
            .or_insert_with(|| KeyRange {
                left_index: left_leaf_index,
                center: None,
                right_index: right_leaf_index,
            });
        Ok(root_hash)
    }

    pub fn add_inclusion_proof(
        &mut self,
        prefix: Address,
        leaf_index: u64,
        key: &Bytes,
        hkey: B256,
        value: Option<&[u8]>,
        siblings: &[Bytes],
    ) -> Result<B256, Error> {
        let out = self
            .build_node_branch(leaf_index, siblings)
            .map_err(Error::BuildInclusionProof(&prefix, &key))?;
        let root_hash = out.last().map(|n| *n.hash()).unwrap();
        for node in out {
            self.nodes.insert(*node.hash(), Arc::new(node));
        }
        log::trace!("add proof: hkey={:?}, root={:?}", hkey, root_hash);
        self.index
            .vals
            .entry(root_hash)
            .or_insert_with(|| BTreeMap::new())
            .entry((prefix, hkey))
            .or_insert_with(|| KeyRange {
                left_index: 0,
                center: Some(FlattenedLeaf {
                    leaf_index,
                    leaf_value: Bytes::copy_from_slice(value.unwrap()),
                }),
                right_index: 0,
            });
        Ok(root_hash)
    }

    fn get_code(&self, hash: &B256) -> Option<Arc<Bytes>> {
        self.codes.get(hash).cloned()
    }

    fn set_code(&mut self, hash: B256, code: Arc<Bytes>) {
        self.codes.insert(hash, code);
    }

    fn get_node(&self, key: &B256) -> Result<Option<Arc<Node>>, Error> {
        if let Some(empty_db) = self.empty_db() {
            if let Some(node) = empty_db.get_node(key).map_err(Error::DBRedirectStatic())? {
                return Ok(Some(node));
            }
        }

        match EMPTY_TRIE_NODE.get(key) {
            Some(n) => return Ok(Some(n.clone())),
            None => {}
        };

        Ok(self.nodes.get(key).map(|n| n.clone()))
    }

    fn update_node(&mut self, key: B256, node: Node) -> Result<Arc<Node>, Error> {
        let node = Arc::new(node);
        self.nodes.insert(key, node.clone());
        Ok(node)
    }

    fn update_index(&mut self, k: B256, v: FlattenedLeaf) {
        self.staging.insert(k, v);
    }

    fn empty_db(&self) -> Option<&'static Self> {
        if !self.use_static_data {
            return None;
        }
        use std::ops::Deref;
        if self as *const _ == EMPTY_DB.deref() as *const _ {
            return None;
        }
        Some(EMPTY_DB.deref())
    }

    fn get_nearest_keys(&self, prefix: Address, root: &B256, k: &B256) -> Result<KeyRange, Error> {
        if let Some(_) = self.empty_db() {
            if *root == *EMPTY_TRIE_NODE_HASH {
                return EMPTY_DB
                    .get_nearest_keys(prefix, root, k)
                    .map_err(Error::GetNearestKeyFromEmpty());
            }
        }
        match self.index.vals.get(root) {
            Some(map) => match map.get(&(prefix, *k)) {
                Some(r) => Ok(r.clone()),
                None => {
                    // dbg!(&map);
                    return Err(Error::IndexNotFoundAtRoot {
                        root: *root,
                        prefix,
                        key: *k,
                    });
                }
            },
            None if root == &*EMPTY_TRIE_NODE_HASH => Ok(KeyRange {
                left_index: 0,
                right_index: 1,
                center: None,
            }),
            None => Err(Error::UnknownRoot { root: *root }),
        }
    }

    fn remove_index(&mut self, k: &B256) {
        self.staging.remove(k);
    }
}

fn trace_nodes(traces: &[Trace]) -> BTreeMap<B256, Arc<Node>> {
    let mut n = BTreeMap::new();
    for trace in traces {
        let (next_free_node, sub_root) = trace.old_state();
        let root = Node::root_node(next_free_node, sub_root);
        log::trace!("add root: {:?} for {:?}", root, trace);
        n.insert(*root.hash(), Arc::new(root));
        // n.insert(*next_free_node.hash(), Arc::new(next_free_node));
        for node in trace.nodes() {
            n.insert(*node.hash(), Arc::new(node));
        }
    }
    n
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyRange {
    pub left_index: u64,
    pub center: Option<FlattenedLeaf>,
    pub right_index: u64,
}

impl KeyRange {
    pub fn left_path(&self) -> [u8; ZK_TRIE_DEPTH + 2] {
        utils::get_leaf_path(self.left_index)
    }
    pub fn right_path(&self) -> [u8; ZK_TRIE_DEPTH + 2] {
        utils::get_leaf_path(self.right_index)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // #[test]
    // fn test_range() {
    //     let mut map = BTreeMap::new();

    //     for i in (0u8..20).step_by(2) {
    //         map.insert(i, ());
    //     }
    //     assert_eq!(
    //         Range::search(&map, &9),
    //         Some(Range {
    //             left: (8, ()),
    //             center: None,
    //             right: (10, ())
    //         })
    //     );

    //     assert_eq!(
    //         Range::search(&map, &10),
    //         Some(Range {
    //             left: (8, ()),
    //             center: Some((10, ())),
    //             right: (12, ())
    //         })
    //     );

    //     map.clear();
    //     assert_eq!(Range::search(&map, &10), None);

    //     map.insert(5, ());
    //     assert_eq!(
    //         Range::search(&map, &10),
    //         Some(Range {
    //             left: (5, ()),
    //             center: None,
    //             right: (5, ())
    //         })
    //     );
    //     assert_eq!(
    //         Range::search(&map, &2),
    //         Some(Range {
    //             left: (5, ()),
    //             center: None,
    //             right: (5, ())
    //         })
    //     );
    // }
}

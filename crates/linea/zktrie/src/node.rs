use core::fmt::Formatter;

use alloy::primitives::{Bytes, B256, U256};
// use alloy::rlp;
use alloy_rlp::{Decodable, Encodable};
use linea_mimc::keccak_hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{parse_node_index, Database, Error, ZK_TRIE_DEPTH};

lazy_static::lazy_static! {
    pub static ref LEAF_OPENING_HEAD: LeafOpening = LeafOpening {
        hkey: B256::default(),
        hval: B256::default(),
        prev_leaf: 0,
        next_leaf: 1,
    };
    pub static ref LEAF_OPENING_TAIL: LeafOpening = LeafOpening {
        hkey: "0x12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000000".parse().unwrap(),
        hval: B256::default(),
        prev_leaf: 0,
        next_leaf: 1,
    };
    pub static ref EMPTY_TRIE_NODE: BTreeMap<B256, Arc<Node>> = {
        let (_, n) = init_world_state();
        n
    };
}

#[repr(u8)]
#[derive(Debug)]
pub enum LeafType {
    Value = 0x16,
    NextFreeNode = 0x17,
    Empty = 0x18,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    raw: NodeValue,
    hash: B256,
}

impl std::fmt::Display for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Node{{raw: {}, hash: {:?}}}", self.raw, self.hash)
    }
}

impl std::fmt::Display for NodeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Branch(node) => write!(
                f,
                "Branch{{left: {:?}, right: {:?}}}",
                node.left, node.right
            ),
            Self::Leaf(node) => {
                write!(f, "Leaf{{path: {:?}, value: {:?}}}", node.path, node.value,)
            }
            Self::EmptyLeaf => write!(f, "EmptyLeaf"),
            Self::NextFree(node) => {
                write!(f, "NextFree{{value: {}}}", parse_node_index(&node.value),)
            }
        }
    }
}

impl Node {
    pub fn root_node(next_free_node: u64, sub_root: B256) -> Node {
        let next_free_node = U256::from(next_free_node);
        // let left = Arc::new(Node::next_free_node(next_free_node));
        Node::branch(next_free_node.into(), sub_root)
    }

    pub fn raw_branch_auto(path: u8, leaf: B256, sibling: B256) -> Node {
        if path == 0 {
            Self::raw_branch(leaf, sibling)
        } else {
            Self::raw_branch(sibling, leaf)
        }
    }

    pub fn raw_branch(left: B256, right: B256) -> Node {
        Self::new(NodeValue::Branch(BranchNode {
            left: left.into(),
            right,
        }))
    }

    pub fn branch(left: B256, right: B256) -> Node {
        Self::new(NodeValue::Branch(BranchNode { right, left }))
    }

    pub fn leaf(path: Vec<u8>, value: Vec<u8>) -> Node {
        if path == &[LeafType::NextFreeNode as u8] {
            Self::new(NodeValue::NextFree(LeafNode {
                path: path.into(),
                value: value.into(),
            }))
        } else {
            Self::new(NodeValue::Leaf(LeafNode {
                path: path.into(),
                value: value.into(),
            }))
        }
    }

    pub fn next_free_node(index: u64) -> Node {
        let mut val = vec![0_u8; 32];
        val[24..].copy_from_slice(&index.to_be_bytes());
        Node::new(NodeValue::new_next_free(val.into()))
    }

    pub fn new(value: NodeValue) -> Node {
        Node {
            hash: value.hash(),
            raw: value,
        }
    }

    pub fn empty_leaf() -> Arc<Node> {
        lazy_static::lazy_static! {
            static ref EMPTY_LEAF: Arc<Node> = Arc::new(Node::new(NodeValue::EmptyLeaf));
        }
        EMPTY_LEAF.clone()
    }

    pub fn is_next_free(&self) -> bool {
        matches!(&self.raw, NodeValue::NextFree(_))
    }

    pub fn value(&self) -> Option<&[u8]> {
        self.raw.value()
    }

    pub fn raw(&self) -> &NodeValue {
        &self.raw
    }

    pub fn hash(&self) -> &B256 {
        &self.hash
    }

    pub fn is_empty_node(&self) -> bool {
        EMPTY_TRIE_NODE.contains_key(&self.hash)
    }
}

pub fn init_world_state() -> (Arc<Node>, BTreeMap<B256, Arc<Node>>) {
    let mut empty_nodes = BTreeMap::new();

    let mut node = Node::empty_leaf();
    empty_nodes.insert(*node.hash(), node.clone());
    for _ in 0..ZK_TRIE_DEPTH {
        node = Arc::new(Node::branch(node.hash, *node.hash()));
        empty_nodes.insert(*node.hash(), node.clone());
    }
    node = Arc::new(Node::branch(B256::default(), *node.hash()));
    empty_nodes.insert(*node.hash(), node.clone());

    (node, empty_nodes)
}

#[derive(Clone, Debug, PartialEq)]
pub enum NodeValue {
    Branch(BranchNode),
    Leaf(LeafNode),
    EmptyLeaf,
    NextFree(LeafNode),
}

impl NodeValue {
    pub fn ty(&self) -> &'static str {
        match self {
            Self::Branch(_) => "branch",
            Self::EmptyLeaf => "emptyleaf",
            Self::Leaf(_) => "leaf",
            Self::NextFree(_) => "nextfree",
        }
    }

    pub fn new_next_free(val: Bytes) -> NodeValue {
        NodeValue::NextFree(LeafNode {
            path: Bytes::new(),
            value: val,
        })
    }

    pub fn branch(&self) -> Option<&BranchNode> {
        match self {
            Self::Branch(node) => Some(node),
            _ => None,
        }
    }

    pub fn hash(&self) -> B256 {
        lazy_static::lazy_static! {
            static ref EMPTY_TRIE_NODE_HASH: B256 = keccak_hash(&[]).into();
        }
        match self {
            NodeValue::EmptyLeaf => B256::default(),
            NodeValue::NextFree(_) | NodeValue::Branch(_) | NodeValue::Leaf(_) => {
                linea_mimc::sum(&self.to_bytes()).unwrap().into()
            }
        }
    }

    pub fn value(&self) -> Option<&[u8]> {
        match self {
            NodeValue::Branch(_) => None,
            NodeValue::EmptyLeaf => Some(&[]),
            NodeValue::NextFree(node) => Some(&node.value),
            NodeValue::Leaf(node) => Some(&node.value),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_to(&mut out);
        out
    }

    pub fn parse_leaf(path: Bytes, buf: Bytes) -> NodeValue {
        if &buf == B256::default().as_slice() {
            return NodeValue::EmptyLeaf;
        }
        NodeValue::Leaf(LeafNode { path, value: buf })
    }

    pub fn parse_root(buf: &[u8]) -> Result<NodeValue, Error> {
        if buf.len() != 64 {
            return Err(Error::InvalidBranchNode(buf.to_vec().into()));
        }
        Ok(NodeValue::Branch(BranchNode {
            left: B256::from_slice(&buf[..32]),
            right: B256::from_slice(&buf[32..]),
        }))
    }

    pub fn parse_branch(buf: &[u8]) -> Result<NodeValue, Error> {
        if buf.len() != 64 {
            return Err(Error::InvalidBranchNode(buf.to_vec().into()));
        }
        Ok(NodeValue::Branch(BranchNode {
            left: B256::from_slice(&buf[..32]).into(),
            right: B256::from_slice(&buf[32..]),
        }))
    }

    pub fn write_to(&self, out: &mut Vec<u8>) {
        match self {
            NodeValue::Branch(node) => {
                out.extend(&node.left.0[..]);
                out.extend(&node.right.0[..]);
            }
            NodeValue::Leaf(node) => out.extend(&node.value),
            NodeValue::NextFree(node) => out.extend(&node.value),
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BranchNode {
    pub left: B256,
    pub right: B256,
}

#[derive(Clone, Debug, PartialEq)]
pub enum HashOrNode {
    Node(Arc<Node>),
    Hash(B256),
}

impl From<&B256> for HashOrNode {
    fn from(n: &B256) -> Self {
        Self::Hash(*n)
    }
}

impl From<B256> for HashOrNode {
    fn from(n: B256) -> Self {
        Self::Hash(n)
    }
}

impl From<&Arc<Node>> for HashOrNode {
    fn from(n: &Arc<Node>) -> Self {
        Self::Node(n.clone())
    }
}

impl From<Arc<Node>> for HashOrNode {
    fn from(n: Arc<Node>) -> Self {
        Self::Node(n.clone())
    }
}

impl HashOrNode {
    pub fn wrap_branch_child(n: &Arc<Node>) -> Self {
        match n.raw() {
            NodeValue::NextFree(_) => Self::Node(n.clone()),
            _ => Self::Hash(*n.hash()),
        }
    }

    pub fn expand<D: Database<Node = Node>>(&self, db: &D) -> Result<Option<Arc<Node>>, Error> {
        // println!("{:?} expand", self);
        match self {
            Self::Hash(hash) => match db.get_node(hash) {
                Ok(n) => Ok(n),
                Err(err) => Err(err),
            },
            Self::Node(n) => Ok(Some(n.clone())),
        }
    }

    pub fn hash(&self) -> &B256 {
        match self {
            Self::Hash(hash) => hash,
            Self::Node(n) => n.hash(),
        }
    }
}

impl BranchNode {
    pub fn child(&self, idx: u8) -> &B256 {
        if idx == 0 {
            &self.left
        } else if idx == 1 {
            &self.right
        } else {
            unreachable!()
        }
    }

    pub fn new_replace(&self, idx: u8, n: B256) -> Self {
        let left = if idx == 0 { n } else { self.left };
        let right = if idx == 1 { n } else { self.right };
        Self { left, right }
    }
}

impl From<BranchNode> for Node {
    fn from(n: BranchNode) -> Self {
        Node::new(NodeValue::Branch(n))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LeafNode {
    // pub location: Vec<u8>,
    pub path: Bytes,
    pub value: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct LeafOpening {
    pub hkey: B256,
    pub hval: B256,
    pub prev_leaf: u64,
    pub next_leaf: u64,
}

impl Decodable for LeafOpening {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(LeafOpening::parse(&buf))
    }
}

impl Encodable for LeafOpening {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        out.put_slice(&self.to_bytes())
    }
}

impl LeafOpening {
    pub fn head() -> &'static LeafOpening {
        &LEAF_OPENING_HEAD
    }

    pub fn tail() -> &'static LeafOpening {
        &LEAF_OPENING_TAIL
    }

    pub fn new(prev_index: u64, next_index: u64, hkey: B256, hval: B256) -> Self {
        Self {
            prev_leaf: prev_index.into(),
            next_leaf: next_index.into(),
            hkey,
            hval,
        }
    }

    pub fn parse(buf: &[u8]) -> Self {
        let prev_leaf = U256::from_be_slice(&buf[..32]);
        let next_leaf = U256::from_be_slice(&buf[32..64]);
        let hkey = B256::from_slice(&buf[64..96]);
        let hval = B256::from_slice(&buf[96..]);
        Self {
            hkey,
            hval,
            prev_leaf: prev_leaf.to(),
            next_leaf: next_leaf.to(),
        }
    }

    pub fn new_hval(&self, hval: B256) -> Self {
        let mut new = self.clone();
        new.hval = hval;
        new
    }

    pub fn new_next_leaf(&self, next_leaf: u64) -> Self {
        let mut new = self.clone();
        new.next_leaf = next_leaf;
        new
    }

    pub fn new_prev_leaf(&self, prev_leaf: u64) -> Self {
        let mut new = self.clone();
        new.prev_leaf = prev_leaf;
        new
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0_u8; 96 + 32];

        let mut tmp = U256::from_limbs_slice(&[self.prev_leaf]);
        out[..32].copy_from_slice(&tmp.to_be_bytes::<32>());

        tmp = U256::from_limbs_slice(&[self.next_leaf]);
        out[32..64].copy_from_slice(&tmp.to_be_bytes::<32>());

        out[64..96].copy_from_slice(&self.hkey.0);
        out[96..].copy_from_slice(&self.hval.0);
        out
    }
}

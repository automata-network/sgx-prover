use std::prelude::v1::*;

use eth_types::SU256;
use std::sync::Arc;

use crate::{
    handling_elems_and_byte32, hash_elems_with_domain, Byte32, Error, Hash, HashScheme,
    HASH_BYTE_LEN,
};

lazy_static::lazy_static! {
    static ref EMPTY: Arc<Node> = Arc::new(Node::new_empty());
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Node {
    value: NodeValue,
    hash: Hash,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NodeValue {
    Empty,
    Leaf(LeafNode),
    Branch(BranchNode),
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BranchType {
    BothTerminal = 6u8,
    LeftTerminal = 7u8,
    RightTerminal = 8u8,
    BothBranch = 9u8,
}

impl BranchType {
    pub fn left(&self, hash: Hash) -> BranchHash {
        match self {
            Self::BothTerminal | Self::LeftTerminal => BranchHash::Ternimal(hash),
            Self::BothBranch | Self::RightTerminal => BranchHash::Branch(hash),
        }
    }

    pub fn right(&self, hash: Hash) -> BranchHash {
        match self {
            Self::BothTerminal | Self::RightTerminal => BranchHash::Ternimal(hash),
            Self::BothBranch | Self::LeftTerminal => BranchHash::Branch(hash),
        }
    }

    pub fn deduce_upgrade(&self, go_right: bool) -> Self {
        if go_right {
            match self {
                Self::BothTerminal => Self::LeftTerminal,
                Self::LeftTerminal => *self,
                Self::RightTerminal | Self::BothBranch => Self::BothBranch,
            }
        } else {
            match self {
                Self::BothTerminal => Self::RightTerminal,
                Self::LeftTerminal | Self::BothBranch => Self::BothBranch,
                Self::RightTerminal => *self,
            }
        }
    }

    pub fn deduce_downgrade(&self, at_right: bool) -> Self {
        if at_right {
            match &self {
                Self::LeftTerminal => Self::BothTerminal,
                Self::BothBranch => Self::RightTerminal,
                Self::BothTerminal | Self::RightTerminal => {
                    panic!("can not downgrade a node with terminal child ({:?})", self)
                }
            }
        } else {
            match &self {
                Self::BothBranch => Self::LeftTerminal,
                Self::RightTerminal => Self::BothTerminal,
                Self::BothTerminal | Self::LeftTerminal => {
                    panic!("can not downgrade a node with terminal child ({:?})", self)
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BranchHash {
    Ternimal(Hash),
    Branch(Hash),
}

impl From<&Node> for BranchHash {
    fn from(n: &Node) -> Self {
        if n.is_terminal() {
            Self::Ternimal(*n.hash())
        } else {
            Self::Branch(*n.hash())
        }
    }
}

impl Default for BranchHash {
    fn default() -> Self {
        BranchHash::Ternimal(Hash::default())
    }
}

impl BranchHash {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn u256(&self) -> SU256 {
        self.hash().u256()
    }

    pub fn hash(&self) -> &Hash {
        match self {
            BranchHash::Branch(n) => n,
            BranchHash::Ternimal(n) => n,
        }
    }
}

impl Node {
    pub fn from_bytes<H: HashScheme>(mut b: &[u8]) -> Result<Node, Error> {
        if b.len() < 1 {
            return Err(Error::NodeBytesBadSize);
        }
        let ty = b[0];
        b = &b[1..];
        match ty {
            0 | 6 | 7 | 8 | 9 => {
                // branch
                if b.len() != 2 * HASH_BYTE_LEN {
                    return Err(Error::NodeBytesBadSize);
                }
                let left = {
                    let hash = Hash::from_bytes(&b[..HASH_BYTE_LEN]);
                    if matches!(ty, 6 | 7) {
                        BranchHash::Ternimal(hash)
                    } else {
                        BranchHash::Branch(hash)
                    }
                };
                let right = {
                    let hash = Hash::from_bytes(&b[HASH_BYTE_LEN..HASH_BYTE_LEN * 2]);
                    if matches!(ty, 6 | 8) {
                        BranchHash::Ternimal(hash)
                    } else {
                        BranchHash::Branch(hash)
                    }
                };
                return Ok(Node::new_branch::<H>(left, right));
            }
            1 | 4 => {
                // leaf
                if b.len() < HASH_BYTE_LEN + 4 {
                    return Err(Error::NodeBytesBadSize);
                }
                let node_key = Hash::from_bytes(&b[..HASH_BYTE_LEN]);
                let mark = {
                    let mut buf = [0_u8; 4];
                    buf.copy_from_slice(&b[HASH_BYTE_LEN..HASH_BYTE_LEN + 4]);
                    u32::from_le_bytes(buf)
                };
                let preimage_len = (mark & 255) as usize;
                let compressed_flags = mark >> 8;
                let mut value_preimage = Vec::with_capacity(preimage_len);
                let mut cur_pos = HASH_BYTE_LEN + 4;
                if b.len() < cur_pos + preimage_len * 32 + 1 {
                    return Err(Error::NodeBytesBadSize);
                }
                for i in 0..preimage_len {
                    let val =
                        Byte32::from_bytes_padding(&b[i * 32 + cur_pos..(i + 1) * 32 + cur_pos]);
                    value_preimage.push(val);
                }
                cur_pos += preimage_len * 32;
                let preimage_size = b[cur_pos] as usize;
                cur_pos += 1;
                if preimage_size != 0 {
                    if b.len() < cur_pos + preimage_size {
                        return Err(Error::NodeBytesBadSize);
                    }
                }
                Ok(Node::new_leaf::<H>(
                    node_key,
                    compressed_flags,
                    value_preimage,
                ))
            }
            2 | 5 => Ok(Node::new_empty()),
            ty => return Err(Error::InvalidNodeFound(ty)),
        }
    }

    pub fn empty() -> Arc<Self> {
        EMPTY.clone()
    }

    pub fn new_branch_ty<H: HashScheme>(ty: BranchType, left: Hash, right: Hash) -> Node {
        let left = ty.left(left);
        let right = ty.right(right);
        Self::new_branch::<H>(left, right)
    }

    pub fn new_branch<H: HashScheme>(left: BranchHash, right: BranchHash) -> Node {
        let value = BranchNode::new(left, right);
        Node {
            hash: value.hash::<H>(),
            value: NodeValue::Branch(value),
        }
    }

    pub fn new_empty() -> Self {
        let value = NodeValue::Empty;
        Self {
            value,
            hash: Hash::default(),
        }
    }

    pub fn leaf(&self) -> Option<&LeafNode> {
        match &self.value {
            NodeValue::Leaf(node) => Some(node),
            _ => None,
        }
    }

    pub fn new_leaf<H: HashScheme>(
        key: Hash,
        value_flag: u32,
        value_preimage: Vec<Byte32>,
    ) -> Self {
        let node = LeafNode {
            key,
            compressed_flags: value_flag,
            value_preimage,
        };
        Self {
            hash: node.hash::<H>(),
            value: NodeValue::Leaf(node),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(&self.value, NodeValue::Empty)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.value, NodeValue::Empty | NodeValue::Leaf(_))
    }

    pub fn value(&self) -> &NodeValue {
        &self.value
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn data(&self) -> &[u8] {
        match &self.value {
            NodeValue::Leaf(leaf) => leaf.data(),
            _ => &[],
        }
    }

    pub fn canonical_value(&self) -> Vec<u8> {
        match &self.value {
            NodeValue::Empty => vec![5],
            NodeValue::Leaf(node) => node.canonical_value(),
            NodeValue::Branch(node) => node.canonical_value(),
        }
    }
}

pub struct EmptyNode {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LeafNode {
    pub key: Hash,
    pub compressed_flags: u32,
    pub value_preimage: Vec<Byte32>,
}

impl LeafNode {
    pub fn hash<H: HashScheme>(&self) -> Hash {
        let value_hash =
            handling_elems_and_byte32::<H>(self.compressed_flags, &self.value_preimage);
        leaf_hash::<H>(&self.key, &value_hash)
    }

    pub fn data(&self) -> &[u8] {
        let ptr = self.value_preimage.as_ptr() as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, self.value_preimage.len() * 32) }
    }

    pub fn ty() -> u8 {
        4
    }

    pub fn canonical_value(&self) -> Vec<u8> {
        let size = 1 + 32 + 4 + self.value_preimage.len() * 32 + 1;
        let mut val = Vec::with_capacity(size);
        val.push(Self::ty());
        val.extend_from_slice(&self.key.bytes());
        let compressed_flag = self.compressed_flags << 8 + self.value_preimage.len() as u32;
        val.extend_from_slice(&compressed_flag.to_le_bytes());
        for elm in &self.value_preimage {
            val.extend_from_slice(elm.bytes());
        }
        val.push(0);
        val
    }
}

pub fn leaf_hash<H: HashScheme>(k: &Hash, v: &Hash) -> Hash {
    let domain = (LeafNode::ty() as usize).into();
    hash_elems_with_domain::<H>(&domain, &k.u256(), &v.u256(), &[])
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BranchNode {
    pub left: BranchHash,
    pub right: BranchHash,
}

impl BranchNode {
    pub fn new(left: BranchHash, right: BranchHash) -> Self {
        BranchNode { left, right }
    }

    pub fn ty(&self) -> BranchType {
        match (&self.left, &self.right) {
            (BranchHash::Ternimal(_), BranchHash::Ternimal(_)) => BranchType::BothTerminal,
            (BranchHash::Ternimal(_), BranchHash::Branch(_)) => BranchType::LeftTerminal,
            (BranchHash::Branch(_), BranchHash::Ternimal(_)) => BranchType::RightTerminal,
            (BranchHash::Branch(_), BranchHash::Branch(_)) => BranchType::BothBranch,
        }
    }

    pub fn canonical_value(&self) -> Vec<u8> {
        Vec::new()
    }

    pub fn hash<H: HashScheme>(&self) -> Hash {
        let domain = (self.ty() as u64).into();
        hash_elems_with_domain::<H>(&domain, &self.left.u256(), &self.right.u256(), &[])
    }
}

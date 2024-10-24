use std::prelude::v1::*;

use alloy::primitives::{Bytes, B256};
// use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use core::convert::TryFrom;
use serde::{Deserialize, Serialize, Serializer};

use crate::{utils, FlattenedLeaf, KeyRange, LeafOpening, Node};

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "RawTrace")]
pub enum Trace {
    Read(ReadTrace),
    ReadZero(ReadZeroTrace),
    Insertion(InsertionTrace),
    Update(UpdateTrace),
    Deletion(DeletionTrace),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawTrace {
    r#type: usize,
    #[serde(flatten)]
    value: serde_json::Value,
}

impl Serialize for Trace {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert Trace back to RawTrace for serialization
        let raw_trace: RawTrace = self.clone().try_into().map_err(serde::ser::Error::custom)?;

        // Serialize `RawTrace` directly
        raw_trace.serialize(serializer)
    }
}

impl TryFrom<RawTrace> for Trace {
    type Error = serde_json::Error;
    fn try_from(value: RawTrace) -> Result<Self, Self::Error> {
        Ok(match value.r#type {
            0 => Trace::Read(serde_json::from_value(value.value)?),
            1 => Trace::ReadZero(serde_json::from_value(value.value)?),
            2 => Trace::Insertion(serde_json::from_value(value.value)?),
            3 => Trace::Update(serde_json::from_value(value.value)?),
            4 => Trace::Deletion(serde_json::from_value(value.value)?),
            _ => unreachable!(),
        })
    }
}

impl TryInto<RawTrace> for Trace {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<RawTrace, Self::Error> {
        use serde_json::to_value;
        let (ty, value) = match self {
            Self::Read(t) => (0, to_value(t)?),
            Self::ReadZero(t) => (1, to_value(t)?),
            Self::Insertion(t) => (2, to_value(t)?),
            Self::Update(t) => (3, to_value(t)?),
            Self::Deletion(t) => (4, to_value(t)?),
        };
        Ok(RawTrace { r#type: ty, value })
    }
}

impl Trace {
    pub fn is_update(&self) -> bool {
        matches!(
            self,
            Self::Insertion(_) | Self::Update(_) | Self::Deletion(_)
        )
    }

    pub fn old_state(&self) -> (u64, B256) {
        match self {
            Trace::Deletion(n) => (n.new_next_free_node, n.old_sub_root),
            Trace::Insertion(n) => (n.new_next_free_node - 1, n.old_sub_root),
            Trace::Read(n) => (n.next_free_node, n.sub_root),
            Trace::ReadZero(n) => (n.next_free_node, n.sub_root),
            Trace::Update(n) => (n.new_next_free_node, n.old_sub_root),
        }
    }

    pub fn old_top_hash(&self) -> B256 {
        *self.old_top_node().hash()
    }

    pub fn old_top_node(&self) -> Node {
        let (next_free_node, sub_root) = self.old_state();
        Node::root_node(next_free_node, sub_root)
    }

    pub fn key(&self) -> &Bytes {
        match self {
            Self::Deletion(n) => &n.key,
            Self::Insertion(n) => &n.key,
            Self::Read(n) => &n.key,
            Self::ReadZero(n) => &n.key,
            Self::Update(n) => &n.key,
        }
    }

    pub fn read_value(&self) -> &[u8] {
        match self {
            Self::Deletion(_) => &[],
            Self::Insertion(_) => &[],
            Self::Read(n) => &n.value,
            Self::ReadZero(_) => &[],
            Self::Update(_) => &[],
        }
    }

    pub fn location(&self) -> &Bytes {
        match self {
            Self::Deletion(n) => &n.location,
            Self::Insertion(n) => &n.location,
            Self::Read(n) => &n.location,
            Self::ReadZero(n) => &n.location,
            Self::Update(n) => &n.location,
        }
    }

    pub fn key_range(&self) -> KeyRange {
        match self {
            Self::ReadZero(n) => KeyRange {
                left_index: n.left_proof.leaf_index,
                center: None,
                right_index: n.right_proof.leaf_index,
            },
            Self::Read(n) => KeyRange {
                left_index: n.leaf.prev_leaf,
                center: Some(FlattenedLeaf {
                    leaf_index: n.proof.leaf_index,
                    leaf_value: n.value.clone().into(),
                }),
                right_index: n.leaf.next_leaf,
            },
            Self::Update(n) => KeyRange {
                left_index: n.prior_updated_leaf.prev_leaf,
                center: Some(FlattenedLeaf {
                    leaf_index: n.proof.leaf_index,
                    leaf_value: n.old_value.clone().into(),
                }),
                right_index: n.prior_updated_leaf.next_leaf,
            },
            Self::Insertion(n) => KeyRange {
                left_index: n.left_proof.leaf_index,
                center: None,
                right_index: n.right_proof.leaf_index,
            },
            Self::Deletion(n) => KeyRange {
                left_index: n.prior_deleted_leaf.prev_leaf,
                center: Some(FlattenedLeaf {
                    leaf_index: n.deleted_proof.leaf_index,
                    leaf_value: n.deleted_value.clone().into(),
                }),
                right_index: n.prior_deleted_leaf.next_leaf,
            },
        }
    }

    pub fn nodes(&self) -> Vec<Node> {
        match self {
            Self::Update(n) => n.proof.build_nodes(Some(&n.prior_updated_leaf)),
            Self::Insertion(n) => [
                n.left_proof.build_nodes(Some(&n.prior_left_leaf)),
                n.new_proof.build_nodes(None),
                n.right_proof.build_nodes(Some(&n.prior_right_leaf)),
            ]
            .concat(),
            Self::Deletion(n) => [
                n.left_proof.build_nodes(Some(&n.prior_left_leaf)),
                n.deleted_proof.build_nodes(Some(&n.prior_deleted_leaf)),
                n.right_proof.build_nodes(Some(&n.prior_right_leaf)),
            ]
            .concat(),
            Self::Read(_) | Self::ReadZero(_) => Vec::new(),
        }
    }
}

#[repr(u32)]
pub enum TraceType {
    Read = 0,
    ReadZero = 1,
    Insertion = 2,
    Update = 3,
    Deletion = 4,
}

// impl rlp::Decodable for Trace {
//     fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
//         let rlp = rlp.at(0)?;
//         let ty: Vec<u8> = rlp.at(0)?.as_val()?;
//         let ty = u32::from_be_bytes(
//             ty.try_into()
//                 .map_err(|_| rlp::DecoderError::Custom("ty expected to 4 bytes"))?,
//         );
//         let rlp = rlp.at(1)?;
//         Ok(match ty {
//             4 => Trace::Deletion(rlp.as_val()?),
//             3 => Trace::Update(rlp.as_val()?),
//             2 => Trace::Insertion(rlp.as_val()?),
//             1 => Trace::ReadZero(rlp.as_val()?),
//             0 => Trace::Read(rlp.as_val()?),
//             _ => return Err(rlp::DecoderError::Custom("unknown trace type")),
//         })
//     }
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTrace {
    pub location: Bytes,
    pub new_next_free_node: u64,
    pub old_sub_root: B256,
    pub new_sub_root: B256,
    pub proof: TraceProof,
    pub key: Bytes,
    pub old_value: Bytes,
    pub new_value: Bytes,
    pub prior_updated_leaf: LeafOpening,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct DeletionTrace {
    pub location: Bytes,
    pub new_next_free_node: u64,
    pub old_sub_root: B256,
    pub new_sub_root: B256,
    pub left_proof: TraceProof,
    pub deleted_proof: TraceProof,
    pub right_proof: TraceProof,
    pub key: Bytes,
    pub deleted_value: Bytes,
    pub prior_left_leaf: LeafOpening,
    pub prior_deleted_leaf: LeafOpening,
    pub prior_right_leaf: LeafOpening,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct TraceProof {
    pub leaf_index: u64,
    pub siblings: Vec<B256>,
}

impl TraceProof {
    pub fn build_nodes(&self, leaf: Option<&LeafOpening>) -> Vec<Node> {
        let mut out = Vec::new();
        let trie_path = utils::get_leaf_path(self.leaf_index);

        let mut root = match leaf {
            Some(leaf) => Node::leaf(trie_path[trie_path.len() - 1..].to_vec(), leaf.to_bytes()),
            None => Node::empty_leaf().as_ref().clone(),
        };
        for idx in 0..self.siblings.len() {
            let sibling = self.siblings[idx];
            let new_root = if trie_path[self.siblings.len() - idx] == 0 {
                Node::raw_branch(*root.hash(), sibling)
            } else {
                Node::raw_branch(sibling, *root.hash())
            };
            out.push(root);
            root = new_root;
        }
        out.push(root);
        out
    }
}

// impl Decodable for TraceProof {
//     fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
//         use alloy_rlp::*;
//         let mut payload = Header::decode_bytes(buf, true)?;
//         let leaf_index = u64::decode(&mut payload)?;
//         let mut siblings = Vec::new();
//         alloy_rlp::d
//     }
// }

// impl rlp::Decodable for TraceProof {
//     fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
//         let leaf_index: u64 = rlp.val_at(0)?;
//         let mut siblings = Vec::new();
//         let rlp = rlp.at(1)?;
//         for i in 0..rlp.item_count()? {
//             let node: B256 = rlp.val_at(i)?;
//             siblings.push(node);
//         }
//         Ok(TraceProof {
//             leaf_index,
//             siblings,
//         })
//     }
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct InsertionTrace {
    pub location: Bytes,
    pub new_next_free_node: u64,
    pub old_sub_root: B256,
    pub new_sub_root: B256,
    pub left_proof: TraceProof,
    pub new_proof: TraceProof,
    pub right_proof: TraceProof,
    pub key: Bytes,
    pub value: Bytes,
    pub prior_left_leaf: LeafOpening,
    pub prior_right_leaf: LeafOpening,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct ReadTrace {
    pub location: Bytes,
    pub next_free_node: u64,
    pub sub_root: B256,
    pub leaf: LeafOpening,
    pub proof: TraceProof,
    pub key: Bytes,
    pub value: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct ReadZeroTrace {
    pub location: Bytes,
    pub next_free_node: u64,
    pub sub_root: B256,
    pub left_leaf: LeafOpening,
    pub right_leaf: LeafOpening,
    pub left_proof: TraceProof,
    pub right_proof: TraceProof,
    pub key: Bytes,
}

#[cfg(test)]
mod test {
    use alloy::primitives::{hex::FromHex, Bytes};

    use super::*;

    fn read_data(path: &str) -> Bytes {
        let data = std::fs::read_to_string(&format!("testdata/{}.hex", path)).unwrap();
        Bytes::from_hex(data.as_bytes()).unwrap()
    }

    // fn parse_trace(path: &str) -> Trace {
    //     rlp::decode(&read_data(path)).unwrap()
    // }

    // #[test]
    // fn test_parse_trace() {
    //     let deletion_trace = parse_trace("deletion_trace");
    //     assert!(matches!(deletion_trace, Trace::Deletion(_)));

    //     let insertion_trace = parse_trace("insertion_trace");
    //     assert!(matches!(insertion_trace, Trace::Insertion(_)));

    //     let read_trace = parse_trace("read_trace");
    //     assert!(matches!(read_trace, Trace::Read(_)));

    //     let read_zero_trace = parse_trace("read_zero_trace");
    //     assert!(matches!(read_zero_trace, Trace::ReadZero(_)));

    //     let update_trace = parse_trace("update_trace");
    //     assert!(matches!(update_trace, Trace::Update(_)));
    // }
}

#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "tstd")]
#[macro_use]
extern crate sgxlib as std;

use std::prelude::v1::*;

mod trie;
use eth_types::{HexBytes, SH256, SH160};
use std::sync::Arc;
pub use trie::*;

mod storage;
pub use storage::*;

mod trace;
pub use trace::*;

mod node;
pub use node::*;

mod hash;
pub use hash::*;

mod sparse_merkle_trie;
pub use sparse_merkle_trie::*;

mod utils;
pub use utils::*;

base::stack_error!(
    name: Error,
    stack_name: ErrorStack,
    error: {
        ReachedMaxLevel,
        PathNotAllow,
        InMemNextNodeNotFound,
        NextFreeNodeNotFound,
        NextFreeNodeEmptyValue(Arc<Node>),
        NodeNotFound(usize, SH256),
        ZKTrieKeyNotFound(HexBytes),
        ZkTrieParseNodeFail(HexBytes, &'static str),
        HashFail(String),
        InvalidBranchNode(HexBytes),
        InvalidProof{
            want_sub_root: SH256, 
            got_sub_root: SH256, 
            got_top_root: SH256,
        },
        RootNodeNotFound(SH256),
        RootNodeExpectToBeBranchNode(Arc<Node>),
    },
    stack: {
        BuildNonInclusionProofLeft(prefix: SH160, key: HexBytes),
        BuildNonInclusionProofRight(prefix: SH160, key: HexBytes),
        BuildInclusionProof(prefix: SH160, key: HexBytes),
        ParseRootFromSibling(),
        ParseBranchNode(lvl: usize),
        ParseLeftNode(),
        ParseRightNode(),
        PutLeftLeaf(),
        PutCenterLeaf(),
        PutRightLeaf(),
        
        GetNextFreeNode(),
        SetNextFreeNode(idx: u64),

        DBRedirectStatic(),

        ZkTriePut(),
    }
);

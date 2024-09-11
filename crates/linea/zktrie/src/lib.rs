mod trie;
use std::sync::Arc;
use alloy::primitives::{Bytes, B256, Address};
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
        UnknownRoot { root: B256 },
        IndexNotFoundAtRoot { root: B256, prefix: Address, key: B256 },
        ReachedMaxLevel,
        PathNotAllow,
        InMemNextNodeNotFound,
        NextFreeNodeNotFound,
        NextFreeNodeEmptyValue(Arc<Node>),
        NodeNotFound(usize, B256),
        ZKTrieKeyNotFound(Bytes),
        ZkTrieParseNodeFail(Bytes, &'static str),
        HashFail(String),
        InvalidBranchNode(Bytes),
        InvalidProof{
            want_sub_root: B256,
            got_sub_root: B256,
            got_top_root: B256
        },
        RootNodeNotFound(B256),
        RootNodeExpectToBeBranchNode(Arc<Node>),
    },
    stack: {
        BuildNonInclusionProofLeft(prefix: Address, key: Bytes),
        BuildNonInclusionProofRight(prefix: Address, key: Bytes),
        BuildInclusionProof(prefix: Address, key: Bytes),
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

        GetNearestKeyFromEmpty(),
        ZktrieRemove(),
        ZktrieRead(),
        ZktriePut(),
    }
);

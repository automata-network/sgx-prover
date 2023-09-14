use std::prelude::v1::*;

use eth_types::{HexBytes, SH256};
use scroll_types::Block;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub struct ProveResult {
    pub new_state_root: SH256,
    pub withdrawal_root: SH256,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Pob {
    pub block: Block,
    pub data: PobData,
}

impl Pob {
    pub fn new(block: Block, mut data: PobData) -> Pob {
        data.mpt_nodes.sort_unstable();
        Pob { block, data }
    }

    pub fn state_hash(&self) -> SH256 {
        // the mpt_nodes should be in order
        crypto::keccak_encode(|hash| {
            for item in &self.data.mpt_nodes {
                hash(&item);
            }
        })
        .into()
    }

    pub fn block_hash(&self) -> SH256 {
        self.block.header.hash()
    }
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct PobData {
    pub chain_id: u64,
    pub prev_state_root: SH256,
    pub block_hashes: BTreeMap<u64, SH256>,
    pub mpt_nodes: Vec<HexBytes>,
    pub codes: Vec<HexBytes>,
    pub start_l1_queue_index: u64,
}

use std::prelude::v1::*;

use eth_types::{Block, HexBytes, Signer, SH256, SU256};
use evm_executor::PrecompileSet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub struct BuildEnv {
    pub precompile_set: PrecompileSet,
    pub signer: Signer,
    pub cfg: evm_executor::Config,
}

impl BuildEnv {
    pub fn new(chain_id: SU256) -> Self {
        Self {
            precompile_set: PrecompileSet::berlin(),
            signer: Signer::new(chain_id),
            cfg: evm_executor::Config::shanghai(),
        }
    }
}

pub struct ProveResult {
    pub new_state_root: SH256,
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct Pob {
    pub blocks: Vec<Block>,
    pub data: PobData,
}

impl Pob {
    pub fn state_hash(&self) -> SH256 {
        crypto::keccak_encode(|hash| {
            for item in &self.data.mpt_nodes {
                hash(&item);
            }
        })
        .into()
    }

    pub fn block_hash(&self) -> SH256 {
        crypto::keccak_encode(|hash| {
            for blk in &self.blocks {
                hash(&blk.header.hash().0);
            }
        })
        .into()
    }
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct PobData {
    pub chain_id: u64,
    pub prev_state_root: SH256,
    pub withdrawal_root: SH256,
    pub block_hashes: BTreeMap<u64, SH256>,
    pub mpt_nodes: Vec<HexBytes>,
    pub codes: Vec<HexBytes>,
}

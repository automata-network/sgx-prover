use std::prelude::v1::*;

use eth_types::{HexBytes, StorageResult, SH160, SH256, SU256, SU64};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};

use crate::POSEIDON_EMPTY_CODE;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct StateAccount {
    pub nonce: u64,
    pub balance: SU256,
    pub root: SH256,
    pub keccak_code_hash: SH256,

    // StateAccount Scroll extensions
    pub poseidon_code_hash: SH256,
    pub code_size: u64,
}

impl Default for StateAccount {
    fn default() -> Self {
        StateAccount {
            nonce: 0,
            balance: 0.into(),
            root: zktrie::empty_root(),
            keccak_code_hash: eth_types::StateAccount::empty_code_hash(),
            poseidon_code_hash: *POSEIDON_EMPTY_CODE,
            code_size: 0,
        }
    }
}

impl StateAccount {
    pub fn is_exist(&self) -> bool {
        self != &Self::default()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AccountResult {
    pub address: SH160,
    pub account_proof: Vec<HexBytes>,
    pub balance: SU256,
    pub poseidon_code_hash: SH256,
    pub keccak_code_hash: SH256,
    pub code_size: SU64,
    pub nonce: SU64,
    pub storage_hash: SH256,
    pub storage_proof: Vec<StorageResult>,
}

#[derive(Debug, Clone, Default)]
pub struct FetchStateResult {
    pub acc: Option<AccountResult>,
    pub code: Option<HexBytes>,
}

use std::prelude::v1::*;

use eth_types::{
    AccessListTx, DynamicFeeTx, HexBytes, LegacyTx, TransactionAccessTuple, SH160, SH256, SU256,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{BlockHeader, Transaction, TransactionInner, L1_MESSAGE_TX_TYPE};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockTrace {
    #[serde(rename = "chainID")]
    #[serde(default)]
    pub chain_id: u64,
    #[serde(default)]
    pub version: String,
    pub coinbase: AccountWrapper,
    pub header: BlockHeader,
    pub transactions: Vec<TraceTx>,
    pub storage_trace: StorageTrace,
    #[serde(default)]
    pub tx_storage_traces: Vec<StorageTrace>,
    pub execution_results: Vec<ExecutionResult>,
    // pub mptwitness: Option<String>,
    #[serde(rename = "withdraw_trie_root")]
    pub withdraw_trie_root: Option<SH256>,
    #[serde(default)]
    pub start_l1_queue_index: u64,
}

impl BlockTrace {
    pub fn num_l1_msg(&self, total_l1_msg_poped_before: u64) -> u64 {
        let mut last_queue_index = None;
        for tx in &self.transactions {
            if tx.is_l1_msg() {
                last_queue_index = Some(tx.nonce);
            }
        }
        match last_queue_index {
            Some(last_queue_index) => last_queue_index - total_l1_msg_poped_before + 1,
            None => 0,
        }
    }

    pub fn num_l2_txs(&self) -> u64 {
        let mut count = 0;
        for tx in &self.transactions {
            if !tx.is_l1_msg() {
                count += 1;
            }
        }
        return count;
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountWrapper {
    pub address: SH160,
    pub nonce: u64,
    pub balance: SU256,
    #[serde(default)]
    pub keccak_code_hash: SH256,
    #[serde(default)]
    pub poseidon_code_hash: SH256,
    #[serde(default)]
    pub code_size: u64,
    // pub storage: Option<StorageWrapper>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageWrapper {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageTrace {
    // Root hash before block execution:
    pub root_before: SH256,
    // Root hash after block execution, is nil if execution has failed
    pub root_after: SH256,

    // All proofs BEFORE execution, for accounts which would be used in tracing
    pub proofs: BTreeMap<String, Vec<HexBytes>>,

    // All storage proofs BEFORE execution
    #[serde(default)]
    pub storage_proofs: BTreeMap<String, BTreeMap<String, Vec<HexBytes>>>,

    // Node entries for deletion, no need to distinguish what it is from, just read them
    // into the partial db
    #[serde(default)]
    pub deletion_proofs: Vec<HexBytes>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionResult {
    pub l1_data_fee: Option<SU256>,
    pub gas: u64,
    pub failed: bool,
    pub return_value: String,
    // Sender's account state (before Tx)
    pub from: Option<AccountWrapper>,
    // Receiver's account state (before Tx)
    pub to: Option<AccountWrapper>,
    // AccountCreated record the account if the tx is "create"
    // (for creating inside a contract, we just handle CREATE op)
    pub account_created: Option<AccountWrapper>,

    // Record all accounts' state which would be affected AFTER tx executed
    // currently they are just `from` and `to` account
    #[serde(default)]
    pub accounts_after: Vec<AccountWrapper>,

    // `PoseidonCodeHash` only exists when tx is a contract call.
    pub poseidon_code_hash: Option<SH256>,
    // If it is a contract call, the contract code is returned.
    #[serde(default)]
    pub byte_code: HexBytes,
    // we don't need it for now
    // pub struct_logs: Vec<StructLogRes>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StructLogRes {
    pub pc: u64,
    pub op: String,
    pub gas: u64,
    pub gas_cost: u64,
    pub depth: u64,
    pub error: Option<String>,
    #[serde(default)]
    pub stack: Vec<String>,
    #[serde(default)]
    pub memory: Vec<String>,
    #[serde(default)]
    pub storage: BTreeMap<String, String>,
    #[serde(default)]
    pub refund: u64,
    pub extra_data: Option<ExtraData>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtraData {
    // Indicate the call succeeds or not for CALL/CREATE op
    #[serde(default)]
    pub call_failed: bool,
    // CALL | CALLCODE | DELEGATECALL | STATICCALL: [tx.to address’s code, stack.nth_last(1) address’s code]
    // CREATE | CREATE2: [created contract’s code]
    // CODESIZE | CODECOPY: [contract’s code]
    // EXTCODESIZE | EXTCODECOPY: [stack.nth_last(0) address’s code]
    #[serde(default)]
    pub code_list: Vec<HexBytes>,
    // SSTORE | SLOAD: [storageProof]
    // SELFDESTRUCT: [contract address’s account, stack.nth_last(0) address’s account]
    // SELFBALANCE: [contract address’s account]
    // BALANCE | EXTCODEHASH: [stack.nth_last(0) address’s account]
    // CREATE | CREATE2: [created contract address’s account (before constructed),
    // 					  created contract address's account (after constructed)]
    // CALL | CALLCODE: [caller contract address’s account,
    // 					stack.nth_last(1) (i.e. callee) address’s account,
    //					callee contract address's account (value updated, before called)]
    // STATICCALL: [stack.nth_last(1) (i.e. callee) address’s account,
    //					  callee contract address's account (before called)]
    #[serde(default)]
    pub state_list: Vec<AccountWrapper>,
    // The status of caller, it would be captured twice:
    // 1. before execution and 2. updated in CaptureEnter (for CALL/CALLCODE it duplicated with StateList[0])
    #[serde(default)]
    pub caller: Vec<AccountWrapper>,
}

#[derive(Default, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TraceTx {
    pub r#type: u8,
    pub nonce: u64,
    pub tx_hash: SH256,
    pub gas: u64,
    pub gas_price: SU256,
    pub gas_tip_cap: Option<SU256>,
    pub gas_fee_cap: Option<SU256>,
    pub from: SH160,
    pub to: Option<SH160>,
    pub chain_id: SU256,
    pub value: SU256,
    pub data: HexBytes,
    pub is_create: bool,
    pub access_list: Option<Vec<TransactionAccessTuple>>,
    pub v: SU256,
    pub r: SU256,
    pub s: SU256,
}

impl TraceTx {
    pub fn is_l1_msg(&self) -> bool {
        self.r#type == L1_MESSAGE_TX_TYPE
    }

    pub fn to_tx(&self) -> Transaction {
        let mut tx = Transaction::default();
        tx.r#type = (self.r#type as u64).into();
        tx.nonce = self.nonce.into();
        tx.gas = self.gas.into();
        tx.gas_price = self.gas_price.into();
        tx.max_priority_fee_per_gas = self.gas_tip_cap;
        tx.max_fee_per_gas = self.gas_fee_cap;
        tx.to = self.to;
        tx.chain_id = Some(self.chain_id);
        tx.value = self.value;
        tx.input = self.data.clone();
        tx.v = self.v;
        tx.r = self.r;
        tx.s = self.s;
        tx.from = Some(self.from);
        if self.r#type == L1_MESSAGE_TX_TYPE {
            tx.queue_index = Some(self.nonce.into());
            tx.sender = Some(self.from);
        }
        
        assert_eq!(tx.clone().inner().unwrap().hash(), self.tx_hash, "tx convert failed");
        tx
    }

    pub fn to_rlp_encoding(&self) -> Vec<u8> {
        let tx = match self.r#type {
            0 => TransactionInner::Legacy(LegacyTx {
                nonce: self.nonce.into(),
                to: self.to.into(),
                value: self.value,
                gas: self.gas.into(),
                gas_price: self.gas_price,
                data: self.data.clone(),
                v: self.v,
                r: self.r,
                s: self.s,
            }),
            1 => TransactionInner::AccessList(AccessListTx {
                chain_id: self.chain_id,
                nonce: self.nonce.into(),
                to: self.to.into(),
                value: self.value,
                gas: self.gas.into(),
                gas_price: self.gas_price.into(),
                data: self.data.clone(),
                access_list: self.access_list.clone().unwrap(),
                v: self.v,
                r: self.r,
                s: self.s,
            }),
            2 => TransactionInner::DynamicFee(DynamicFeeTx {
                chain_id: self.chain_id.into(),
                nonce: self.nonce.into(),
                max_priority_fee_per_gas: self.gas_tip_cap.unwrap().into(),
                max_fee_per_gas: self.gas_fee_cap.unwrap().into(),
                gas: self.gas.into(),
                to: self.to.into(),
                value: self.value,
                data: self.data.clone(),
                access_list: self.access_list.clone().unwrap(),
                v: self.v,
                r: self.r,
                s: self.s,
            }),
            126 => return Vec::new(),
            ty => unreachable!("unknown tx type: {}", ty),
        };
        tx.to_bytes()
    }
}

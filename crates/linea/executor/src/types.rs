use std::convert::Infallible;

use crate::ZkStateAccount;
use alloy::{
    consensus::{Transaction, TxEip4844Variant, TxEnvelope},
    primitives::{Address, B256, U256},
};
use base::PrimitivesConvert;
use linea_revm::{
    db::CacheDB,
    primitives::{AccessList, BlockEnv, EVMError},
};
pub use linea_revm::{
    primitives::{state::AccountInfo, Bytecode, SpecId, TxEnv},
    DatabaseRef,
};

base::stack_error! {
    name: ExecutionError,
    stack_name: ExecutionErrorStack,
    error: {

    },
    wrap: {
        ZkTrie(linea_zktrie::Error),
        EVM(EVMError<Infallible>),
        Str(String),
    },
    stack: {
        CommitAccount(addr: Address, acc: ZkStateAccount),
        CommitStorage(addr: Address, key: U256, value: U256),
        CommitTx(number: u64, tx_hash: B256),
    }
}

pub trait Context {
    type ExecutionResult;
    type CommitState;
    type DB: DatabaseRef<Error = Infallible>;

    fn db(&self) -> Self::DB;
    fn spec_id(&self) -> SpecId;

    fn chain_id(&self) -> u64;
    fn number(&self) -> u64;
    fn coinbase(&self) -> Address;
    fn transactions(&self) -> impl Iterator<Item = TxEnvelope>;
    fn timestamp(&self) -> U256;
    fn gas_limit(&self) -> U256;
    fn base_fee_per_gas(&self) -> Option<U256>;
    fn difficulty(&self) -> U256;
    fn prevrandao(&self) -> Option<B256>;
    fn old_state_root(&self) -> B256;
    fn state_root(&self) -> B256;
    fn withdrawal_root(&self) -> B256;
    fn block_hash(&self) -> B256;
    fn verify_execution_result(&self, idx: usize, result: Self::ExecutionResult);
    fn commit_changes(&self, db: CacheDB<Self::DB>) -> Result<Self::CommitState, ExecutionError>;

    fn tx_env(&self, tx_idx: usize, rlp: Vec<u8>) -> TxEnv;

    fn _gas_price(&self, tx: &TxEnvelope) -> Option<U256> {
        Some(match tx.gas_price() {
            Some(v) => v.to(),
            None => {
                let max_fee = self._max_fee_per_gas(tx)?;
                let priority_fee = self._max_priority_fee_per_gas(tx)?;
                let base_fee = self.base_fee_per_gas()?;
                (base_fee + priority_fee).min(max_fee)
            }
        })
    }

    fn _access_list<'a>(&self, tx: &'a TxEnvelope) -> Option<&'a AccessList> {
        Some(match tx {
            TxEnvelope::Legacy(_) => return None,
            TxEnvelope::Eip2930(tx) => &tx.tx().access_list,
            TxEnvelope::Eip1559(tx) => &tx.tx().access_list,
            TxEnvelope::Eip4844(tx) => match tx.tx() {
                TxEip4844Variant::TxEip4844(tx) => &tx.access_list,
                TxEip4844Variant::TxEip4844WithSidecar(tx) => &tx.tx().access_list,
            },
            _ => unreachable!(),
        })
    }

    fn _max_fee_per_gas(&self, tx: &TxEnvelope) -> Option<U256> {
        Some(match tx {
            TxEnvelope::Legacy(_) => return None,
            TxEnvelope::Eip2930(_) => return None,
            TxEnvelope::Eip1559(tx) => tx.tx().max_fee_per_gas.to(),
            TxEnvelope::Eip4844(tx) => match tx.tx() {
                TxEip4844Variant::TxEip4844(tx) => tx.max_fee_per_gas.to(),
                TxEip4844Variant::TxEip4844WithSidecar(tx) => tx.tx.max_fee_per_gas.to(),
            },
            _ => unreachable!(),
        })
    }

    fn _max_priority_fee_per_gas(&self, tx: &TxEnvelope) -> Option<U256> {
        Some(match tx {
            TxEnvelope::Legacy(_) => return None,
            TxEnvelope::Eip2930(_) => return None,
            TxEnvelope::Eip1559(tx) => tx.tx().max_priority_fee_per_gas.to(),
            TxEnvelope::Eip4844(tx) => match tx.tx() {
                TxEip4844Variant::TxEip4844(tx) => tx.max_priority_fee_per_gas.to(),
                TxEip4844Variant::TxEip4844WithSidecar(tx) => tx.tx.max_priority_fee_per_gas.to(),
            },
            _ => unreachable!(),
        })
    }

    fn _max_fee_per_blob_gas(&self, tx: &TxEnvelope) -> Option<U256> {
        Some(match tx {
            TxEnvelope::Legacy(_) => return None,
            TxEnvelope::Eip2930(_) => return None,
            TxEnvelope::Eip1559(_) => return None,
            TxEnvelope::Eip4844(tx) => match tx.tx() {
                TxEip4844Variant::TxEip4844(tx) => tx.max_fee_per_blob_gas.to(),
                TxEip4844Variant::TxEip4844WithSidecar(tx) => tx.tx.max_fee_per_blob_gas.to(),
            },
            _ => unreachable!(),
        })
    }

    fn block_env(&self) -> BlockEnv {
        BlockEnv {
            number: self.number().to(),
            coinbase: self.coinbase(),
            timestamp: self.timestamp(),
            gas_limit: self.gas_limit(),
            basefee: self.base_fee_per_gas().unwrap_or_default(),
            difficulty: self.difficulty(),
            prevrandao: self.prevrandao(),
            blob_excess_gas_and_price: None,
        }
    }
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub new_state_root: B256,
}

#[derive(Debug)]
pub struct CommitState {
    pub new_state_root: B256,
}

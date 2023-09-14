use std::prelude::v1::*;

use eth_types::{SH160, SH256, SU256};
use scroll_types::TransactionInner;
use statedb::StateDB;

lazy_static::lazy_static! {
    static ref SLOT_L1_BASE_FEE: SH256 = SU256::from(1).into();
    static ref SLOT_OVERHEAD: SH256 = SU256::from(2).into();
    static ref SLOT_SCALAR: SH256 = SU256::from(3).into();
    static ref GAS_FEE_PRECISION: SU256 = SU256::from(1_000_000_000u64);
    static ref L1_GAS_PRICE_ORACLE_ADDRESS: SH160 = "0x5300000000000000000000000000000000000002".into();
    static ref FEE_VAULT_ADDRESS: SH160 = "0x5300000000000000000000000000000000000005".into();
    static ref L1_MESSAGE_QUEUE: SH160 = "0x5300000000000000000000000000000000000000".into();
    static ref SLOT_WITHDRAW_TRIE_ROOT: SH256 = SU256::from(0).into();
}

pub fn read_withdral_root<S>(state: &mut S) -> Result<SH256, statedb::Error>
where
    S: StateDB,
{
    state.get_state(&L1_MESSAGE_QUEUE, &SLOT_WITHDRAW_TRIE_ROOT)
}

pub fn calculate_l1_data_fee<S>(
    cfg: &evm::Config,
    tx: &TransactionInner,
    state: &mut S,
) -> Result<SU256, statedb::Error>
where
    S: StateDB,
{
    if matches!(tx, TransactionInner::L1Message(_)) {
        return Ok(0.into());
    }
    let raw = tx.to_bytes();
    let l1_fee = read_gpo_storage_slots(&L1_GAS_PRICE_ORACLE_ADDRESS, state)?;
    let data_fee = l1_fee.data_fee(cfg, &raw);
    Ok(data_fee)
}

pub struct L1GasFee {
    pub l1_base_fee: SU256,
    pub overhead: SU256,
    pub scalar: SU256,
}

impl L1GasFee {
    fn zeroes_and_ones(data: &[u8]) -> (u64, u64) {
        let mut zeroes = 0;
        let mut ones = 0;
        for byt in data {
            if *byt == 0 {
                zeroes += 1;
            } else {
                ones += 1;
            }
        }
        return (zeroes, ones);
    }

    pub fn gas_used(&self, cfg: &evm::Config, data: &[u8]) -> SU256 {
        let (zeroes, ones) = Self::zeroes_and_ones(data);
        let zeroes_gas = zeroes * cfg.gas_transaction_zero_data;
        // txExtraDataBytes is the number of bytes that we commit to L1 in addition
        // to the RLP-encoded signed transaction. Note that these are all assumed
        // to be non-zero.
        // - tx length prefix: 4 bytes
        const TX_EXTRA_DATA_BYTES: u64 = 4;
        let ones_gas = (ones + TX_EXTRA_DATA_BYTES) * cfg.gas_transaction_non_zero_data;
        let l1_gas = zeroes_gas + ones_gas;
        SU256::from(l1_gas) + self.overhead
    }

    pub fn data_fee(&self, cfg: &evm::Config, data: &[u8]) -> SU256 {
        let l1_gas_used = self.gas_used(cfg, data);
        let l1_data_fee = l1_gas_used * self.l1_base_fee;
        l1_data_fee * self.scalar / *GAS_FEE_PRECISION
    }
}

fn read_gpo_storage_slots<S>(addr: &SH160, state: &mut S) -> Result<L1GasFee, statedb::Error>
where
    S: StateDB,
{
    let l1_base_fee = state.get_state(addr, &SLOT_L1_BASE_FEE)?;
    let overhead = state.get_state(addr, &SLOT_OVERHEAD)?;
    let scalar = state.get_state(addr, &SLOT_SCALAR)?;
    let fee = L1GasFee {
        l1_base_fee: (&l1_base_fee).into(),
        overhead: (&overhead).into(),
        scalar: (&scalar).into(),
    };
    Ok(fee)
}

// pub fn verify_fee<S: StateDB>(signer: &Signer, tx: &TransactionInner, state: S) -> Result<state>

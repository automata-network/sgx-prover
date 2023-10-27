use std::prelude::v1::*;

use base::format::parse_ether;
use eth_types::{SH256, SU256};
use evm_executor::{calculate_l1_data_fee, ExecuteError, PrecompileSet};
use scroll_types::{BlockHeader, PoolTx, Signer, TransactionInner};
use statedb::StateDB;
use std::sync::Arc;

pub struct Executor<S: StateDB> {
    signer: Signer,
    cfg: evm_executor::Config,
    precompile_set: PrecompileSet,
    header: Arc<BlockHeader>,
    state_db: S,
}

pub fn scroll_evm_config() -> evm_executor::Config {
    let mut cfg = evm_executor::Config::shanghai();
    // SputnikVM doesn't have the option to disable the SELFDESTRUCT,
    // however, we can raise a OutOfGas error to stop the execution
    cfg.gas_suicide = 1_000_000_000;

    cfg.has_base_fee = false;
    cfg
}

impl<S: StateDB> Executor<S> {
    pub fn new(signer: Signer, state_db: S, header: Arc<BlockHeader>) -> Self {
        let precompile_set = PrecompileSet::scroll();
        let cfg = scroll_evm_config();

        Self {
            signer,
            cfg,
            precompile_set,
            header,
            state_db,
        }
    }

    pub fn state_db(&mut self) -> &mut S {
        &mut self.state_db
    }

    fn effective_gas_tip(&self, tx: &TransactionInner) -> Result<SU256, ExecuteError> {
        let base_fee = self.header.base_fee_per_gas.as_ref();
        let zero = SU256::zero();
        match tx.effective_gas_tip(base_fee) {
            Some(n) => Ok(n),
            None => Err(ExecuteError::InsufficientBaseFee {
                tx_hash: tx.hash(),
                block_number: self.header.number.as_u64().into(),
                block_base_fee_gwei: parse_ether(base_fee.unwrap_or(&zero), 9),
                base_fee_gwei: parse_ether(&tx.effective_gas_tip(None).unwrap(), 9),
            }),
        }
    }

    pub fn execute(&mut self, txs: Vec<TransactionInner>) -> Result<SH256, ExecuteError> {
        for (tx_idx, tx) in txs.into_iter().enumerate() {
            self.execute_tx(tx_idx as _, tx)?;
        }
        let new_state = self.state_db.flush()?;
        Ok(new_state)
    }

    fn execute_tx(&mut self, tx_idx: u64, tx: TransactionInner) -> Result<(), ExecuteError> {
        self.effective_gas_tip(&tx)?;
        let caller = tx.sender(&self.signer);
        let l1_fee = if tx.extra_fee() {
            Some(calculate_l1_data_fee(&self.cfg, &tx, &mut self.state_db)?)
        } else {
            None
        };
        let tx = PoolTx::with_tx(&self.signer, tx);

        let exec_ctx = evm_executor::Context {
            chain_id: &self.signer.chain_id,
            caller: &caller,
            cfg: &self.cfg,
            precompile: &self.precompile_set,
            tx: &tx,
            header: &self.header,
            extra_fee: l1_fee,
        };

        let _receipt = evm_executor::Executor::apply(exec_ctx, &mut self.state_db, tx_idx)?;

        // env.use_gas(receipt.gas_used.as_u64());
        Ok(())
    }
}

use std::prelude::v1::*;

use base::format::parse_ether;
use eth_types::{BlockHeader, PoolTx, Signer, TransactionInner, SH256, SU256};
use evm_executor::{ExecuteError, PrecompileSet};
use statedb::StateDB;
use std::sync::Arc;

pub struct Executor<S: StateDB> {
    signer: Signer,
    cfg: evm_executor::Config,
    precompile_set: PrecompileSet,
    header: Arc<BlockHeader>,
    state_db: S,
}

impl<S: StateDB> Executor<S> {
    pub fn new(signer: Signer, state_db: S, header: Arc<BlockHeader>) -> Self {
        let precompile_set = PrecompileSet::berlin();
        let cfg = evm_executor::Config::shanghai();

        Self {
            signer,
            cfg,
            precompile_set,
            header,
            state_db,
        }
    }

    fn effective_gas_tip(&self, tx: &TransactionInner) -> Result<SU256, ExecuteError> {
        match tx.effective_gas_tip(Some(&self.header.base_fee_per_gas)) {
            Some(n) => Ok(n),
            None => Err(ExecuteError::InsufficientBaseFee {
                tx_hash: tx.hash(),
                block_number: self.header.number.as_u64().into(),
                block_base_fee_gwei: parse_ether(&self.header.base_fee_per_gas, 9),
                base_fee_gwei: parse_ether(&tx.effective_gas_tip(None).unwrap(), 9),
            }),
        }
    }

    pub fn execute(&mut self, txs: Vec<TransactionInner>) -> Result<SH256, ExecuteError> {
        let prev_state = self.state_db.state_root();
        for (tx_idx, tx) in txs.into_iter().enumerate() {
            self.execute_tx(tx_idx as _, tx)?;
        }
        self.state_db.flush()?;
        let new_state = self.state_db.state_root();
        glog::info!("state_root: {:?} -> {:?}", prev_state, new_state);
        Ok(new_state)
    }

    fn execute_tx(&mut self, tx_idx: u64, tx: TransactionInner) -> Result<(), ExecuteError> {
        self.effective_gas_tip(&tx)?;
        let caller = tx.sender(&self.signer);
        let tx = PoolTx::with_tx(&self.signer, tx);

        let exec_ctx = evm_executor::Context {
            chain_id: &self.signer.chain_id,
            caller: &caller,
            cfg: &self.cfg,
            precompile: &self.precompile_set,
            tx: &tx,
            header: &self.header,
        };

        let _receipt = evm_executor::Executor::apply(exec_ctx, &mut self.state_db, tx_idx)?;

        // env.use_gas(receipt.gas_used.as_u64());
        Ok(())
    }
}

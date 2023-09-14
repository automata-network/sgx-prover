use std::prelude::v1::*;

use super::{Context, StateProxy};
use base::format::parse_ether;
use eth_types::{HexBytes, Log, Receipt, SH256, SU256, SU64};
use statedb::StateDB;

use std::cmp::Ordering;
use std::time::Instant;

use evm::backend::Apply;
use evm::executor::stack::{MemoryStackState, StackExecutor, StackSubstateMetadata};
use evm::{ExitFatal, ExitReason};

#[derive(Debug)]
pub struct Executor<'a, D: StateDB> {
    ctx: Context<'a>,
    state_db: &'a mut D,
    initial_gas: u64,
    gas: u64,
    gas_price: SU256,
}

impl<'a, D: StateDB> Executor<'a, D> {
    pub fn new(ctx: Context<'a>, state_db: &'a mut D) -> Self {
        let gas_price = ctx.tx.tx.gas_price(ctx.header.base_fee_per_gas);
        Self {
            ctx,
            state_db,
            gas: 0,
            initial_gas: 0,
            gas_price,
        }
    }

    pub fn dry_run(ctx: Context<'a>, state_db: &'a mut D) -> Result<ExecuteResult, ExecuteError> {
        Executor::new(ctx, state_db).run(true)
    }

    pub fn apply(
        ctx: Context<'a>,
        state_db: &'a mut D,
        tx_idx: u64,
    ) -> Result<Receipt, ExecuteError> {
        let mut result = Executor::new(ctx.clone(), state_db).run(false)?;
        for log in &mut result.logs {
            log.transaction_hash = ctx.tx.hash;
        }
        let mut receipt = Receipt {
            status: (result.success as u64).into(),
            transaction_hash: ctx.tx.tx.hash(),
            transaction_index: tx_idx.into(),
            r#type: Some(ctx.tx.tx.ty().into()),
            gas_used: result.used_gas,
            cumulative_gas_used: ctx.header.gas_used + result.used_gas,
            logs: result.logs,
            logs_bloom: HexBytes::new(),
            contract_address: None, // the rlp didn't included;
            root: None,
            block_hash: None,
            block_number: None,
        };

        // contract_address
        receipt.logs_bloom = eth_types::create_bloom([&receipt].into_iter()).to_hex();

        Ok(receipt)
    }

    pub fn run(&mut self, dry_run: bool) -> Result<ExecuteResult, ExecuteError> {
        let precompile_set = self.ctx.precompile;
        let config = self.ctx.cfg;
        let tx = &self.ctx.tx.tx;
        let mut base_fee = self.ctx.header.base_fee_per_gas;
        let gas_fee_cap = tx.max_fee_per_gas();

        if tx.can_check_nonce() {
            self.check_nonce(true, dry_run)?;
        }

        if let Some(fee) = &base_fee {
            if fee > gas_fee_cap {
                if dry_run {
                    // adjust the base_fee so we can run this tx
                    base_fee = Some(SU256::zero());
                } else {
                    return Err(ExecuteError::InsufficientBaseFee {
                        tx_hash: self.ctx.tx.hash,
                        block_base_fee_gwei: parse_ether(fee, 9),
                        base_fee_gwei: parse_ether(&tx.effective_gas_tip(None).unwrap(), 9),
                        block_number: self.ctx.header.number.as_u64(),
                    });
                }
            }
        }

        let mut access_list = vec![];
        if let Some(al) = tx.access_list() {
            access_list.reserve(al.len());
            for tat in al {
                access_list.push((
                    tat.address.raw().clone(),
                    tat.storage_keys.iter().map(|n| n.raw().clone()).collect(),
                ));
            }
        }

        if tx.can_check_nonce() {
            self.check_nonce(false, dry_run)?;
        }
        self.buy_gas(dry_run)?;

        let mut result = ExecuteResult::default();

        let gas_limit = tx.gas().as_u64();
        let metadata = StackSubstateMetadata::new(gas_limit, config);
        let state = StateProxy::new(self.state_db, self.ctx.clone());

        let execute_instant = Instant::now();
        // glog::info!("gas remain: {}", metadata.gasometer().gas());
        let mem_state = MemoryStackState::new(metadata, &state);
        let mut executor = StackExecutor::new_with_precompiles(mem_state, config, precompile_set);

        // check balance > gas_limit * gasPrice first
        let (reason, data) = match tx.to() {
            Some(to) => executor.transact_call(
                self.ctx.caller.clone().into(),
                to.into(),
                tx.value().into(),
                tx.input().into(),
                gas_limit,
                access_list,
            ),
            None => executor.transact_create(
                self.ctx.caller.clone().into(),
                tx.value().into(),
                tx.input().into(),
                gas_limit,
                access_list,
            ),
        };

        if matches!(reason, ExitReason::Fatal(ExitFatal::NotSupported)) {
            self.refund_gas()?;
            return Err(ExecuteError::NotSupported);
        }
        let mut used_gas = executor.used_gas();
        if !tx.cost_gas() {
            used_gas += 5600;
        }

        if !dry_run {
            glog::debug!(
                target: "execute_result",
                "{}({:?}): reason: {:?}(data: {:?}), gas: {}+{}, elapsed: {:?}, du per gas: {:?}",
                if dry_run { "dry_run" } else { "apply" },
                tx.hash().raw(),
                reason, data,
                // HexBytes::from(data).to_utf8(),
                used_gas,
                executor.gas(),
                execute_instant.elapsed(),
                execute_instant.elapsed() / (used_gas as u32),
            );
        }

        result.success = reason.is_succeed();
        result.used_gas = used_gas.into();
        result.err = data.into();
        if self.gas < used_gas && !tx.cost_gas() {
            self.gas = 0; // FIXME, over commit for l1 msg
        } else {
            self.gas -= used_gas;
        }

        let (storages, logs) = executor.into_state().deconstruct();

        let mut log_index = 0;
        for log in logs {
            result.logs.push(Log {
                address: log.address.into(),
                topics: log.topics.iter().map(|t| t.clone().into()).collect(),
                data: log.data.clone().into(),
                block_number: Default::default(),
                transaction_hash: Default::default(),
                transaction_index: Default::default(),
                block_hash: Default::default(),
                log_index: log_index.clone().into(),
                removed: false,
            });
            log_index += 1;
        }

        // glog::info!("storage: {:?}", storages);
        if result.success || dry_run {
            for change in storages {
                match change {
                    Apply::Modify {
                        address,
                        basic,
                        code,
                        storage,
                        reset_storage,
                    } => {
                        let address = address.into();
                        if reset_storage {
                            self.state_db.suicide(&address).unwrap();
                        }

                        self.state_db
                            .set_balance(&address, basic.balance.into())
                            .unwrap();
                        self.state_db
                            .set_nonce(&address, basic.nonce.into())
                            .unwrap();
                        if let Some(code) = code {
                            self.state_db.set_code(&address, code).unwrap();
                        }
                        for (index, value) in storage {
                            self.state_db
                                .set_state(&address, &index.into(), value.into())
                                .unwrap();
                        }
                    }
                    Apply::Delete { address } => {
                        self.state_db.suicide(&address.into()).unwrap();
                        // unreachable!("unsupport tx: {:?}", self.tx.hash());
                    }
                }
            }
        } else {
            // we should advance the nonce
            for change in storages {
                match change {
                    Apply::Modify {
                        address,
                        basic,
                        code: _,
                        storage: _,
                        reset_storage: _,
                    } => {
                        let address = address.into();
                        if &address == self.ctx.caller {
                            self.state_db
                                .set_nonce(&address, basic.nonce.into())
                                .unwrap();
                        }
                        // glog::info!("storage: {:?}", storage);
                    }
                    Apply::Delete { address } => {
                        glog::error!("deletion in reverted tx: {:?}", address);
                    }
                }
            }
        }

        // let gas = self
        //     .state_db
        //     .client()
        //     .call(&self.context.caller.into(), self.tx, &self.parent.number)
        //     .unwrap();
        // glog::info!("gas: {}", gas);
        // glog::info!("================================================================================================");
        // panic!("tx: {:?}", self.tx.hash());
        let gas_tip_cap = tx.max_priority_fee_per_gas();
        let gas_fee_cap = tx.max_fee_per_gas();
        if let Some(base_fee) = &base_fee {
            if base_fee > gas_fee_cap {
                glog::info!(
                    "invalid tx: {:?}, base_fee:{:?}, gas_fee_cap:{:?}",
                    tx,
                    base_fee,
                    gas_fee_cap
                )
            }
        }
        let effective_tip = (*gas_tip_cap).min(*gas_fee_cap - base_fee.unwrap_or(SU256::zero()));
        let miner = if dry_run {
            eth_types::zero_addr()
        } else {
            &self.ctx.header.miner
        };

        let extra_fee = self.ctx.extra_fee.unwrap_or(SU256::zero());
        let fee = SU256::from(result.used_gas) * effective_tip + extra_fee;
        if tx.cost_gas() {
            self.refund_gas()?;
        }

        self.state_db.add_balance(miner, &fee)?;
        Ok(result)
    }

    fn refund_gas(&mut self) -> Result<(), ExecuteError> {
        // Apply refund counter, capped to a refund quotient
        // REMINDER: already calculated in executor.gas_used();
        // let mut refund = self.gas_used() / refund_quotient;
        // if refund > state_refund {
        //     refund = state_refund
        // }
        // self.gas += refund;

        // Return ETH for remaining gas, exchanged at the original rate.
        let remaining = SU256::from(self.gas) * self.gas_price;
        self.state_db.add_balance(self.ctx.caller, &remaining)?;
        // glog::info!("refund gas fee: {}", remaining);

        // Also return remaining gas to the block gas counter so it is
        // available for the next transaction.
        // FIXME: st.gp.AddGas(st.gas)
        Ok(())
    }

    fn buy_gas(&mut self, dry_run: bool) -> Result<(), ExecuteError> {
        let tx = &self.ctx.tx.tx;
        let caller = self.ctx.caller;
        let gas: SU256 = tx.gas().as_u64().into();
        let mut mgval = gas * self.gas_price;
        // let mut balance_check = mgval.clone();
        // if let Some(gas_fee_cap) = self.tx.max_fee_per_gas() {
        let mut balance_check = gas * tx.max_fee_per_gas();
        balance_check = balance_check + tx.value();
        let extra_fee = self.ctx.extra_fee.unwrap_or(SU256::default());
        balance_check += extra_fee;

        // }

        let balance = self.state_db.get_balance(caller)?;

        if balance < balance_check {
            if !dry_run {
                glog::info!(
                    "[{:?}] acc: {:?}, got balance: {}, need balance: {}",
                    tx.hash().raw(),
                    self.ctx.caller,
                    balance,
                    balance_check
                );
                return Err(ExecuteError::InsufficientFunds);
            }

            // so the dry run can continue
            mgval = balance;
        }

        // TODO: sub block gas pool tx.gas();
        self.gas += tx.gas().as_u64();

        self.initial_gas += tx.gas().as_u64();
        // glog::info!("buy gas: {:?} {:?} + {:?}(extra)", caller, mgval, extra_fee);
        if tx.cost_gas() {
            self.state_db.sub_balance(caller, &(extra_fee + mgval))?;
        }
        Ok(())
    }

    fn check_nonce(&mut self, try_get: bool, dry_run: bool) -> Result<(), ExecuteError> {
        let caller = self.ctx.caller;
        let tx_nonce = self.ctx.tx.tx.nonce();
        let nonce = if try_get {
            match self.state_db.try_get_nonce(caller) {
                Some(nonce) => nonce,
                None => return Ok(()),
            }
        } else {
            glog::debug!(target:"invalid_nonce", "check tx[{:?}] nonce", self.ctx.tx.hash);
            self.state_db.get_nonce(caller)?
        };
        match nonce.cmp(&tx_nonce) {
            Ordering::Equal => Ok(()),
            Ordering::Greater => {
                return Err(ExecuteError::NonceTooLow {
                    got: tx_nonce,
                    expect: nonce,
                })
            }
            Ordering::Less => {
                if !dry_run {
                    return Err(ExecuteError::NonceTooHigh {
                        got: tx_nonce,
                        expect: nonce,
                    });
                }
                return Ok(());
            }
        }
    }
}

#[derive(Debug)]
pub enum ExecuteError {
    NotSupported,
    InsufficientFunds,
    InsufficientBaseFee {
        tx_hash: SH256,
        block_base_fee_gwei: String,
        base_fee_gwei: String,
        block_number: u64,
    },
    ExecutePaymentTxFail(String),
    NonceTooLow {
        expect: u64,
        got: u64,
    },
    NonceTooHigh {
        expect: u64,
        got: u64,
    },
    StateError(statedb::Error),
}

impl From<statedb::Error> for ExecuteError {
    fn from(err: statedb::Error) -> Self {
        Self::StateError(err)
    }
}

#[derive(Debug, Default)]
pub struct ExecuteResult {
    pub success: bool,
    pub used_gas: SU64,       // Total used gas but include the refunded gas
    pub err: HexBytes, // Any error encountered during the execution(listed in core/vm/errors.go)
    pub return_data: Vec<u8>, // Returned data from evm(function result or data supplied with revert opcode)
    pub logs: Vec<Log>,
}

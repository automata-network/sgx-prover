use std::prelude::v1::*;

use base::time::Time;
use base::trace::Alive;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use crypto::{secp256k1_gen_keypair, Secp256k1PrivateKey};
use eth_client::ExecutionClient;
use eth_types::{BlockSelector, HexBytes, SH160, SH256, SU256, SU64};
use evm_executor::{read_withdral_root, ExecuteError};
use jsonrpc::{RpcClient, RpcError};
use scroll_types::{Block, BlockTrace, Poe, Signer};
use scroll_types::{Transaction, TransactionInner};
use serde::Deserialize;
use statedb::{NodeDB, StateDB};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::{executor::Executor, new_zktrie_state, Database, Pob, PobData, ProveResult};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    pub l2_chain_id: SU256,
}

pub struct Prover {
    alive: Alive,
    l2_signer: Signer,
    prvkey: Mutex<Secp256k1PrivateKey>,
    l1_el: Arc<ExecutionClient>,
    attested: AtomicBool,
}

impl Prover {
    pub fn new(alive: Alive, cfg: Config, l1_el: Arc<ExecutionClient>) -> Prover {
        let l2_signer = Signer::new(cfg.l2_chain_id);
        let (prvkey, pubkey) = secp256k1_gen_keypair();
        let prover_pubkey: SH160 = pubkey.eth_accountid().into();
        glog::info!("prover pubkey: {:?}", prover_pubkey);
        Self {
            alive,
            l2_signer,
            prvkey: Mutex::new(prvkey),
            l1_el,
            attested: AtomicBool::new(false),
        }
    }

    fn get_prvkey(&self) -> Secp256k1PrivateKey {
        let prvkey = self.prvkey.lock().unwrap();
        prvkey.clone()
    }

    fn update_prvkey(&self, new: Secp256k1PrivateKey) {
        let mut prvkey = self.prvkey.lock().unwrap();
        *prvkey = new;
    }

    pub fn sign_poe(&self, batch_hash: SH256, reports: &[Poe]) -> Option<Poe> {
        Poe::sign(
            &self.l2_signer.chain_id,
            batch_hash,
            reports,
            &self.get_prvkey(),
        )
    }

    pub fn balance(&self, acc: &SH160) -> Result<SU256, RpcError> {
        self.l1_el.balance(acc, BlockSelector::Latest)
    }

    pub fn check_chain_id(&self, chain_id: u64) -> Result<(), String> {
        if self.l2_signer.chain_id.as_u64() != chain_id {
            return Err("chainID mismatch".into());
        }
        Ok(())
    }

    pub fn generate_pob(&self, block_trace: BlockTrace, extra_codes: Vec<HexBytes>) -> Pob {
        let mut header = block_trace.header;
        header.miner = block_trace.coinbase.address;

        let mut mpt_nodes = BTreeMap::new();
        let mut codes = BTreeMap::new();
        for (_, nodes) in block_trace.storage_trace.proofs {
            for node in nodes {
                mpt_nodes.insert(node, ());
            }
        }
        for (_, proofs) in block_trace.storage_trace.storage_proofs {
            for (_, nodes) in proofs {
                for node in nodes {
                    mpt_nodes.insert(node, ());
                }
            }
        }
        for node in block_trace.storage_trace.deletion_proofs {
            mpt_nodes.insert(node, ());
        }
        for exec_result in block_trace.execution_results {
            codes.insert(exec_result.byte_code, ());
        }
        for code in extra_codes.into_iter() {
            codes.insert(code, ());
        }

        for (idx, ts) in block_trace.tx_storage_traces.iter().enumerate() {
            glog::debug!(
                target: "tx_state_root",
                "state_root [{}] {:?} -> {:?}",
                idx,
                ts.root_before,
                ts.root_after
            );
        }

        let transactions = block_trace
            .transactions
            .iter()
            .map(|tx| tx.to_tx())
            .collect();
        let block = Block {
            header,
            transactions,
            withdrawals: None,
        };
        let data = PobData {
            chain_id: block_trace.chain_id,
            prev_state_root: block_trace.storage_trace.root_before,
            block_hashes: BTreeMap::new(),
            mpt_nodes: mpt_nodes.into_keys().collect(),
            codes: codes.into_keys().collect(),
            start_l1_queue_index: block_trace.start_l1_queue_index,
        };

        Pob::new(block, data)
    }

    fn preprocess_txs(
        &self,
        mut start_queue_index: u64,
        txs: Vec<Transaction>,
    ) -> Result<Vec<TransactionInner>, BuildError> {
        let mut allow_l1_msg = true;
        let mut out = Vec::with_capacity(txs.len());
        for tx in txs {
            let tx = match tx.inner() {
                Some(tx) => tx,
                None => return Err(BuildError::InternalError("invalid transaction".into())),
            };
            match &tx {
                TransactionInner::L1Message(msg) => {
                    if !allow_l1_msg {
                        return Err(BuildError::UnexpectedL1Msg);
                    }
                    if msg.queue_index.as_u64() != start_queue_index {
                        return Err(BuildError::UnexpectedL1MsgIndex {
                            want: start_queue_index,
                            got: msg.queue_index.as_u64(),
                        });
                    }
                    start_queue_index += 1;
                }
                _ => {
                    allow_l1_msg = false;
                }
            }

            out.push(tx);
        }

        Ok(out)
    }

    pub fn execute_block(&self, db: &Database, pob: Pob) -> Result<ProveResult, BuildError> {
        let header = Arc::new(pob.block.header);

        let mut db = db.fork();
        for node in &pob.data.mpt_nodes {
            db.resume_node(&node);
        }
        for code in pob.data.codes {
            db.resume_code(&code);
        }
        db.commit();

        let state_db = new_zktrie_state(pob.data.prev_state_root, db);

        assert_eq!(state_db.state_root(), pob.data.prev_state_root);
        let txs = self.preprocess_txs(pob.data.start_l1_queue_index, pob.block.transactions)?;

        let mut executor = Executor::new(self.l2_signer, state_db, header);
        let new_state_root = executor.execute(txs).map_err(BuildError::ExecuteError)?;

        let prove_result = ProveResult {
            new_state_root,
            withdrawal_root: read_withdral_root(executor.state_db())?,
        };

        Ok(prove_result)
    }

    pub fn fetch_codes<C: RpcClient>(
        &self,
        l2: &ExecutionClient<C>,
        block_trace: &BlockTrace,
    ) -> Result<Vec<HexBytes>, RpcError> {
        let mut accs = BTreeMap::new();
        for (acc, _) in &block_trace.storage_trace.proofs {
            let addr: SH160 = acc.as_str().into();
            accs.insert(addr, ());
        }
        let number = block_trace.header.number;
        let acc_keys: Vec<_> = accs.into_keys().collect();
        let codes = l2.get_codes(&acc_keys, (number - SU64::from(1)).into())?;
        Ok(codes)
    }

    pub fn is_attested(&self) -> bool {
        self.attested.load(Ordering::SeqCst)
    }

    pub fn monitor_attested<F>(
        &self,
        relay: &Secp256k1PrivateKey,
        verifier: &verifier::Client,
        f: F,
    ) where
        F: Fn(&Secp256k1PrivateKey) -> Result<Vec<u8>, String>,
    {
        let mut attested_validity_secs;
        let mut last_submit = None;
        let mut submit_cooldown = Duration::from_secs(180);
        let mut staging_key = None;
        while self.alive.is_alive() {
            let prvkey = self.get_prvkey();
            let prvkey = staging_key.as_ref().unwrap_or(&prvkey);

            let prover = prvkey.public().eth_accountid().into();

            let attested_time = match verifier.prover_status(&prover) {
                Ok(status) => status,
                Err(err) => {
                    glog::error!("getting prover status fail: {:?}", err);
                    self.alive.sleep_ms(1000);
                    continue;
                }
            };

            attested_validity_secs = match verifier.attest_validity_seconds() {
                Ok(secs) => secs,
                Err(err) => {
                    glog::error!("getting attest_validity_seconds fail: {:?}", err);
                    self.alive.sleep_ms(1000);
                    continue;
                }
            };
            if attested_validity_secs < submit_cooldown.as_secs() {
                submit_cooldown = Duration::from_secs(attested_validity_secs / 2);
            }

            let now = base::time::now().as_secs();
            let is_attesed = attested_time + attested_validity_secs > now;
            if staging_key.is_none() {
                self.attested.store(is_attesed, Ordering::SeqCst);
            }

            let need_attestation = attested_time + attested_validity_secs / 2 < now;
            if !need_attestation {
                if let Some(staging_key) = staging_key.take() {
                    self.update_prvkey(staging_key);
                    glog::info!(
                        "prover[{:?}] is attested...",
                        staging_key.public().eth_accountid()
                    );
                } else {
                    glog::info!("prover[{:?}] is attested...", prover);
                }
                self.alive
                    .sleep_ms(60.min(attested_validity_secs / 2) * 1000);
                continue;
            }

            let need_attestation = if let Some(last_submit) = &last_submit {
                Time::now() > *last_submit + submit_cooldown
            } else {
                true
            };

            if need_attestation {
                let (new_prover_prvkey, _) = crypto::secp256k1_gen_keypair();
                let new_prover: SH160 = new_prover_prvkey.public().eth_accountid().into();
                glog::info!("getting prover[{:?}] attested...", new_prover);
                let report = match f(&new_prover_prvkey) {
                    Ok(report) => report,
                    Err(err) => {
                        glog::info!("generate report fail: {}", err);
                        self.alive.sleep_ms(1000);
                        continue;
                    }
                };
                if let Err(err) = verifier.submit_attestation_report(relay, &new_prover, &report) {
                    glog::info!("submit attestation report fail: {:?}", err);
                    self.alive.sleep_ms(1000);
                    continue;
                }
                last_submit = Some(Time::now());
                staging_key = Some(new_prover_prvkey);
                glog::info!("attestation report submitted -> {:?}", new_prover);
            } else {
                glog::info!(
                    "waiting attestor to approve[{:?}]",
                    staging_key
                        .as_ref()
                        .unwrap_or(&prvkey)
                        .public()
                        .eth_accountid()
                );
            }
            self.alive.sleep_ms(5000);
        }
    }
}

#[derive(Debug)]
pub enum BuildError {
    NoTx,
    StateError(statedb::Error),
    SendTipsFail(String),
    FeeTooLow,
    InternalError(String),
    ExecuteError(ExecuteError),
    UnexpectedL1Msg,
    UnexpectedL1MsgIndex { got: u64, want: u64 },
}

impl From<statedb::Error> for BuildError {
    fn from(err: statedb::Error) -> Self {
        Self::StateError(err)
    }
}

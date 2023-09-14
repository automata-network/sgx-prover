use std::prelude::v1::*;

use crypto::{secp256k1_gen_keypair, Secp256k1PrivateKey, Secp256k1PublicKey};
use eth_client::ExecutionClient;
use eth_types::{BlockSelector, HexBytes, SH160, SU256};
use evm_executor::{read_withdral_root, ExecuteError};
use jsonrpc::RpcError;
use scroll_types::{Block, BlockTrace, Signer};
use scroll_types::{Transaction, TransactionInner};
use serde::Deserialize;
use statedb::{NodeDB, StateDB};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{executor::Executor, new_zktrie_state, Database, Pob, PobData, ProveResult};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    pub l2_chain_id: SU256,
}

pub struct Prover {
    l2_signer: Signer,
    prvkey: Secp256k1PrivateKey,
    pubkey: Secp256k1PublicKey,
    l1_el: Arc<ExecutionClient>,
}

impl Prover {
    pub fn new(cfg: Config, l1_el: Arc<ExecutionClient>) -> Prover {
        let l2_signer = Signer::new(cfg.l2_chain_id);
        let (prvkey, pubkey) = secp256k1_gen_keypair();
        let prover_pubkey: SH160 = pubkey.eth_accountid().into();
        glog::info!("prover pubkey: {:?}", prover_pubkey);
        Self {
            l2_signer,
            prvkey,
            pubkey,
            l1_el,
        }
    }

    pub fn pubkey(&self) -> Secp256k1PublicKey {
        self.pubkey
    }

    pub fn account(&self) -> SH160 {
        self.pubkey.eth_accountid().into()
    }

    pub fn prvkey(&self) -> &Secp256k1PrivateKey {
        &self.prvkey
    }

    pub fn balance(&self, acc: &SH160) -> Result<SU256, RpcError> {
        self.l1_el.balance(acc, BlockSelector::Latest)
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

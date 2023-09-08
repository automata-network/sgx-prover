use std::prelude::v1::*;

use crypto::{secp256k1_gen_keypair, Secp256k1PrivateKey, Secp256k1PublicKey};
use eth_client::ExecutionClient;
use eth_types::{Block, BlockSelector, Signer, SH160, SH256, SU256, SU64};
use evm_executor::{BlockStateFetcher, TraceBlockStateFetcher};
use jsonrpc::RpcError;
use serde::Deserialize;
use statedb::{TrieMemStore, TrieState, TrieStore};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{executor::Executor, Pob, PobData, ProveResult};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    pub chain_id: SU256,
}

pub struct Prover {
    cfg: Config,
    signer: Signer,
    prvkey: Secp256k1PrivateKey,
    pubkey: Secp256k1PublicKey,
    el: Arc<ExecutionClient>,
}

impl Prover {
    pub fn new(cfg: Config, el: Arc<ExecutionClient>) -> Prover {
        let signer = Signer::new(cfg.chain_id);
        let (prvkey, pubkey) = secp256k1_gen_keypair();
        let prover_pubkey: SH160 = pubkey.eth_accountid().into();
        glog::info!("prover pubkey: {:?}", prover_pubkey);
        Self {
            cfg,
            signer,
            prvkey,
            pubkey,
            el,
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
        self.el.balance(acc, BlockSelector::Latest)
    }

    pub fn generate_pob(
        &self,
        prev_state_root: SH256,
        blks: Vec<Block>,
    ) -> Result<Pob, BuildError> {
        let store = TrieMemStore::new(102400);
        let mut state_root = prev_state_root;
        let first_blk = blks.first().unwrap();
        let state_block_number = first_blk.header.number - SU64::from(1u64);
        let mut fetcher = TraceBlockStateFetcher::new(self.el.clone(), state_block_number.into());

        let mut new_blks = Vec::with_capacity(blks.len());
        for blk in blks {
            fetcher
                .fetcher
                .select_blk((blk.header.number - SU64::from(1u64)).into());
            let header = Arc::new(blk.header.clone());
            let state_db =
                TrieState::new(fetcher.clone(), state_root, header.clone(), store.fork());
            let mut executor = Executor::new(self.signer, state_db, header);
            let mut txs = Vec::with_capacity(blk.transactions.len());
            for tx in &blk.transactions {
                let tx = match tx.clone().inner() {
                    Some(tx) => tx,
                    None => return Err(BuildError::InternalError("invalid transaction".into())),
                };
                txs.push(tx);
            }
            state_root = executor.execute(txs).unwrap();
            new_blks.push(blk);
        }
        let data = PobData {
            chain_id: self.cfg.chain_id.as_u64(),
            prev_state_root,
            withdrawal_root: Default::default(),
            block_hashes: fetcher.block_hashes(),
            mpt_nodes: fetcher.mpt_nodes(),
            codes: fetcher.codes(),
        };

        Ok(Pob {
            blocks: new_blks,
            data,
        })
    }

    pub fn execute_block(
        &self,
        prev_state_root: SH256,
        store: TrieMemStore,
        block_hashes: &BTreeMap<u64, SH256>,
        blk: Block,
    ) -> Result<ProveResult, BuildError> {
        let state_block_number = blk.header.number - SU64::from(1u64);
        let fetcher = BlockStateFetcher::new(self.el.clone(), state_block_number.into());
        for (number, hash) in block_hashes {
            fetcher.add_block_hashes_cache(*number, *hash);
        }

        let header = Arc::new(blk.header);
        let state_db = TrieState::new(
            fetcher.clone(),
            prev_state_root,
            header.clone(),
            store.fork(),
        );

        let mut executor = Executor::new(self.signer, state_db, header);
        let mut txs = Vec::with_capacity(blk.transactions.len());
        for tx in blk.transactions {
            let tx = match tx.inner() {
                Some(tx) => tx,
                None => return Err(BuildError::InternalError("invalid transaction".into())),
            };
            txs.push(tx);
        }
        let new_state = executor.execute(txs).unwrap();
        let prove_result = ProveResult {
            new_state_root: new_state,
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
}

impl From<statedb::Error> for BuildError {
    fn from(err: statedb::Error) -> Self {
        Self::StateError(err)
    }
}

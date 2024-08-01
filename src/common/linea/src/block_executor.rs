use std::prelude::v1::*;

use crate::Linea;
use crate::ZkTrieState;
use base::format::debug;
use base::trace::Slowlog;
use crypto::keccak_hash;
use eth_tools::{ExecutionClient, MixRpcClient, RpcClient, RpcError};
use eth_types::{
    Block, BlockSelector, FetchState, Transaction, TransactionAccessTuple, TransactionInner, SH256,
    SU256, SU64,
};
use evm::ExitSucceed;
use evm_executor::{BlockBuilder, BlockHashGetter, Engine, Pob};
use mpt::{Database, StateCollector};
use statedb::NodeDB;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use zktrie::PrefixDB;
use zktrie::Trace;

#[derive(Clone, Debug)]
pub struct BlockExecutor {
    engine: Linea,
}

pub struct BlockHashCache {
    cache: BTreeMap<u64, SH256>,
}

impl BlockHashCache {
    pub fn new(cache: BTreeMap<u64, SH256>) -> Self {
        Self { cache }
    }
}

impl BlockHashGetter for BlockHashCache {
    fn get_hash(&self, current: u64, target: u64) -> SH256 {
        if target >= current || target < current.saturating_sub(256) {
            return Default::default();
        }
        self.cache.get(&target).cloned().unwrap_or_default()
    }
}

#[derive(Clone)]
pub struct BuilderFetcher<C: RpcClient> {
    client: ExecutionClient<C>,
    cache: Arc<Mutex<BTreeMap<u64, SH256>>>,
}

impl<C: RpcClient> BuilderFetcher<C> {
    pub fn new(client: ExecutionClient<C>) -> Self {
        Self {
            client,
            cache: Default::default(),
        }
    }
}

impl<C: RpcClient> BlockHashGetter for BuilderFetcher<C> {
    fn get_hash(&self, current: u64, target: u64) -> SH256 {
        if target >= current || target < current.saturating_sub(256) {
            return Default::default();
        }
        {
            let cache = self.cache.lock().unwrap();
            if let Some(hash) = cache.get(&target) {
                return *hash;
            }
        }
        match self.client.get_block_header(target.into()) {
            Ok(header) => {
                let hash = header.hash();
                let mut cache = self.cache.lock().unwrap();
                cache.insert(target, hash);
                hash
            }
            Err(_) => Default::default(),
        }
    }
}

impl BlockExecutor {
    pub fn new(chain_id: SU256) -> Self {
        Self {
            engine: Linea::new(chain_id),
        }
    }

    fn fetch_prestate(
        &self,
        chain_id: u64,
        client: &ExecutionClient<Arc<MixRpcClient>>,
        block: BlockSelector,
    ) -> Result<Pob, RpcError> {
        let txs = client.trace_prestate(block)?;
        let mut unique = BTreeMap::new();
        let mut codes = BTreeMap::new();
        for tx in txs {
            if let Some(result) = tx.result {
                for (addr, acc) in result {
                    let code_hash = SH256::from(keccak_hash(&acc.code));
                    codes.entry(code_hash).or_insert(acc.code);
                    let acc_stateset = unique.entry(addr).or_insert_with(|| BTreeSet::new());
                    for key in acc.storage.keys() {
                        acc_stateset.insert(*key);
                    }
                }
            }
        }

        let blk = client.get_block(block)?;

        let mut fetch_reqs = Vec::with_capacity(unique.len());
        for (key, acc) in unique {
            fetch_reqs.push(FetchState {
                access_list: Some(Cow::Owned(TransactionAccessTuple {
                    address: key,
                    storage_keys: acc.into_iter().collect(),
                })),
                code: None,
            });
        }

        let prev_block = (blk.header.number.as_u64() - 1).into();

        let states = client.fetch_states(&fetch_reqs, prev_block, true)?;
        let prev_state_root = if blk.header.number.as_u64() > 0 {
            client.get_block_header(prev_block)?.state_root
        } else {
            SH256::default()
        };
        let block_hashes = BTreeMap::new();
        let pob = Pob::from_proof(chain_id, blk, prev_state_root, block_hashes, codes, states);
        Ok(pob)
    }

    pub fn generate_pob(
        &self,
        client: &ExecutionClient<Arc<MixRpcClient>>,
        block: BlockSelector,
    ) -> Result<Pob, String> {
        let chain_id = self.engine.signer().chain_id;
        let mut pob = {
            let tag = format!("{:?}", block);
            let _trace = Slowlog::new_ms(&tag, 500);
            retry(3, || self.fetch_prestate(chain_id.as_u64(), client, block)).map_err(debug)?
        };

        let mut db = Database::new();
        self.resume_db(&mut pob, &mut db);

        let builder_fetcher = BuilderFetcher::new(client.clone());

        if true {
            // fill reduction node
            let header = pob.block.header.clone();
            let mut fetcher = StateCollector::new(
                client.clone(),
                (pob.block.header.number - SU64::from(1)).into(),
            );
            let statedb = mpt::TrieState::new(fetcher.clone(), pob.data.prev_state_root, db);
            let mut builder = BlockBuilder::new(
                self.engine.clone(),
                statedb,
                builder_fetcher.clone(),
                header,
            )?;
            let txs = self.preprocess_txs(pob.block.transactions.clone())?;
            for tx in txs {
                builder.commit(Arc::new(tx)).map_err(debug)?;
            }
            builder.flush_state().map_err(debug)?;
            for (_, node) in fetcher.take() {
                pob.data.mpt_nodes.push(node);
            }
            {
                let cache = builder_fetcher.cache.lock().unwrap();
                for (block_no, block_hash) in cache.iter() {
                    pob.data.block_hashes.insert(*block_no, *block_hash);
                }
            }
        }
        Ok(pob)
    }

    fn resume_db(&self, pob: &Pob, db: &mut Database) {
        for node in &pob.data.mpt_nodes {
            db.resume_node(node);
        }
        for code in &pob.data.codes {
            db.resume_code(&code);
        }
        db.commit();
    }

    pub fn execute_v2(
        &self,
        db: PrefixDB,
        start_root: SH256,
        block: Block,
    ) -> Result<SH256, String> {
        let statedb = ZkTrieState::new_from_trace(db, start_root);
        let block_hash_cache = BlockHashCache::new(BTreeMap::new());
        let mut builder =
            BlockBuilder::new(self.engine.clone(), statedb, block_hash_cache, block.header)?;
        let txs = self.preprocess_txs(block.transactions)?;

        let mut root_hash = SH256::default();

        root_hash = builder.flush_state().map_err(debug)?;
        Ok(root_hash)
    }

    pub fn execute(&self, db: &Database, pob: Pob) -> Result<Block, String> {
        if pob.data.chain_id != self.engine.signer().chain_id.as_u64() {
            return Err(format!(
                "chain_id mismatch {}!={}",
                pob.data.chain_id,
                self.engine.signer().chain_id
            ));
        }

        let mut db = db.fork();
        self.resume_db(&pob, &mut db);

        let builder_fetcher = BlockHashCache::new(pob.data.block_hashes);

        let number = pob.block.header.number.as_u64();
        let header = pob.block.header;

        let statedb = mpt::TrieState::new((), pob.data.prev_state_root, db);
        let mut builder = BlockBuilder::new(
            self.engine.clone(),
            statedb,
            builder_fetcher,
            header.clone(),
        )?;
        let txs = self.preprocess_txs(pob.block.transactions)?;
        let total = txs.len();
        for (idx, tx) in txs.into_iter().enumerate() {
            let tx = Arc::new(tx);
            let receipt = builder.commit(tx.clone()).unwrap();
            glog::info!(
                "[{}][{}/{}]tx: {:?}, receipt:{}",
                number,
                idx + 1,
                total,
                tx.hash(),
                receipt.status
            );
            // let expect_receipt = client.get_receipt(&tx.hash()).unwrap().unwrap();
            // if let Err(err) = Receipt::compare(&expect_receipt, receipt) {
            //     glog::info!("diff: {}", err);
            // }
        }
        if let Some(withdrawals) = pob.block.withdrawals {
            builder.withdrawal(withdrawals).unwrap();
        }
        let block = builder.finalize().unwrap();
        return Ok(block);
    }

    fn preprocess_txs(&self, txs: Vec<Transaction>) -> Result<Vec<TransactionInner>, String> {
        let mut out = Vec::with_capacity(txs.len());
        let chain_id = self.engine.signer().chain_id.as_u64();
        for mut tx in txs {
            // fix bug in besu
            if tx.r#type.as_u64() > 0 {
                if tx.v.as_u64() > 1 {
                    tx.v = (tx.v.as_u64() - chain_id * 2 - 8 - 27).into();
                }
            }
            let tx = match tx.inner() {
                Some(tx) => tx,
                None => return Err("invalid transaction".into()),
            };
            out.push(tx);
        }

        Ok(out)
    }
}

fn retry<T, E, F>(retry: usize, f: F) -> Result<T, E>
where
    F: Fn() -> Result<T, E>,
{
    let mut error = None;
    for i in 0..retry {
        match f() {
            Ok(n) => return Ok(n),
            Err(err) => {
                error = Some(err);
                base::thread::sleep_ms((i as u64 + 1) * 300);
            }
        }
    }
    return Err(error.unwrap());
}

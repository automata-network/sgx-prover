use std::prelude::v1::*;

use crate::{get_timeout, Args, Collector, Config, DaManager, PublicApi};
use apps::{Getter, OptionGetter, Var, VarMutex};
use base::{format::debug, trace::Alive};
use crypto::Secp256k1PrivateKey;
use eth_client::ExecutionClient;
use eth_types::SH256;
use jsonrpc::{MixRpcClient, RpcServer};
use prometheus::CollectorRegistry;
use prover::{Database, Pob, Prover};
use scroll_types::{BatchChunkBlockTx, BatchChunkBuilder, BatchTask, Poe, TransactionInner};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub static BUILD_TAG: Option<&str> = option_env!("BUILD_TAG");

#[derive(Default)]
pub struct App {
    pub alive: Alive,
    pub args: Var<Args>,
    pub cfg: Var<Config>,

    pub l2_el: Var<ExecutionClient>,
    pub l2_chain_id: Var<L2ChainID>,
    pub l1_el: Var<L1ExecutionClient>,
    pub verifier: Var<verifier::Client>,
    pub prover: Var<Prover>,
    pub srv: VarMutex<RpcServer<PublicApi>>,
    pub pob_da: Var<DaManager<Vec<Pob>>>,
    pub metric_collector: Var<Collector>,
}

impl apps::App for App {
    fn run(&self, env: apps::AppEnv) -> Result<(), String> {
        self.args.set(Args::from_args(env.args));
        #[cfg(feature = "std")]
        assert!(
            self.args.get(self).dummy_attestation_report,
            "must enable --dummy_attestation_report on std mode"
        );

        let cfg = self.cfg.get(self);
        let srv = self.srv.get(self);

        let prover = self.prover.get(self);

        let metadata_handle = base::thread::spawn("metadata".into(), {
            let metadata = self.metric_collector.get(self);
            let labels = [BUILD_TAG.unwrap_or("v0.0.1").into()];
            let alive = self.alive.clone();
            move || {
                while alive.sleep_ms(6000) {
                    metadata
                        .counter_metadata
                        .lock()
                        .unwrap()
                        .inc(labels.clone());
                }
            }
        });

        let handle = base::thread::spawn("jsonrpc-server".into(), {
            move || {
                let mut srv = srv.lock().unwrap();
                srv.run();
            }
        });
        handle.join().unwrap();

        Ok(())
    }

    fn terminate(&self) {
        self.alive.shutdown()
    }
}

impl App {
    pub fn generate_pob(
        alive: &Alive,
        l2: &Arc<ExecutionClient>,
        prover: &Arc<Prover>,
        block_numbers: Vec<u64>,
    ) -> Result<Vec<Pob>, String> {
        let ctx = Arc::new(Mutex::new(Vec::<Pob>::new()));
        let succ_cnt = base::thread::parallel(alive, block_numbers.clone(), 8, {
            let ctx = ctx.clone();
            let prover = prover.clone();
            let l2 = l2.clone();
            move |blk| {
                let now = Instant::now();
                let block_trace = l2.get_block_trace(blk.into()).map_err(debug)?;
                let codes = prover.fetch_codes(&l2, &block_trace).map_err(debug)?;
                let pob = prover.generate_pob(block_trace.clone(), codes);

                let _ = Self::execute_block(&prover, &pob, &pob.data.withdrawal_root)?;
                let mut ctx = ctx.lock().unwrap();
                ctx.push(pob);
                glog::info!("generate pob: {} -> {:?}", blk, now.elapsed());
                Ok(())
            }
        });
        if succ_cnt != block_numbers.len() {
            return Err("partial failed, skip".into());
        }
        let ctx = Arc::try_unwrap(ctx).unwrap();
        let mut ctx = ctx.into_inner().unwrap();
        ctx.sort_by(|a, b| a.block.header.number.cmp(&b.block.header.number));
        Ok(ctx)
    }

    pub fn generate_poe_by_pob(
        alive: &Alive,
        prover: &Arc<Prover>,
        batch: &BatchTask,
        pob_list: Arc<Vec<Pob>>,
        worker: usize,
    ) -> Result<Poe, String> {
        let block_numbers = batch.block_numbers();
        let ctx = Arc::new(Mutex::new(vec![Poe::default(); block_numbers.len()]));

        let mut batch_chunk = BatchChunkBuilder::new(batch.chunks.clone());
        let pob_id_list = pob_list
            .iter()
            .map(|pob| pob.block.header.number)
            .collect::<Vec<_>>();
        for pob in pob_list.as_ref() {
            let mut txs = Vec::new();
            for tx_bytes in &pob.block.transactions {
                let tx = TransactionInner::from_bytes(tx_bytes).map_err(debug)?;
                txs.push(BatchChunkBlockTx::from(&tx));
            }
            batch_chunk.add_block(&pob.block.header, txs)?;
        }
        let succ = base::thread::parallel(
            alive,
            block_numbers.clone().into_iter().enumerate().collect(),
            worker,
            {
                let ctx = ctx.clone();
                let prover = prover.clone();
                move |(idx, blk)| {
                    let pob = pob_list
                        .iter()
                        .find(|n| n.block.header.number.as_u64() == blk)
                        .unwrap();
                    let now = Instant::now();
                    let poe = Self::execute_block(&prover, pob, &pob.data.withdrawal_root)?;
                    let mut ctx = ctx.lock().unwrap();
                    ctx[idx] = poe;
                    glog::info!("generate poe for: {} -> {:?}", blk, now.elapsed());
                    Ok(())
                }
            },
        );
        if succ != block_numbers.len() {
            return Err("partial fail: skip".into());
        }

        let reports = Arc::try_unwrap(ctx).unwrap();
        let reports = reports.into_inner().unwrap();

        let batch_header = batch.build_header(&batch_chunk.chunks).map_err(debug)?;
        let poe = prover
            .merge_poe(batch_header.hash(), &reports)
            .ok_or(format!("fail to gen poe"))?;
        glog::info!("batch: {:?}", batch_header);
        glog::info!("batch_hash: {:?}", batch_header.hash());
        Ok(poe)
    }

    pub fn generate_poe(
        alive: &Alive,
        l2: &Arc<ExecutionClient>,
        prover: &Arc<Prover>,
        task: BatchTask,
    ) -> Result<Poe, String> {
        let mut batch_chunk = BatchChunkBuilder::new(task.chunks.clone());

        glog::info!("generate poe: {:?}", task.chunks);
        let block_numbers = task
            .chunks
            .clone()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let ctx = Arc::new(Mutex::new((
            vec![Poe::default(); block_numbers.len()],
            BTreeMap::new(),
        )));

        let now = Instant::now();
        base::thread::parallel(
            alive,
            block_numbers.clone().into_iter().enumerate().collect(),
            8,
            {
                let ctx = ctx.clone();
                let prover = prover.clone();
                let l2 = l2.clone();
                move |(idx, blk)| {
                    let now = Instant::now();
                    let block_trace = l2.get_block_trace(blk.into()).map_err(debug)?;
                    prover.check_chain_id(block_trace.chain_id)?;
                    let codes = prover.fetch_codes(&l2, &block_trace).map_err(debug)?;
                    let withdrawal_root = block_trace.withdraw_trie_root.unwrap_or_default();
                    let pob = prover.generate_pob(block_trace.clone(), codes);
                    let poe = Self::execute_block(&prover, &pob, &withdrawal_root)?;
                    let mut ctx = ctx.lock().unwrap();
                    ctx.0[idx] = poe;
                    ctx.1.insert(blk, block_trace);
                    glog::info!("executed block: {} -> {:?}", blk, now.elapsed());
                    Ok(())
                }
            },
        );

        {
            let ctx = ctx.lock().unwrap();
            for chunk in &task.chunks {
                for blk in chunk {
                    let block_trace = ctx
                        .1
                        .get(blk)
                        .ok_or_else(|| format!("blockTrace#{} should exists", blk))?;
                    let txs = block_trace
                        .transactions
                        .iter()
                        .map(BatchChunkBlockTx::from)
                        .collect();
                    batch_chunk.add_block(&block_trace.header, txs)?;
                }
            }
        }

        let execute_time = now.elapsed();
        glog::info!(
            "batch#{}: execute_time: {:?}, avg: {:?}",
            task.id(),
            execute_time,
            execute_time / (block_numbers.len() as u32)
        );

        let ctx = ctx.lock().unwrap();
        let reports = &ctx.0;

        let batch_header = task.build_header(&batch_chunk.chunks).map_err(debug)?;

        let poe = prover
            .merge_poe(batch_header.hash(), &reports)
            .ok_or(format!("fail to gen poe"))?;

        Ok(poe)
    }

    pub fn commit_batch(
        alive: &Alive,
        l2: &Arc<ExecutionClient>,
        prover: &Arc<Prover>,
        relay_acc: &Secp256k1PrivateKey,
        verifier: &verifier::Client,
        task: BatchTask,
    ) -> Result<SH256, String> {
        let batch_id = task.id().into();
        let poe = Self::generate_poe(alive, l2, prover, task)?;
        verifier.commit_batch(relay_acc, &batch_id, &poe.encode())
    }

    fn execute_block(
        prover: &Prover,
        pob: &Pob,
        new_withdrawal_trie_root: &SH256,
    ) -> Result<Poe, String> {
        let block_num = pob.block.header.number.as_u64();
        let state_hash = pob.state_hash();
        let prev_state_root = pob.data.prev_state_root;
        let new_state_root = pob.block.header.state_root;
        let db = Database::new(102400);
        let result = prover.execute_block(&db, &pob).map_err(debug)?;
        if new_state_root != result.new_state_root {
            glog::error!(
                "state not match[{}]: local: {:?} -> remote: {:?}",
                block_num,
                result.new_state_root,
                new_state_root,
            );
            return Err("ratelimited, skip".into());
        }
        if new_withdrawal_trie_root != &result.withdrawal_root {
            glog::error!(
                "withdrawal not match[{}]: local: {:?} -> remote: {:?}",
                block_num,
                result.withdrawal_root,
                new_withdrawal_trie_root,
            );
            return Err("ratelimited, skip".into());
        }
        Ok(Poe {
            state_hash,
            prev_state_root,
            new_state_root: result.new_state_root,
            withdrawal_root: result.withdrawal_root,
            ..Default::default()
        })
    }

    pub fn collect_pob_map(
        da: &DaManager<Pob>,
        start: u64,
        end: u64,
        pob_hash: &[SH256],
    ) -> Result<BTreeMap<u64, Arc<Pob>>, String> {
        if end < start {
            return Err(format!("invalid offset, start={}, end={}", start, end));
        }
        if end - start + 1 != pob_hash.len() as u64 {
            return Err(format!(
                "unexpected hash size: want: {}, got: {}",
                end - start + 1,
                pob_hash.len()
            ));
        }

        let mut pob_map = BTreeMap::new();
        for hash in pob_hash {
            match da.get(&hash) {
                Some(pob) => {
                    let blkno = pob.block.header.number.as_u64();
                    if blkno > end || blkno < start {
                        return Err(format!("unrelated pob data={}", blkno));
                    }
                    match pob_map.entry(blkno) {
                        Entry::Occupied(_) => return Err(format!("duplicated pob={}", blkno)),
                        Entry::Vacant(entry) => {
                            entry.insert(pob);
                        }
                    }
                }
                None => return Err(format!("pobhash={:?} not found", hash)),
            }
        }
        Ok(pob_map)
    }
}

impl Getter<Args> for App {
    fn generate(&self) -> Args {
        Args::default()
    }
}

impl Getter<Config> for App {
    fn generate(&self) -> Config {
        let data = base::fs::read_file(&self.args.get(self).cfg).unwrap();
        let cfg: Config = serde_json::from_slice(&data).unwrap();
        cfg
    }
}

impl OptionGetter<verifier::Client> for App {
    fn generate(&self) -> Option<verifier::Client> {
        let cfg = self.cfg.get(self);

        Some(verifier::Client::new(
            &self.alive,
            cfg.verifier.as_ref()?.clone(),
        ))
    }
}

pub struct L1ExecutionClient(ExecutionClient);

impl std::ops::Deref for L1ExecutionClient {
    type Target = ExecutionClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for L1ExecutionClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl OptionGetter<L1ExecutionClient> for App {
    fn generate(&self) -> Option<L1ExecutionClient> {
        let cfg = self.cfg.get(self);
        let scroll_chain = cfg.scroll_chain.as_ref()?;
        let mut mix = MixRpcClient::new(get_timeout(scroll_chain.timeout_secs));
        mix.add_endpoint(&self.alive, &[scroll_chain.endpoint.clone()])
            .unwrap();
        Some(L1ExecutionClient(ExecutionClient::new(mix)))
    }
}

// L2
impl OptionGetter<ExecutionClient> for App {
    fn generate(&self) -> Option<ExecutionClient> {
        let cfg = self.cfg.get(self);
        let scroll_endpoint = match &cfg.scroll_endpoint {
            Some(scroll_endpoint) if scroll_endpoint.is_empty() => return None,
            None => return None,
            Some(scroll_endpoint) => scroll_endpoint,
        };
        let mut mix = MixRpcClient::new(get_timeout(cfg.l2_timeout_secs));
        mix.add_endpoint(&self.alive, &[scroll_endpoint.clone()])
            .unwrap();
        Some(ExecutionClient::new(mix))
    }
}

pub struct L2ChainID(u64);

impl Getter<L2ChainID> for App {
    fn generate(&self) -> L2ChainID {
        let l2 = self.l2_el.option_get(self);
        L2ChainID(match l2.as_ref() {
            Some(l2) => l2.chain_id().unwrap(),
            None => match self.cfg.get(self).scroll_chain_id {
                Some(chain_id) => chain_id,
                None => panic!(
                    "config error: missing both scroll_endpoint and scroll_chain_id, should at least provide one"
                ),
            },
        })
    }
}

impl Getter<Prover> for App {
    fn generate(&self) -> Prover {
        let cfg = self.cfg.get(self);
        let prover_cfg = prover::Config {
            l2_chain_id: self.l2_chain_id.get(self).0.into(),
        };
        let l1_el = match &cfg.verifier {
            Some(verifier) => {
                let mut mix = MixRpcClient::new(get_timeout(verifier.timeout_secs));
                mix.add_endpoint(&self.alive, &[verifier.endpoint.clone()])
                    .unwrap();
                Some(ExecutionClient::new(mix))
            }
            None => None,
        };

        Prover::new(self.alive.clone(), prover_cfg, Arc::new(l1_el))
    }
}

impl Getter<DaManager<Vec<Pob>>> for App {
    fn generate(&self) -> DaManager<Vec<Pob>> {
        DaManager::new()
    }
}

impl Getter<Collector> for App {
    fn generate(&self) -> Collector {
        Collector::new("avs")
    }
}

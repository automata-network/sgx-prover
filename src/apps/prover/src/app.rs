use std::prelude::v1::*;

use crate::{get_timeout, Args, BatchChunkBuilder, BatchCommiter, BatchTask, Config, PublicApi};
use apps::{Getter, Var, VarMutex};
use base::time::Time;
use base::{format::debug, trace::Alive};
use crypto::Secp256k1PrivateKey;
use eth_client::ExecutionClient;
use eth_types::{SH160, SH256};
use jsonrpc::{MixRpcClient, RpcServer};
use prover::{Database, Pob, Prover};
use scroll_types::Poe;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct App {
    pub alive: Alive,
    pub args: Var<Args>,
    pub cfg: Var<Config>,

    pub l2_el: Var<ExecutionClient>,
    pub l1_el: Var<L1ExecutionClient>,
    pub verifier: Var<verifier::Client>,
    pub prover: Var<Prover>,
    pub srv: VarMutex<RpcServer<PublicApi>>,
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
        if let Some(relay) = cfg.relay_account {
            let relay_acc: SH160 = relay.public().eth_accountid().into();
            let relay_balance = prover.balance(&relay_acc).map_err(debug)?;
            glog::info!(
                "prove relay account: {:?}, balance: {}",
                relay_acc,
                relay_balance
            );
        }

        // disable sending commit batch tx (done in the operator)
        // let batch_commiter_thread = base::thread::spawn("BatchCommiter".into(), {
        //     let alive = self.alive.clone();
        //     let cfg = cfg.clone();
        //     let prover = prover.clone();
        //     let verifier = self.verifier.get(self);
        //     let l2 = self.l2_el.get(self);
        //     let insecure = self.args.get(self).insecure;
        //     move || {
        //         let commiter = BatchCommiter::new(&alive, cfg.scroll_chain.clone());
        //         let receiver = commiter.run().unwrap();
        //         for task in alive.recv_iter(&receiver, Duration::from_secs(1)) {
        //             glog::info!("task: {:?}", task);
        //             while !prover.is_attested() && !insecure {
        //                 glog::info!("prover not attested, stall task: {:?}", task.batch_id);
        //                 if !alive.sleep_ms(1000) {
        //                     break;
        //                 }
        //             }

        //             let result = Self::commit_batch(
        //                 &alive,
        //                 &l2,
        //                 &prover,
        //                 &cfg.relay_account,
        //                 &verifier,
        //                 task,
        //             );
        //             glog::info!("submit batch: {:?}", result);
        //         }
        //     }
        // });

        let handle = base::thread::spawn("jsonrpc-server".into(), {
            move || {
                let mut srv = srv.lock().unwrap();
                srv.run();
            }
        });

        // disable automatically sending attestation report for now (done in the operator)
        // if !self.args.get(self).insecure {
        //     let dummy_attestation_report = self.args.get(self).dummy_attestation_report;
        //     let prover_status_monitor = base::thread::spawn("prover-status-monitor".into(), {
        //         let verifier = self.verifier.get(self);
        //         let signer = cfg.relay_account;
        //         let prover = self.prover.get(self);

        //         #[cfg(feature = "tstd")]
        //         let check_report_metadata = self.args.get(self).check_report_metadata;

        //         move || {
        //             prover.monitor_attested(
        //                 &signer,
        //                 &verifier,
        //                 |prvkey| -> Result<Vec<u8>, String> {
        //                     let mut report_data = [0_u8; 64];
        //                     let prover_key = SH160::from(prvkey.public().eth_accountid());
        //                     report_data[44..].copy_from_slice(prover_key.as_bytes());

        //                     if !dummy_attestation_report {
        //                         #[cfg(feature = "tstd")]
        //                         {
        //                             let quote = sgxlib_ra::dcap_generate_quote(report_data)
        //                                 .map_err(debug)?;
        //                             if check_report_metadata {
        //                                 let pass_mrenclave = verifier
        //                                     .verify_mrenclave(quote.get_mr_enclave())
        //                                     .map_err(debug)?;
        //                                 let pass_mrsigner = verifier
        //                                     .verify_mrsigner(quote.get_mr_signer())
        //                                     .map_err(debug)?;
        //                                 if !pass_mrenclave || !pass_mrsigner {
        //                                     glog::info!(
        //                                         "mrenclave: {}, mrsigner: {}",
        //                                         HexBytes::from(&quote.get_mr_enclave()[..]),
        //                                         HexBytes::from(&quote.get_mr_signer()[..])
        //                                     );
        //                                     return Err(format!(
        //                                         "mrenclave[{}] or mr_signer[{}] not trusted",
        //                                         pass_mrenclave, pass_mrsigner
        //                                     ));
        //                                 }
        //                             }
        //                             let data = serde_json::to_vec(&quote).map_err(debug)?;

        //                             verifier
        //                                 .verify_report_on_chain(&prover_key, &data)
        //                                 .map_err(debug)?;
        //                             return Ok(data);
        //                         }
        //                     }

        //                     {
        //                         let mut report = [0_u8; 5 << 10];
        //                         crypto::read_rand(&mut report);
        //                         Ok(report.into())
        //                     }
        //                 },
        //             );
        //         }
        //     });

        //     prover_status_monitor.join().unwrap();
        // }
        handle.join().unwrap();
        // batch_commiter_thread.join().unwrap();

        Ok(())
    }

    fn terminate(&self) {
        self.alive.shutdown()
    }
}

impl App {
    pub fn generate_poe(
        alive: &Alive,
        l2: &Arc<ExecutionClient>,
        prover: &Arc<Prover>,
        task: BatchTask,
    ) -> Result<Poe, String> {
        let mut batch_chunk = BatchChunkBuilder::new(task.chunks.clone());
        let ctx = Arc::new(Mutex::new((Vec::<Poe>::new(), BTreeMap::new())));

        glog::info!("generate poe: {:?}", task.chunks);
        let block_numbers = task
            .chunks
            .clone()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let now = Instant::now();
        base::thread::parallel(alive, block_numbers.clone(), 8, {
            let ctx = ctx.clone();
            let prover = prover.clone();
            let l2 = l2.clone();
            move |blk| {
                let now = Instant::now();
                let block_trace = l2.get_block_trace(blk.into()).map_err(debug)?;
                prover.check_chain_id(block_trace.chain_id)?;
                let codes = prover.fetch_codes(&l2, &block_trace).map_err(debug)?;
                let withdrawal_root = block_trace.withdraw_trie_root.unwrap_or_default();
                let pob = prover.generate_pob(block_trace.clone(), codes);
                let poe = Self::execute_block(&prover, pob, &withdrawal_root)?;
                let mut ctx = ctx.lock().unwrap();
                ctx.0.push(poe);
                ctx.1.insert(blk, block_trace);
                glog::info!("executed block: {} -> {:?}", blk, now.elapsed());
                Ok(())
            }
        });

        {
            let ctx = ctx.lock().unwrap();
            for chunk in &task.chunks {
                for blk in chunk {
                    let block_trace = ctx
                        .1
                        .get(blk)
                        .ok_or_else(|| format!("blockTrace#{} should exists", blk))?;
                    batch_chunk.add_block(block_trace)?;
                }
            }
        }

        // let execute_now = Instant::now();
        // base::thread::parallel(alive, block_numbers.clone(), 8, {
        //     let prover = prover.clone();
        //     let l2 = l2.clone();
        //     let ctx = ctx.clone();
        //     move |blk| {
        //         let block_trace = ctx.lock().unwrap().1.remove(&blk).unwrap();

        //         prover.check_chain_id(block_trace.chain_id)?;
        //         let codes = prover.fetch_codes(&l2, &block_trace).map_err(debug)?;
        //         let withdrawal_root = block_trace.withdraw_trie_root.unwrap_or_default();
        //         let pob = prover.generate_pob(block_trace, codes);
        //         let poe = Self::execute_block(&prover, pob, &withdrawal_root)?;
        //         ctx.lock().unwrap().0.push(poe);
        //         glog::info!("executed block: {}", blk);
        //         Ok(())
        //     }
        // });
        let execute_time = now.elapsed();
        glog::info!(
            "batch#{}: execute_time: {:?}, avg: {:?}",
            task.batch_id,
            execute_time,
            execute_time / (block_numbers.len() as u32)
        );

        let ctx = ctx.lock().unwrap();
        let reports = &ctx.0;

        let batch_header = task.build_header(&batch_chunk.chunks)?;
        if batch_header.hash() != task.batch_hash
            || batch_header.batch_index != task.batch_id.as_u64()
        {
            glog::error!(
                "batch hash mismatch, remote: ({:?}){:?}, local:{:?}({:?})",
                task.batch_id,
                task.batch_hash,
                batch_header.hash(),
                batch_header
            );
            return Err("ratelimited, skip".into());
        }

        let poe = prover
            .sign_poe(task.batch_hash, &reports)
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
        let batch_id = task.batch_id.clone();
        let poe = Self::generate_poe(alive, l2, prover, task)?;
        verifier.commit_batch(relay_acc, &batch_id, &poe.encode())
    }

    fn execute_block(
        prover: &Prover,
        pob: Pob,
        new_withdrawal_trie_root: &SH256,
    ) -> Result<Poe, String> {
        let block_num = pob.block.header.number.as_u64();
        let state_hash = pob.state_hash();
        let prev_state_root = pob.data.prev_state_root;
        let new_state_root = pob.block.header.state_root;
        let db = Database::new(102400);
        let result = prover.execute_block(&db, pob).map_err(debug)?;
        if new_state_root != result.new_state_root {
            glog::error!(
                "state not match[{}]: local: {:?} -> remote: {:?}",
                block_num, result.new_state_root, new_state_root,
            );
            return Err("ratelimited, skip".into());
        }
        if new_withdrawal_trie_root != &result.withdrawal_root {
            glog::error!(
                "withdrawal not match[{}]: local: {:?} -> remote: {:?}",
                block_num, result.withdrawal_root, new_withdrawal_trie_root,
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

impl Getter<verifier::Client> for App {
    fn generate(&self) -> verifier::Client {
        let cfg = self.cfg.get(self);

        verifier::Client::new(&self.alive, cfg.verifier.clone())
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

impl Getter<L1ExecutionClient> for App {
    fn generate(&self) -> L1ExecutionClient {
        let cfg = self.cfg.get(self);
        let mut mix = MixRpcClient::new(get_timeout(cfg.scroll_chain.timeout_secs));
        mix.add_endpoint(&self.alive, &[cfg.scroll_chain.endpoint.clone()])
            .unwrap();
        L1ExecutionClient(ExecutionClient::new(mix))
    }
}

// L2
impl Getter<ExecutionClient> for App {
    fn generate(&self) -> ExecutionClient {
        let cfg = self.cfg.get(self);
        let mut mix = MixRpcClient::new(get_timeout(cfg.l2_timeout_secs));
        mix.add_endpoint(&self.alive, &[cfg.l2.clone()]).unwrap();
        ExecutionClient::new(mix)
    }
}

impl Getter<Prover> for App {
    fn generate(&self) -> Prover {
        let cfg = self.cfg.get(self);
        let l2 = self.l2_el.get(self);
        let prover_cfg = prover::Config {
            l2_chain_id: l2.chain_id().unwrap().into(),
        };
        let mut mix = MixRpcClient::new(get_timeout(cfg.verifier.timeout_secs));
        mix.add_endpoint(&self.alive, &[cfg.verifier.endpoint.clone()])
            .unwrap();
        Prover::new(
            self.alive.clone(),
            prover_cfg,
            Arc::new(ExecutionClient::new(mix)),
        )
    }
}

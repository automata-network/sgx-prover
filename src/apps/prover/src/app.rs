use std::prelude::v1::*;

use crate::{Args, BatchCommiter, BatchTask, Config, ExecutionReport, PublicApi};
use apps::{Getter, Var, VarMutex};
use base::{format::debug, trace::Alive};
use crypto::Secp256k1PrivateKey;
use eth_client::ExecutionClient;
use eth_types::{SH160, SH256};
use jsonrpc::{MixRpcClient, RpcServer};
use prover::{Database, Pob, Prover};
use std::sync::Arc;
use std::time::Duration;

#[derive(Default)]
pub struct App {
    pub alive: Alive,
    pub args: Var<Args>,
    pub cfg: Var<Config>,

    pub l2_el: Var<ExecutionClient>,
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
        {
            let relay_acc: SH160 = cfg.relay_account.public().eth_accountid().into();
            let relay_balance = prover.balance(&relay_acc).map_err(debug)?;
            glog::info!(
                "prove relay account: {:?}, balance: {}",
                relay_acc,
                relay_balance
            );
        }

        let batch_commiter_thread = base::thread::spawn("batch commiter".into(), {
            let alive = self.alive.clone();
            let cfg = cfg.clone();
            let prover = prover.clone();
            let verifier = self.verifier.get(self);
            let l2 = self.l2_el.get(self);
            move || {
                let commiter = BatchCommiter::new(&alive, cfg.scroll_chain.clone());
                let receiver = commiter.run().unwrap();
                for task in alive.recv_iter(&receiver, Duration::from_secs(1)) {
                    glog::info!("task: {:?}", task);
                    while !verifier.is_attested() {
                        glog::info!("prover not attested, stall task: {:?}", task.batch_id);
                        if !alive.sleep_ms(1000) {
                            break;
                        }
                    }

                    let result = Self::commit_batch(
                        &alive,
                        &l2,
                        &prover,
                        &cfg.relay_account,
                        &verifier,
                        task,
                    );
                    glog::info!("submit batch: {:?}", result);
                }
            }
        });

        let handle = base::thread::spawn("jsonrpc-server".into(), {
            move || {
                let mut srv = srv.lock().unwrap();
                srv.run();
            }
        });

        if !self.args.get(self).insecure {
            let dummy_attestation_report = self.args.get(self).dummy_attestation_report;
            let prover_status_monitor = base::thread::spawn("prover-status-monitor".into(), {
                let verifier = self.verifier.get(self);
                let signer = cfg.relay_account;
                let prover_key = *prover.prvkey();
                move || {
                    verifier.monitor_attested(
                        &signer,
                        &prover_key,
                        || -> Result<Vec<u8>, String> {
                            if !dummy_attestation_report {
                                #[cfg(feature = "tstd")]
                                {
                                    let acc = prover.pubkey().to_raw_bytes();
                                    let quote =
                                        sgxlib_ra::dcap_generate_quote(acc).map_err(debug)?;

                                    let data = serde_json::to_vec(&quote).map_err(debug)?;
                                    return Ok(data);
                                }
                            }

                            {
                                let mut report = [0_u8; 5 << 10];
                                crypto::read_rand(&mut report);
                                Ok(report.into())
                            }
                        },
                    );
                }
            });

            prover_status_monitor.join().unwrap();
        }
        handle.join().unwrap();
        batch_commiter_thread.join().unwrap();

        Ok(())
    }

    fn terminate(&self) {
        self.alive.shutdown()
    }
}

impl App {
    pub fn commit_batch(
        alive: &Alive,
        l2: &ExecutionClient,
        prover: &Prover,
        relay_acc: &Secp256k1PrivateKey,
        verifier: &verifier::Client,
        task: BatchTask,
    ) -> Result<SH256, String> {
        let mut reports = Vec::new();
        for chunk in task.chunks {
            for blk in chunk {
                if !alive.is_alive() {
                    return Err("Canceled".into());
                }
                let block_trace = l2.get_block_trace(blk.into()).map_err(debug)?;
                let codes = prover.fetch_codes(&l2, &block_trace).map_err(debug)?;
                let withdrawal_root = block_trace.withdraw_trie_root.unwrap_or_default();
                let pob = prover.generate_pob(block_trace, codes);
                reports.push(Self::execute_block(&prover, pob, &withdrawal_root)?);
                glog::info!("executed block: {}", blk);
            }
        }
        let poe = ExecutionReport::sign(task.batch_hash, &reports, prover.prvkey())
            .ok_or(format!("fail to gen poe"))?;

        verifier.commit_batch(relay_acc, &task.batch_id, &poe.encode())
    }

    fn execute_block(
        prover: &Prover,
        pob: Pob,
        new_withdrawal_trie_root: &SH256,
    ) -> Result<ExecutionReport, String> {
        let block_num = pob.block.header.number.as_u64();
        let state_hash = pob.state_hash();
        let prev_state_root = pob.data.prev_state_root;
        let new_state_root = pob.block.header.state_root;
        let db = Database::new(102400);
        let result = prover.execute_block(&db, pob).map_err(debug)?;
        if new_state_root != result.new_state_root {
            return Err(format!(
                "state not match[{}]: local: {:?} -> remote: {:?}",
                block_num, result.new_state_root, new_state_root,
            ));
        }
        if new_withdrawal_trie_root != &result.withdrawal_root {
            return Err(format!(
                "withdrawal not match[{}]: local: {:?} -> remote: {:?}",
                block_num, result.withdrawal_root, new_withdrawal_trie_root,
            ));
        }
        Ok(ExecutionReport {
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

// L2
impl Getter<ExecutionClient> for App {
    fn generate(&self) -> ExecutionClient {
        let cfg = self.cfg.get(self);
        let mut mix = MixRpcClient::new(None);
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
        let mut mix = MixRpcClient::new(None);
        mix.add_endpoint(&self.alive, &[cfg.verifier.endpoint.clone()])
            .unwrap();
        Prover::new(prover_cfg, Arc::new(ExecutionClient::new(mix)))
    }
}

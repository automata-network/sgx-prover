use std::prelude::v1::*;

use crate::{Args, Config, PublicApi};
use apps::{Getter, Var, VarMutex};
use base::{format::debug, trace::Alive};
use eth_client::ExecutionClient;
use eth_types::SH160;
use jsonrpc::{MixRpcClient, RpcServer};
use prover::Prover;
use std::sync::Arc;

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

                #[cfg(feature = "sgx")]
                let spid = {
                    let mut buf = [0_u8; 16];
                    buf.copy_from_slice(&cfg.spid);
                    buf
                };

                #[cfg(all(feature = "sgx", feature = "epid"))]
                let ias_server = sgxlib_ra::IasServer::new(&cfg.ias_apikey, true, None);

                move || {
                    verifier.monitor_attested(
                        &signer,
                        &prover_key,
                        || -> Result<Vec<u8>, String> {
                            if !dummy_attestation_report {
                                // generate the report
                                #[cfg(feature = "epid")]
                                {
                                    let acc = prover.pubkey().to_raw_bytes();
                                    let report = sgxlib_ra::epid_report(
                                        &ias_server,
                                        acc,
                                        spid,
                                        env.enclave_id,
                                    )
                                    .map_err(debug)?;
                                    return serde_json::to_vec(&report).map_err(debug);
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

        Ok(())
    }

    fn terminate(&self) {
        self.alive.shutdown()
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

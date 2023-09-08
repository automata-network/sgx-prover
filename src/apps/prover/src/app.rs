use std::prelude::v1::*;

use crate::{Args, Config, PublicApi};
use apps::{Getter, Var, VarMutex};
use base::{format::debug, trace::Alive};
use eth_client::ExecutionClient;
use eth_types::{BlockSelector, SH160};
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

            #[cfg(feature = "sgx")]
            let ias_server = sgxlib_ra::IasServer::new(&cfg.ias_apikey, true, None);

            move || {
                verifier.monitor_attested(&signer, &prover_key, || -> Result<Vec<u8>, String> {
                    // generate the report
                    #[cfg(feature = "sgx")]
                    {
                        let acc = prover.pubkey().to_raw_bytes();
                        let report =
                            sgxlib_ra::self_attestation(&ias_server, acc, spid, env.enclave_id)
                                .map_err(debug)?;
                        return serde_json::to_vec(&report).map_err(debug);
                    }

                    #[cfg(not(feature = "sgx"))]
                    {
                        let mut report = [0_u8; 5 << 10];
                        crypto::read_rand(&mut report);
                        Ok(report.into())
                    }
                });
            }
        });

        prover_status_monitor.join().unwrap();
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
        let el = {
            let cfg = self.cfg.get(self);
            let mut mix = MixRpcClient::new(None);
            mix.add_endpoint(&self.alive, &[cfg.verifier.endpoint.clone()])
                .unwrap();
            Arc::new(ExecutionClient::new(mix))
        };
        let chain_id = el.chain_id().unwrap();
        let prover_cfg = prover::Config {
            chain_id: chain_id.into(),
        };
        Prover::new(prover_cfg, el)
    }
}

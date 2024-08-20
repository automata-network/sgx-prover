use base::{time::Time, trace::Alive};
use crypto::{secp256k1_gen_keypair, Secp256k1PrivateKey};
use eth_tools::MixRpcClient;
use eth_types::{EthereumEngineTypes, SH160};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use crate::Verifier;

pub struct Prover {
    alive: Alive,
    prvkey: Mutex<Secp256k1PrivateKey>,
    attested: AtomicBool,
}

impl Prover {
    pub fn new(alive: Alive) -> Prover {
        let (prvkey, pubkey) = secp256k1_gen_keypair();
        let prover_pubkey: SH160 = pubkey.eth_accountid().into();
        glog::info!("prover pubkey: {:?}", prover_pubkey);
        Self {
            alive,
            prvkey: Mutex::new(prvkey),
            attested: AtomicBool::new(false),
        }
    }

    pub fn get_prvkey(&self) -> Secp256k1PrivateKey {
        let prvkey = self.prvkey.lock().unwrap();
        prvkey.clone()
    }

    pub fn wait_attested(&self, alive: &Alive) -> bool {
        if self.is_attested() {
            return true;
        }
        while alive.sleep_ms(100) {
            if self.is_attested() {
                return true;
            }
        }
        false
    }

    pub fn is_attested(&self) -> bool {
        self.attested.load(Ordering::SeqCst)
    }

    fn update_prvkey(&self, new: Secp256k1PrivateKey) {
        let mut prvkey = self.prvkey.lock().unwrap();
        *prvkey = new;
        self.attested.store(true, Ordering::SeqCst);
    }

    pub fn monitor_attested<F>(
        &self,
        relay: &Secp256k1PrivateKey,
        verifier: &Verifier<Arc<MixRpcClient>, EthereumEngineTypes>,
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

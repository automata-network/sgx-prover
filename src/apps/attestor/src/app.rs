use std::prelude::v1::*;

use apps::{Const, Getter, Var};
use base::{
    format::{debug, parse_ether},
    fs::parse_file,
    trace::Alive,
};
use eth_types::{BlockSelector, SH160};

use crate::{Args, Config};

#[derive(Default)]
pub struct App {
    pub alive: Alive,
    pub arg: Const<Args>,
    pub cfg: Var<Config>,
    pub verifier: Var<verifier::Client>,
}

impl apps::App for App {
    fn run(&self, env: apps::AppEnv) -> Result<(), String> {
        self.arg.set(Args::from_args(env.args));
        let cfg = self.cfg.get(self);

        let acc: SH160 = cfg.private_key.public().eth_accountid().into();

        let verifier = self.verifier.get(self);
        if !verifier.is_attestor(&acc).map_err(debug)? {
            return Err(format!("{:?} should be a attestor", acc));
        }
        let balance = verifier.el().balance(&acc, BlockSelector::Latest).unwrap();
        glog::info!(
            "attestor info: addr={:?}, balance={}",
            acc,
            parse_ether(&balance, 18)
        );

        verifier
            .subscribe_attestation_request(None, &cfg.private_key)
            .unwrap();
        Ok(())
    }

    fn terminate(&self) {
        self.alive.shutdown()
    }
}

impl Getter<Config> for App {
    fn generate(&self) -> Config {
        parse_file(&self.arg.get().cfg).unwrap()
    }
}

impl Getter<verifier::Client> for App {
    fn generate(&self) -> verifier::Client {
        let cfg = self.cfg.get(self);

        verifier::Client::new(&self.alive, cfg.verifier.clone())
    }
}

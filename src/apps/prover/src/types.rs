use std::prelude::v1::*;

use apps::getargs::{Opt, Options};
use crypto::Secp256k1PrivateKey;
use eth_types::{SH160, SH256};
use prover::Pob;
use scroll_types::Poe;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub verifier: verifier::Config,
    pub scroll_chain: ScrollChain,
    pub server: ServerConfig,
    pub l2: String,

    pub relay_account: Secp256k1PrivateKey,
}

impl Config {}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScrollChain {
    pub contract: SH160,
    pub endpoint: String,
    pub wait_block: u64,
    pub max_block: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProveResult {
    pub report: Poe,
    pub tx_hash: SH256,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ServerConfig {
    pub tls: String,
    pub body_limit: usize,
    pub workers: usize,
}

#[derive(Debug)]
pub struct Args {
    pub executable: String,
    pub port: u32,
    pub cfg: String,
    // skip the attestation
    pub insecure: bool,
    pub dummy_attestation_report: bool,
    pub check_report_metadata: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            executable: "".into(),
            port: 18232,
            insecure: false,
            dummy_attestation_report: false,
            check_report_metadata: true,
            cfg: "config/prover.json".into(),
        }
    }
}

impl Args {
    pub fn from_args(mut args: Vec<String>) -> Self {
        let mut out = Args::default();
        out.executable = args.remove(0);
        let mut opts = Options::new(args.iter().map(|a| a.as_str()));
        while let Some(opt) = opts.next_opt().expect("argument parsing error") {
            match opt {
                Opt::Short('p') => {
                    out.port = opts.value().unwrap().parse().unwrap();
                }
                Opt::Short('c') => {
                    out.cfg = opts.value().unwrap().parse().unwrap();
                }
                Opt::Long("insecure") => out.insecure = true,
                Opt::Long("dummy_attestation_report") => out.dummy_attestation_report = true,
                Opt::Long("disable_check_report_metadata") => out.check_report_metadata = false,
                opt => {
                    glog::warn!("unknown opt: {:?}", opt);
                    continue
                },
            }
        }
        out
    }
}

#[derive(Debug, Deserialize)]
pub struct ProveParams {
    pub pob: Pob,
    pub withdrawal_root: SH256,
    pub new_state_root: SH256,
}

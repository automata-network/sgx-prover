use std::prelude::v1::*;

use apps::getargs::{Opt, Options};
use crypto::{Secp256k1PrivateKey, Secp256k1RecoverableSignature};
use eth_types::{HexBytes, SH160, SH256};
use prover::Pob;
use serde::{Deserialize, Serialize};
use solidity::EncodeArg;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub verifier: verifier::Config,
    pub server: ServerConfig,
    pub l2: String,

    pub relay_account: Secp256k1PrivateKey,
}

impl Config {}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProveResult {
    pub report: ExecutionReport,
    pub tx_hash: SH256,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecutionReport {
    pub block_hash: SH256,
    pub state_hash: SH256,
    pub prev_state_root: SH256,
    pub new_state_root: SH256,
    pub withdrawal_root: SH256,
    pub signature: HexBytes, // 65bytes
}

impl ExecutionReport {
    pub fn sign(
        reports: &[ExecutionReport],
        prvkey: &Secp256k1PrivateKey,
    ) -> Option<ExecutionReport> {
        if reports.len() < 1 {
            return None;
        }

        let block_hash = crypto::keccak_encode(|hash| {
            for report in reports {
                hash(&report.block_hash.0);
            }
        })
        .into();
        let state_hash = crypto::keccak_encode(|hash| {
            for report in reports {
                hash(&report.state_hash.0);
            }
        })
        .into();
        let prev_state_root = reports.first().unwrap().prev_state_root;
        let new_state_root = reports.last().unwrap().new_state_root;
        let withdrawal_root = reports.last().unwrap().withdrawal_root;
        let mut report = Self {
            block_hash,
            state_hash,
            prev_state_root,
            new_state_root,
            withdrawal_root,
            signature: vec![0_u8; 65].into(),
        };
        let data = report.encode();
        let sig = prvkey.sign(&data);
        report.signature = sig.to_array().to_vec().into();
        Some(report)
    }
}

impl Default for ExecutionReport {
    fn default() -> Self {
        Self {
            block_hash: SH256::default(),
            state_hash: SH256::default(),
            prev_state_root: SH256::default(),
            new_state_root: SH256::default(),
            withdrawal_root: SH256::default(),
            signature: vec![0_u8; 65].into(),
        }
    }
}

impl ExecutionReport {
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = solidity::Encoder::new("");
        encoder.add(&self.block_hash);
        encoder.add(&self.state_hash);
        encoder.add(&self.prev_state_root);
        encoder.add(&self.new_state_root);
        encoder.add(&self.withdrawal_root);
        encoder.add(self.signature.as_bytes());
        encoder.encode()
    }

    pub fn recover(&self) -> SH160 {
        let mut tmp = self.clone();
        tmp.signature = vec![0_u8; 65].into();
        let data = tmp.encode();
        let mut sig = [0_u8; 65];
        sig.copy_from_slice(&self.signature);
        let sig = Secp256k1RecoverableSignature::new(sig);
        crypto::secp256k1_recover_pubkey(&sig, &data)
            .eth_accountid()
            .into()
    }
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
}

impl Default for Args {
    fn default() -> Self {
        Self {
            executable: "".into(),
            port: 18232,
            insecure: false,
            dummy_attestation_report: false,
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
                _ => continue,
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

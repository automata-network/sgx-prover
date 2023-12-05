use std::prelude::v1::*;

use apps::getargs::{Opt, Options};
use crypto::Secp256k1PrivateKey;
use serde::Deserialize;

#[derive(Debug)]
pub struct Args {
    pub executable: String,
    pub port: u32,
    pub cfg: String,
    pub insecure: bool,
    pub check_report_metadata: bool,
    pub start: Option<u64>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            executable: "".into(),
            port: 19001,
            insecure: false,
            cfg: "".into(),
            check_report_metadata: true,
            start: None,
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
                Opt::Long("insecure") => {
                    out.insecure = true;
                }
                Opt::Long("start") => {
                    out.start = Some(opts.value().unwrap().parse().unwrap());
                }
                Opt::Long("disable_check_report_metadata") => {
                    out.check_report_metadata = false;
                }
                opt => {
                    glog::warn!("unknown opt: {:?}", opt);
                    continue;
                }
            }
        }
        out
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub verifier: verifier::Config,
    pub private_key: Secp256k1PrivateKey,
}

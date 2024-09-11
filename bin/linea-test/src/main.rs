#![feature(fs_try_exists)]

use std::path::PathBuf;

use clap::Parser;
use clients::Eth;
use linea_verifier::{block_trace_to_pob, BlockTrace, LineaBatchVerifier, PobContext};
use prover_types::SuccinctPobList;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value = "http://127.0.0.1:8888", env = "SHOMEI")]
    shomei: String,
    #[clap(long, default_value = "2.2.1-dev-0285d7e0")]
    shomei_version: String,
    #[clap(long, default_value = "http://127.0.0.1:8545", env = "BESU")]
    besu: String,

    #[clap(default_value = "0")]
    block: u64,
}

#[tokio::main]
async fn main() {
    base::init_log();

    let opt = Opt::parse();
    let mut eth = None;
    let block_number = if opt.block > 0 {
        opt.block
    } else {
        eth = Some(Eth::dial(&opt.besu, None).unwrap());
        eth.as_ref()
            .unwrap()
            .provider()
            .get_block_number()
            .await
            .unwrap()
    };

    log::info!("block_number: {}", block_number);

    let block_trace = fetch_or_gen_block_trace(&opt, &mut eth, block_number).await;
    let pob = block_trace_to_pob(block_trace.clone()).unwrap();
    let spob = SuccinctPobList::compress(&[pob.clone()]);
    log::info!("context size: {}", serde_json::to_vec(&spob).unwrap().len());
    
    let ctx = PobContext::new(pob).unwrap();
    // let ctx = BlockTraceContext::new(block_trace);
    let poe = LineaBatchVerifier::verify(vec![ctx]).await.unwrap();
    log::info!("{:?}", poe);
}

async fn fetch_or_gen_block_trace(
    opt: &Opt,
    eth: &mut Option<Eth>,
    block_number: u64,
) -> BlockTrace {
    let dir = PathBuf::new().join("testdata").join("downloaded");
    let _ = std::fs::create_dir(&dir);

    let cfg = linea_shomei::ShomeiConfig {
        endpoint: opt.shomei.clone(),
        version: opt.shomei_version.clone(),
    };
    let client = linea_shomei::Client::new(cfg).unwrap();
    if eth.is_none() {
        *eth = Some(Eth::dial(&opt.besu, None).unwrap());
    }
    let eth = eth.as_ref().unwrap();

    let fp = dir.join(format!("linea-mainnet-{}.json", block_number));
    match std::fs::try_exists(&fp).unwrap() {
        true => serde_json::from_slice::<BlockTrace>(&std::fs::read(&fp).unwrap()).unwrap(),
        false => {
            let block_trace = BlockTrace::build(&eth, &client, block_number)
                .await
                .unwrap();
            std::fs::write(fp, serde_json::to_vec_pretty(&block_trace).unwrap()).unwrap();
            block_trace
        }
    }
}

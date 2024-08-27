use std::path::PathBuf;

use clap::Parser;
use scroll_executor::BlockTrace;
use scroll_verifier::{
    block_trace_to_pob, BatchTask, Finalize, HardforkConfig, PobContext, ScrollBatchVerifier,
};

#[derive(Debug, Parser)]
struct Opt {
    tx: PathBuf,
}

fn read_batch_task(path: &PathBuf) -> BatchTask {
    assert!(
        path.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("commit"),
        "should use commit tx"
    );
    let commit_tx_calldata = std::fs::read(&path).unwrap();
    let commit_tx_calldata = hex::decode(&commit_tx_calldata[2..]).unwrap();
    let batch = BatchTask::from_calldata(&commit_tx_calldata[4..]).unwrap();
    batch
}

fn read_finalize(path: &PathBuf) -> Finalize {
    let file_name = path.file_name().unwrap().to_str().unwrap();
    let file_name = file_name.replace("commit", "finalize");
    let path = path.parent().unwrap().join(file_name);
    let calldata = std::fs::read(&path).unwrap();
    let calldata = hex::decode(&calldata[2..]).unwrap();
    Finalize::from_calldata(&calldata[4..]).unwrap()
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let opt = Opt::parse();
    let batch = read_batch_task(&opt.tx);
    let finalize = read_finalize(&opt.tx);

    let dir = opt
        .tx
        .parent()
        .unwrap()
        .join("downloaded")
        .join(opt.tx.file_stem().unwrap().to_str().unwrap());

    log::info!("reading blocktraces...");
    let chunks = batch
        .chunks
        .iter()
        .map(|chunk| {
            chunk.iter().map(|blk| {
                let block_trace: BlockTrace = serde_json::from_slice(
                    &std::fs::read(dir.join(format!("{}.blocktrace", blk))).unwrap(),
                )
                .unwrap();
                PobContext::new(block_trace_to_pob(block_trace).unwrap())
            })
        })
        .flatten()
        .collect::<Vec<_>>();

    let first_block = chunks.first().unwrap();

    let fork = HardforkConfig::default_from_chain_id(first_block.pob.data.chain_id);

    log::info!("build batch header...");
    let mut builder = batch.builder(fork).unwrap();
    for blk in &chunks {
        builder.add(blk).unwrap();
    }
    let new_batch = builder.build(batch.parent_batch_header.clone()).unwrap();
    assert_eq!(new_batch, finalize.batch);

    log::info!("executing blocks...");
    let poe = ScrollBatchVerifier::verify(&batch, chunks).await.unwrap();
    finalize.assert_poe(&poe);

    log::info!("done");
}

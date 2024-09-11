#![feature(fs_try_exists)]

use std::path::PathBuf;

use clap::Parser;
use scroll_executor::BlockTrace;
use scroll_verifier::{
    block_trace_to_pob, BatchTask, Finalize, HardforkConfig, PobContext, ScrollBatchVerifier, ScrollExecutionNode,
};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, default_value = "")]
    download_from: String,
    txs: Vec<PathBuf>,
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

    for tx in &opt.txs {
        let file_stem = tx.file_stem().unwrap().to_str().unwrap();
        if !file_stem.contains("-commit-") {
            continue;
        }

        log::info!("executing {}...", tx.display());

        let batch = read_batch_task(tx);
        let finalize = read_finalize(tx);

        let dir = tx.parent().unwrap().join("downloaded").join(file_stem);

        std::fs::create_dir_all(&dir).unwrap();

        if !opt.download_from.is_empty() {
            log::info!("downloading from {}...", opt.download_from);
            let client = ScrollExecutionNode::dial(&opt.download_from).unwrap();

            let block_numbers = batch
                .chunks
                .clone()
                .into_iter()
                .map(|n| n)
                .flatten()
                .collect::<Vec<_>>();

            let total = block_numbers.len();
            let start = *block_numbers.first().unwrap();
            let alive = base::Alive::new();

            base::parallel(
                &alive,
                (start, client, dir.clone(), total),
                block_numbers,
                4,
                |block, (start, client, dir, total)| async move {
                    let idx = block - start;
                    let output = dir.join(format!("{}.blocktrace", block));
                    let is_exist = std::fs::try_exists(&output).unwrap();
                    if is_exist {
                        return Ok::<(), ()>(());
                    }

                    println!("[{}/{}] downloading block #{}", idx, total, block);
                    let block_trace = client.trace_block(block).await.unwrap();
                    let data = serde_json::to_vec(&block_trace).unwrap();
                    std::fs::write(output, data).unwrap();
                    Ok(())
                },
            )
            .await
            .unwrap();
        }

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
        let new_batch = batch.build_batch(fork, &chunks).unwrap();

        log::info!("executing blocks...");
        let poe = ScrollBatchVerifier::verify(&batch, chunks).await.unwrap();
        finalize.assert_poe(&poe);

        assert_eq!(new_batch, finalize.batch);
        log::info!("done");
    }
}

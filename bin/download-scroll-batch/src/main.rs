#![feature(fs_try_exists)]

use std::path::PathBuf;

use base::Alive;
use clap::Parser;
use scroll_verifier::BatchTask;
// use scroll_executor::Bytes;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long)]
    scroll: String,
    #[clap(long)]
    tx: PathBuf,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let opt = Opt::parse();
    let commit_tx_calldata = std::fs::read(&opt.tx).unwrap();
    let commit_tx_calldata = hex::decode(&commit_tx_calldata[2..]).unwrap();
    let batch = BatchTask::from_calldata(&commit_tx_calldata[4..]).unwrap();
    let client = clients::Eth::dial(&opt.scroll);

    let dir = opt
        .tx
        .parent()
        .unwrap()
        .join("downloaded")
        .join(opt.tx.file_stem().unwrap().to_str().unwrap());
    std::fs::create_dir_all(&dir).unwrap();

    let block_numbers = batch
        .chunks
        .into_iter()
        .map(|n| n)
        .flatten()
        .collect::<Vec<_>>();

    let total = block_numbers.len();
    let start = *block_numbers.first().unwrap();
    let alive = Alive::new();

    base::parallel(
        &alive,
        (start, client, dir, total),
        block_numbers,
        4,
        |block, (start, client, dir, total)| async move {
            let idx = block - start;
            println!("[{}/{}] downloading block #{}", idx, total, block);
            let output = dir.join(format!("{}.blocktrace", block));
            let is_exist = std::fs::try_exists(&output).unwrap();
            if is_exist {
                return Ok::<(), ()>(());
            }
            let block_trace = client.trace_block(block).await;
            let data = serde_json::to_vec(&block_trace).unwrap();
            std::fs::write(output, data).unwrap();
            Ok(())
        },
    )
    .await
    .unwrap();
}

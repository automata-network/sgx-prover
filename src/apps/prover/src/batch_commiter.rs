use std::prelude::v1::*;

use base::{format::debug, trace::Alive};
use eth_client::LogFilter;
use eth_client::{ExecutionClient, LogTrace};
use eth_types::{SH256, SU256};
use jsonrpc::MixRpcClient;
use scroll_types::{decode_block_numbers, BatchHeader};
use std::sync::{mpsc, Arc};

use crate::ScrollChain;

#[derive(Debug, Clone)]
pub struct BatchTask {
    pub batch_id: SU256,
    pub batch_hash: SH256,
    pub chunks: Vec<Vec<u64>>,
    pub parent_batch_header: BatchHeader,
}

#[derive(Debug, Clone)]
pub struct BatchCommiter {
    alive: Alive,
    cfg: ScrollChain,
}

impl BatchCommiter {
    pub fn new(alive: &Alive, cfg: ScrollChain) -> Self {
        Self {
            alive: alive.clone(),
            cfg,
        }
    }

    pub fn run(&self) -> Result<mpsc::Receiver<BatchTask>, String> {
        let (sender, receiver) = mpsc::channel();
        let start = 0;
        base::thread::spawn("batch monitor".into(), {
            let alive = self.alive.clone();
            let cfg = self.cfg.clone();
            let mut client = MixRpcClient::new(None);
            client
                .add_endpoint(&alive, &[cfg.endpoint.clone()])
                .map_err(debug)?;
            move || {
                let client = ExecutionClient::new(Arc::new(client));
                let log_trace =
                    LogTrace::new(alive.clone(), client.clone(), cfg.max_block, cfg.wait_block);
                let topic = solidity::encode_eventsig("CommitBatch(uint256,bytes32)");
                let filter = LogFilter {
                    address: vec![cfg.contract],
                    topics: vec![vec![topic]],
                    ..Default::default()
                };
                log_trace.subscribe("BatchCommiter", start, filter, |logs| {
                    'nextLog: for log in logs {
                        let batch_id = SU256::from_big_endian(log.topics[1].as_bytes());
                        let batch_hash = log.topics[2];
                        let mut outs = Vec::new();
                        let tx = client
                            .get_transaction(&log.transaction_hash)
                            .map_err(debug)?;
                        let parent_batch_header_bytes = solidity::parse_bytes(32, &tx.input[4..]);
                        let chunks_bytes = solidity::parse_array_bytes(64, &tx.input[4..]);
                        let parent_batch_header =
                            BatchHeader::from_bytes(&parent_batch_header_bytes);
                        for chunk_byte in chunks_bytes {
                            match decode_block_numbers(&chunk_byte) {
                                Some(blks) => outs.push(blks),
                                None => continue 'nextLog,
                            }
                        }
                        let _ = sender.send(BatchTask {
                            batch_id,
                            batch_hash,
                            chunks: outs,
                            parent_batch_header,
                        });
                    }
                    Ok(())
                }).unwrap();
            }
        });
        Ok(receiver)
    }
}

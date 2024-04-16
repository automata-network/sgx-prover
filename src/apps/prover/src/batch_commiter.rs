use core::time::Duration;
use std::prelude::v1::*;

use base::thread;
use base::{format::debug, trace::Alive};
use crypto::keccak_hash;
use eth_client::LogFilter;
use eth_client::{ExecutionClient, LogTrace};
use eth_types::{HexBytes, SH256, SU256};
use jsonrpc::MixRpcClient;
use scroll_types::{decode_block_numbers, BatchHeader, BlockTrace, Poe, TraceTx};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::{mpsc, Arc, Mutex};

use crate::ScrollChain;

pub struct TaskManager {
    tasks: Mutex<(BTreeMap<BatchTask, TaskContext>, Vec<BatchTask>)>,
    cap: usize,
}

impl TaskManager {
    pub fn new(cap: usize) -> TaskManager {
        Self {
            tasks: Mutex::new((BTreeMap::new(), Vec::new())),
            cap,
        }
    }

    fn add_task(&self, task: BatchTask) -> Option<TaskContext> {
        let mut tasks = self.tasks.lock().unwrap();
        let result = match tasks.0.entry(task.clone()) {
            Entry::Occupied(entry) => Some(entry.get().clone()),
            Entry::Vacant(entry) => {
                entry.insert(TaskContext { result: None });
                tasks.1.push(task);
                None
            }
        };
        while tasks.1.len() > self.cap {
            let task = tasks.1.remove(0);
            tasks.0.remove(&task);
        }
        result
    }

    pub fn process_task(&self, task: BatchTask) -> Option<Result<Poe, String>> {
        let alive = Alive::new();
        let alive = alive.fork_with_timeout(Duration::from_secs(120));
        
        while alive.is_alive() {
            match self.add_task(task.clone()) {
                Some(tc) => match tc.result {
                    Some(poe) => return Some(poe),
                    None => {
                        glog::info!("polling task result: {:?}", task);
                        alive.sleep_ms(5000);
                        continue;
                    }
                },
                None => return None,
            }
        }
        None
    }

    pub fn update_task(&self, task: BatchTask, poe: Result<Poe, String>) -> bool {
        let mut tasks = self.tasks.lock().unwrap();
        match tasks.0.entry(task) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().result = Some(poe);
                true
            }
            Entry::Vacant(entry) => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TaskContext {
    pub result: Option<Result<Poe, String>>,
}

pub struct BatchChunkBuilder {
    numbers: Vec<Vec<u64>>,
    pub chunks: Vec<BatchChunk>,
    current_chunk_id: usize,
    current_block_id: usize,
}

impl BatchChunkBuilder {
    pub fn new(numbers: Vec<Vec<u64>>) -> Self {
        Self {
            chunks: Vec::with_capacity(numbers.len()),
            numbers,
            current_chunk_id: 0,
            current_block_id: 0,
        }
    }

    pub fn chunks(self) -> Vec<BatchChunk> {
        self.chunks
    }

    pub fn add_block(&mut self, block: &BlockTrace) -> Result<(), String> {
        for (chunk_id, chunk) in self.numbers.iter().enumerate() {
            for (block_id, blkno) in chunk.iter().enumerate() {
                if blkno == &block.header.number.as_u64() {
                    let mut expect_chunk_id = self.current_chunk_id;
                    let mut expect_block_id = self.current_block_id;
                    if expect_block_id == self.numbers[self.current_chunk_id].len() {
                        expect_chunk_id += 1;
                        expect_block_id = 0;
                    }
                    if expect_block_id != block_id || expect_chunk_id != chunk_id {
                        return Err("unexpected block".into());
                    }
                    if block_id == 0 {
                        self.chunks.push(BatchChunk { blocks: Vec::new() });
                    }
                    let chunk = self.chunks.get_mut(chunk_id).unwrap();
                    let txs = block
                        .transactions
                        .iter()
                        .map(BatchChunkBlockTx::from)
                        .collect();
                    chunk.blocks.push(BatchChunkBlock {
                        number: block.header.number.as_u64(),
                        timestamp: block.header.timestamp.as_u64(),
                        gas_limit: block.header.gas_limit.as_u64(),
                        hash: block.header.hash(),
                        txs,
                    });

                    self.current_chunk_id = chunk_id;
                    self.current_block_id = block_id + 1;
                    return Ok(());
                }
            }
        }
        return Err("unknown block".into());
    }
}

#[derive(Clone, Debug)]
pub struct BatchChunk {
    blocks: Vec<BatchChunkBlock>,
}

impl BatchChunk {
    pub fn encode(&self, mut total_l1_msg_poped_before: u64) -> Result<Vec<u8>, String> {
        let num_blocks = self.blocks.len();
        if num_blocks > 255 {
            return Err("number of blocks exceeds 1 byte".into());
        }
        if num_blocks == 0 {
            return Err("number of blocks is 0".into());
        }

        let mut chunk_bytes = vec![num_blocks as u8];
        let mut l2_tx_data_bytes = vec![];
        for block in &self.blocks {
            let block_bytes = block.encode(total_l1_msg_poped_before)?;
            total_l1_msg_poped_before += block.num_l1_msg(total_l1_msg_poped_before);
            if block_bytes.len() != 60 {
                return Err(format!(
                    "block encoding is not 60 bytes long: {:?}",
                    HexBytes::from(block_bytes)
                ));
            }
            chunk_bytes.extend_from_slice(&block_bytes);
            for tx in &block.txs {
                if tx.l1_msg {
                    continue;
                }
                let rlp_tx_data = &tx.encode;
                l2_tx_data_bytes.extend_from_slice(&(rlp_tx_data.len() as u32).to_be_bytes());
                l2_tx_data_bytes.extend(rlp_tx_data);
            }
        }

        chunk_bytes.extend_from_slice(&l2_tx_data_bytes);
        Ok(chunk_bytes)
    }

    pub fn hash(&self, total_l1_msg_poped_before: u64) -> Result<SH256, String> {
        let chunk_bytes = self.encode(total_l1_msg_poped_before)?;
        let num_blocks = chunk_bytes[0] as usize;
        let mut data_bytes = vec![];
        for i in 0..num_blocks {
            let start = 1 + 60 * i;
            let end = 60 * i + 59;
            data_bytes.extend_from_slice(&chunk_bytes[start..end]);
        }

        for block in &self.blocks {
            let mut l1_tx_hashes = vec![];
            let mut l2_tx_hashes = vec![];
            for tx in &block.txs {
                if tx.l1_msg {
                    l1_tx_hashes.extend_from_slice(tx.tx_hash.as_bytes());
                } else {
                    l2_tx_hashes.extend_from_slice(tx.tx_hash.as_bytes());
                }
            }
            data_bytes.extend_from_slice(&l1_tx_hashes);
            data_bytes.extend_from_slice(&l2_tx_hashes);
        }

        let hash = keccak_hash(&data_bytes);
        Ok(hash.into())
    }
}

#[derive(Clone, Debug)]
pub struct BatchChunkBlock {
    number: u64,
    timestamp: u64,
    gas_limit: u64,
    hash: SH256,
    txs: Vec<BatchChunkBlockTx>,
}

impl BatchChunkBlock {
    pub fn num_l1_msg(&self, total_l1_msg_poped_before: u64) -> u64 {
        let mut last_queue_index = None;
        for tx in &self.txs {
            if tx.l1_msg {
                last_queue_index = Some(tx.nonce);
            }
        }
        match last_queue_index {
            Some(last_queue_index) => last_queue_index - total_l1_msg_poped_before + 1,
            None => 0,
        }
    }

    pub fn num_l2_txs(&self) -> u64 {
        let mut count = 0;
        for tx in &self.txs {
            if !tx.l1_msg {
                count += 1;
            }
        }
        return count;
    }

    pub fn encode(&self, total_l1_msg_poped_before: u64) -> Result<Vec<u8>, &'static str> {
        let mut bytes = Vec::with_capacity(60);
        let num_l1_messages = self.num_l1_msg(total_l1_msg_poped_before);
        if num_l1_messages > u16::max_value() as _ {
            return Err("number of l1 messages exceeds max uint16");
        }

        let num_l2_transactions = self.num_l2_txs();
        let num_transactions = num_l1_messages + num_l2_transactions;
        if num_transactions > u16::max_value() as _ {
            return Err("number of transaction exceeds max uint16");
        }
        bytes.extend_from_slice(&self.number.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&[0_u8; 32]); // base fee
        bytes.extend_from_slice(&self.gas_limit.to_be_bytes());
        bytes.extend_from_slice(&(num_transactions as u16).to_be_bytes());
        bytes.extend_from_slice(&(num_l1_messages as u16).to_be_bytes());
        Ok(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct BatchChunkBlockTx {
    l1_msg: bool,
    nonce: u64,
    tx_hash: SH256,
    encode: Vec<u8>,
}

impl From<&TraceTx> for BatchChunkBlockTx {
    fn from(tx: &TraceTx) -> Self {
        Self {
            l1_msg: tx.is_l1_msg(),
            nonce: tx.nonce,
            tx_hash: tx.tx_hash,
            encode: tx.to_rlp_encoding(),
        }
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct BatchTask {
    pub batch_id: SU256,
    pub batch_hash: SH256,
    pub chunks: Vec<Vec<u64>>,
    pub parent_batch_header: BatchHeader,
}

impl BatchTask {
    pub fn from_calldata(
        batch_id: SU256,
        batch_hash: SH256,
        data: &[u8],
    ) -> Result<BatchTask, String> {
        let parent_batch_header_bytes = solidity::parse_bytes(32, data);
        let chunks_bytes = solidity::parse_array_bytes(64, data);
        let parent_batch_header = BatchHeader::from_bytes(&parent_batch_header_bytes);
        let mut outs = Vec::new();
        for chunk_byte in chunks_bytes {
            match decode_block_numbers(&chunk_byte) {
                Some(blks) => outs.push(blks),
                None => return Err("invalid data".into()),
            }
        }
        Ok(BatchTask {
            batch_id,
            batch_hash,
            chunks: outs,
            parent_batch_header,
        })
    }

    pub fn build_header(&self, chunks: &[BatchChunk]) -> Result<BatchHeader, String> {
        let total_l1_message_popped = self.parent_batch_header.total_l1_message_popped;
        let base_index = total_l1_message_popped;
        let mut next_index = total_l1_message_popped;
        let mut skipped_bitmap = vec![];
        let mut data_bytes = vec![];
        for (chunk_id, chunk) in chunks.iter().enumerate() {
            let total_l1_message_popped_before_chunk = next_index;
            let chunk_hash = chunk.hash(total_l1_message_popped_before_chunk)?;
            data_bytes.extend_from_slice(chunk_hash.as_bytes());
            for (block_id, block) in chunk.blocks.iter().enumerate() {
                for tx in &block.txs {
                    if !tx.l1_msg {
                        continue;
                    }
                    let current_index = tx.nonce;
                    if current_index < next_index {
                        return Err(format!("unexpected batch payload, expected queue index: {}, got: {}. Batch index: {}, chunk index in batch: {}, block index in chunk: {}, block hash: {}, transaction hash: {}", next_index, current_index, self.batch_id, chunk_id, block_id, block.hash, tx.tx_hash));
                    }

                    for skipped_index in next_index..current_index {
                        let quo = ((skipped_index - base_index) / 256) as usize;
                        let rem = ((skipped_index - base_index) % 256) as usize;
                        while skipped_bitmap.len() <= quo {
                            let bitmap = SU256::zero();
                            skipped_bitmap.push(bitmap);
                        }
                        set_bit(&mut skipped_bitmap[quo], rem);
                    }

                    let quo = ((current_index - base_index) / 256) as usize;
                    while skipped_bitmap.len() <= quo {
                        skipped_bitmap.push(SU256::default());
                    }
                    next_index = current_index + 1;
                }
            }
        }

        let data_hash = keccak_hash(&data_bytes).into();

        let mut bitmap_bytes = vec![0_u8; skipped_bitmap.len() * 32];
        for (ii, num) in skipped_bitmap.into_iter().enumerate() {
            num.to_big_endian(&mut bitmap_bytes[32 * ii..])
        }
        Ok(BatchHeader {
            version: self.parent_batch_header.version,
            batch_index: self.batch_id.as_u64(),
            l1_message_popped: next_index - total_l1_message_popped,
            total_l1_message_popped: next_index,
            data_hash,
            parent_batch_hash: self.parent_batch_header.hash(),
            skipped_l1_message_bitmap: bitmap_bytes,
        })
    }
}

fn set_bit(val: &mut SU256, i: usize) {
    let j = i / 4;
    let m = 1u64 << (i % 8);
    val.0[j] |= m;
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
            let mut client = MixRpcClient::new(Some(Duration::from_secs(60)));
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
                log_trace
                    .subscribe("BatchCommiter", start, filter, |logs| {
                        'nextLog: for log in logs {
                            let batch_id = SU256::from_big_endian(log.topics[1].as_bytes());
                            let batch_hash = log.topics[2];
                            let tx = client
                                .get_transaction(&log.transaction_hash)
                                .map_err(debug)?;
                            let task = match BatchTask::from_calldata(
                                batch_id,
                                batch_hash,
                                &tx.input[4..],
                            ) {
                                Ok(task) => task,
                                Err(_) => continue 'nextLog,
                            };
                            let _ = sender.send(task);
                        }
                        Ok(())
                    })
                    .unwrap();
            }
        });
        Ok(receiver)
    }
}

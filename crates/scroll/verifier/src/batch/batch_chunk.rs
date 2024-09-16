use scroll_executor::{revm::primitives::keccak256, B256, U256};

use super::BatchError;

#[derive(Clone, Debug)]
pub struct BatchChunk {
    pub blocks: Vec<BatchChunkBlock>,
}

impl BatchChunk {
    pub fn encode(&self, mut total_l1_msg_poped_before: u64) -> Result<Vec<u8>, BatchError> {
        let num_blocks = self.blocks.len();
        if num_blocks > 255 || num_blocks == 0 {
            return Err(BatchError::InvalidNumBlock(num_blocks));
        }

        let mut chunk_bytes = vec![num_blocks as u8];
        let mut l2_tx_data_bytes = vec![];
        for block in &self.blocks {
            let block_bytes = block.encode(total_l1_msg_poped_before)?;
            total_l1_msg_poped_before += block.num_l1_msg(total_l1_msg_poped_before);
            if block_bytes.len() != 60 {
                return Err(BatchError::InvalidBlockBytes(block_bytes.into()));
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

    pub fn hash(&self, version: u8, total_l1_msg_poped_before: u64) -> Result<B256, BatchError> {
        let chunk_bytes = self
            .encode(total_l1_msg_poped_before)
            .map_err(BatchError::EncodeBatchChunk())?;
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
                    l1_tx_hashes.extend_from_slice(tx.tx_hash.as_slice());
                } else {
                    if version == 0 {
                        l2_tx_hashes.extend_from_slice(tx.tx_hash.as_slice());
                    }
                }
            }
            data_bytes.extend_from_slice(&l1_tx_hashes);
            if version == 0 {
                data_bytes.extend_from_slice(&l2_tx_hashes);
            }
        }

        Ok(keccak256(&data_bytes))
    }
}

#[derive(Clone, Debug)]
pub struct BatchChunkBlock {
    pub number: u64,
    pub timestamp: u64,
    pub base_fee: Option<U256>,
    pub gas_limit: u64,
    pub hash: B256,
    pub txs: Vec<BatchChunkBlockTx>,
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

    pub fn encode(&self, total_l1_msg_poped_before: u64) -> Result<Vec<u8>, BatchError> {
        let mut bytes = Vec::with_capacity(60);
        let num_l1_messages = self.num_l1_msg(total_l1_msg_poped_before);
        if num_l1_messages > u16::max_value() as _ {
            return Err(BatchError::NumL1TxTooLarge);
        }

        let num_l2_transactions = self.num_l2_txs();
        let num_transactions = num_l1_messages + num_l2_transactions;
        if num_transactions > u16::max_value() as _ {
            return Err(BatchError::NumTxTooLarge);
        }
        bytes.extend_from_slice(&self.number.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        let mut base_fee_bytes = [0_u8; 32];
        if let Some(base_fee) = self.base_fee {
            base_fee_bytes = base_fee.to_be_bytes();
        }
        bytes.extend_from_slice(&base_fee_bytes);
        bytes.extend_from_slice(&self.gas_limit.to_be_bytes());
        bytes.extend_from_slice(&(num_transactions as u16).to_be_bytes());
        bytes.extend_from_slice(&(num_l1_messages as u16).to_be_bytes());
        Ok(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct BatchChunkBlockTx {
    pub l1_msg: bool,
    pub nonce: u64,
    pub tx_hash: B256,
    pub encode: Vec<u8>,
}

pub struct BatchChunkBuilder {
    pub numbers: Vec<Vec<u64>>,
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

    pub fn add_block(&mut self, block: BatchChunkBlock) -> Result<(), String> {
        for (chunk_id, chunk) in self.numbers.iter().enumerate() {
            for (block_id, blkno) in chunk.iter().enumerate() {
                if blkno == &block.number {
                    let mut expect_chunk_id = self.current_chunk_id;
                    let mut expect_block_id = self.current_block_id;
                    if expect_block_id == self.numbers[self.current_chunk_id].len() {
                        expect_chunk_id += 1;
                        expect_block_id = 0;
                    }
                    if expect_block_id != block_id || expect_chunk_id != chunk_id {
                        return Err(format!(
                            "unexpected block, want=[{}.{}], got=[{}.{}]",
                            expect_block_id, expect_chunk_id, block_id, chunk_id
                        ));
                    }
                    if block_id == 0 {
                        self.chunks.push(BatchChunk { blocks: Vec::new() });
                    }
                    let chunk = self.chunks.get_mut(chunk_id).unwrap();
                    chunk.blocks.push(block);

                    self.current_chunk_id = chunk_id;
                    self.current_block_id = block_id + 1;
                    return Ok(());
                }
            }
        }
        return Err("unknown block".into());
    }
}

use super::prelude::*;

pub const VERSION: u8 = 0;

pub struct CodecV0 {}
impl BatchVersionedType for CodecV0 {
    type Batch = DABatch;
    type Chunk = DAChunk;
    type Block = DABlock;
    type Tx = DABlockTx;
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DABlockTx {
    pub l1_msg: bool,
    pub nonce: u64,
    pub tx_hash: B256,
    pub rlp: Vec<u8>,
}

impl TxTrait for DABlockTx {
    fn new(tx: &Transaction, rlp: Vec<u8>) -> Self {
        Self {
            l1_msg: tx.transaction_type.map(|n| n.as_u64()) == Some(0x7E),
            nonce: tx.nonce.as_u64(),
            tx_hash: tx.hash().0.into(),
            rlp,
        }
    }

    fn is_l1_msg(&self) -> bool {
        self.l1_msg
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn hash(&self) -> B256 {
        self.tx_hash
    }

    fn rlp_bytes(&self) -> &[u8] {
        &self.rlp
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DABlock {
    pub number: u64,
    pub timestamp: u64,
    pub base_fee: Option<U256>,
    pub gas_limit: u64,
    pub hash: B256,
    pub txs: Vec<DABlockTx>,
}

impl BlockTrait for DABlock {
    type Tx = DABlockTx;
    fn new<C: scroll_executor::Context>(ctx: &C, txs: Vec<Self::Tx>) -> Self {
        DABlock {
            number: ctx.number(),
            timestamp: ctx.timestamp().to(),
            base_fee: ctx.base_fee_per_gas().map(|n| n.to()),
            gas_limit: ctx.gas_limit().to(),
            hash: ctx.block_hash(),
            txs,
        }
    }

    fn timestamp(&self) -> u64 {
        self.timestamp
    }

    fn number(&self) -> u64 {
        self.number
    }
    fn txs(&self) -> &[Self::Tx] {
        &self.txs
    }

    fn num_l1_messages(&self, total_l1_message_popped_before: u64) -> u64 {
        let mut last_queue_index = None;
        for tx_data in &self.txs {
            if tx_data.is_l1_msg() {
                last_queue_index = Some(tx_data.nonce());
            }
        }
        match last_queue_index {
            // note: last queue index included before this block is total_l1_message_popped_before - 1
            Some(last_queue_index) => last_queue_index - total_l1_message_popped_before + 1,
            None => 0,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, BatchError> {
        let mut bytes = Vec::with_capacity(60);

        let num_l1_messages = self.txs.iter().filter(|n| n.is_l1_msg()).count() as u16;

        bytes.extend_from_slice(&self.number.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        let mut base_fee_bytes = [0_u8; 32];
        if let Some(base_fee) = self.base_fee {
            base_fee_bytes = base_fee.to_be_bytes();
        }
        bytes.extend_from_slice(&base_fee_bytes);
        bytes.extend_from_slice(&self.gas_limit.to_be_bytes());
        bytes.extend_from_slice(&(self.txs.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&num_l1_messages.to_be_bytes());
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DAChunk {
    pub blocks: Vec<DABlock>,
}

impl DAChunk {
    fn encode(&self, mut total_l1_msg_poped_before: u64) -> Result<Vec<u8>, BatchError> {
        let num_blocks = self.blocks.len();
        if num_blocks > 255 || num_blocks == 0 {
            return Err(BatchError::InvalidNumBlock(num_blocks));
        }

        let mut chunk_bytes = vec![num_blocks as u8];
        let mut l2_tx_data_bytes = vec![];
        for block in &self.blocks {
            let block_bytes = block.encode()?;
            total_l1_msg_poped_before += block.num_l1_messages(total_l1_msg_poped_before);
            if block_bytes.len() != 60 {
                return Err(BatchError::InvalidBlockBytes(block_bytes.into()));
            }
            chunk_bytes.extend_from_slice(&block_bytes);

            for tx in &block.txs {
                if tx.l1_msg {
                    continue;
                }
                let rlp_tx_data = &tx.rlp;
                l2_tx_data_bytes.extend_from_slice(&(rlp_tx_data.len() as u32).to_be_bytes());
                l2_tx_data_bytes.extend(rlp_tx_data);
            }
        }

        chunk_bytes.extend_from_slice(&l2_tx_data_bytes);
        Ok(chunk_bytes)
    }
}

impl ChunkTrait for DAChunk {
    type Block = DABlock;
    fn add_block(&mut self, blk: Self::Block) {
        self.blocks.push(blk);
    }

    fn blocks(&self) -> &[Self::Block] {
        &self.blocks
    }

    fn hash(&self, total_l1_msg_poped_before: u64) -> Result<B256, BatchError> {
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
                    l2_tx_hashes.extend_from_slice(tx.tx_hash.as_slice());
                }
            }
            data_bytes.extend_from_slice(&l1_tx_hashes);
            data_bytes.extend_from_slice(&l2_tx_hashes);
        }

        Ok(keccak256(&data_bytes))
    }

    fn num_l1_messages(&self, mut total_l1_message_popped_before: u64) -> u64 {
        let mut num_l1_messages = 0_u64;
        for block in &self.blocks {
            let num_l1_messages_in_block = block.num_l1_messages(total_l1_message_popped_before);
            num_l1_messages += num_l1_messages_in_block;
            total_l1_message_popped_before += num_l1_messages_in_block;
        }
        return num_l1_messages;
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DABatch {
    pub version: u8,
    pub batch_index: u64,
    pub l1_message_popped: u64,
    pub total_l1_message_popped: u64,
    pub data_hash: B256,
    pub parent_batch_hash: B256,
    pub skipped_l1_message_bitmap: Vec<u8>,
}

impl BatchTrait for DABatch {
    fn new<B: BatchTrait, C: ChunkTrait>(parent: B, chunks: Vec<C>) -> Result<Self, BatchError> {
        let mut data_bytes = Vec::with_capacity(chunks.len() * 32);
        let batch_index = parent.batch_index() + 1;
        let mut total_l1_message_popped_before_chunk = parent.total_l1_message_popped();

        // skipped L1 messages bitmap
        let (bitmap_bytes, total_l1_message_popped_after) =
            construct_skipped_bitmap(batch_index, &chunks, total_l1_message_popped_before_chunk)?;

        for chunk in chunks {
            // build data hash
            let da_chunk_hash = chunk
                .hash(total_l1_message_popped_before_chunk)
                .map_err(BatchError::BuildChunkHash())?;
            total_l1_message_popped_before_chunk +=
                chunk.num_l1_messages(total_l1_message_popped_before_chunk);
            data_bytes.extend_from_slice(da_chunk_hash.as_slice());
        }

        // compute data hash
        let data_hash = keccak256(&data_bytes);
        Ok(Self {
            version: VERSION,
            batch_index,
            l1_message_popped: total_l1_message_popped_after - parent.total_l1_message_popped(),
            total_l1_message_popped: total_l1_message_popped_after,
            data_hash,
            parent_batch_hash: parent.hash(),
            skipped_l1_message_bitmap: bitmap_bytes,
        })
    }

    fn batch_index(&self) -> u64 {
        self.batch_index
    }

    fn total_l1_message_popped(&self) -> u64 {
        self.total_l1_message_popped
    }

    fn parent_batch_hash(&self) -> B256 {
        self.parent_batch_hash
    }

    fn encode(&self) -> Vec<u8> {
        let mut batch_bytes = Vec::with_capacity(89 + self.skipped_l1_message_bitmap.len());
        batch_bytes.push(self.version);
        batch_bytes.extend_from_slice(&self.batch_index.to_be_bytes());
        batch_bytes.extend_from_slice(&self.l1_message_popped.to_be_bytes());
        batch_bytes.extend_from_slice(&self.total_l1_message_popped.to_be_bytes());
        batch_bytes.extend_from_slice(self.data_hash.as_slice());
        batch_bytes.extend_from_slice(self.parent_batch_hash.as_slice());
        batch_bytes.extend_from_slice(&self.skipped_l1_message_bitmap);
        batch_bytes
    }

    fn from_bytes(data: &[u8]) -> Result<Self, BatchError> {
        if data.len() < 89 {
            return Err(BatchError::InvalidDABatchData {
                version: VERSION,
                want_at_least: 89,
                got: data.len(),
            });
        }

        Ok(Self {
            version: data[0],
            batch_index: u64_be(&data[1..9]),
            l1_message_popped: u64_be(&data[9..17]),
            total_l1_message_popped: u64_be(&data[17..25]),
            data_hash: to_hash(&data[25..57]),
            parent_batch_hash: to_hash(&data[57..89]),
            skipped_l1_message_bitmap: data[89..].to_vec(),
        })
    }
}

impl DABatch {
    pub fn hash(&self) -> B256 {
        keccak256(&self.encode())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_v0_da_batch() {
        test_dabatch::<DABatch>(testdata!("scroll-mainnet-v0", 27589)).unwrap();
    }
}

use super::prelude::*;

use super::v0;

// diffs from v0:
//  * DAChunk.hash: removed l2 txs
//  * added blob_versioned_hash (89..121)

const MAX_NUM_CHUNKS: usize = 15;
pub const VERSION: u8 = 1;
pub type DABlock = v0::DABlock;
pub type DABlockTx = v0::DABlockTx;

pub struct CodecV1 {}
impl BatchVersionedType for CodecV1 {
    type Batch = DABatch;
    type Chunk = DAChunk;
    type Block = DABlock;
    type Tx = DABlockTx;
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DABatch {
    pub version: u8,
    pub batch_index: u64,
    pub l1_message_popped: u64,
    pub total_l1_message_popped: u64,
    pub data_hash: B256,
    pub blob_versioned_hash: B256,
    pub parent_batch_hash: B256,
    pub skipped_l1_message_bitmap: Vec<u8>,
}

impl BatchTrait for DABatch {
    fn new<B: BatchTrait, C: ChunkTrait>(parent: B, chunks: Vec<C>) -> Result<Self, BatchError> {
        check_chunks_size(&chunks, MAX_NUM_CHUNKS)?;

        let data_hash = compute_batch_data_hash(&chunks, parent.total_l1_message_popped())?;

        let batch_index = parent.batch_index() + 1;

        // skipped L1 messages bitmap
        let (bitmap_bytes, total_l1_message_popped_after) =
            construct_skipped_bitmap(batch_index, &chunks, parent.total_l1_message_popped())?;

        // blob payload
        let BlobPayload {
            blob_versioned_hash,
            ..
        } = BlobPayload::build(&chunks, MAX_NUM_CHUNKS, BlobPayloadCompress::None)?;

        Ok(Self {
            version: VERSION,
            batch_index,
            l1_message_popped: total_l1_message_popped_after - parent.total_l1_message_popped(),
            total_l1_message_popped: total_l1_message_popped_after,
            data_hash,
            blob_versioned_hash,
            parent_batch_hash: parent.hash(),
            skipped_l1_message_bitmap: bitmap_bytes,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut batch_bytes = Vec::with_capacity(121 + self.skipped_l1_message_bitmap.len());
        batch_bytes.push(self.version);
        batch_bytes.extend_from_slice(&self.batch_index.to_be_bytes());
        batch_bytes.extend_from_slice(&self.l1_message_popped.to_be_bytes());
        batch_bytes.extend_from_slice(&self.total_l1_message_popped.to_be_bytes());
        batch_bytes.extend_from_slice(self.data_hash.as_slice());
        batch_bytes.extend_from_slice(self.blob_versioned_hash.as_slice());
        batch_bytes.extend_from_slice(self.parent_batch_hash.as_slice());
        batch_bytes.extend_from_slice(&self.skipped_l1_message_bitmap);
        batch_bytes
    }

    fn from_bytes(data: &[u8]) -> Result<Self, BatchError> {
        if data.len() < 121 {
            return Err(BatchError::InvalidDABatchData {
                version: VERSION,
                want_at_least: 121,
                got: data.len(),
            });
        }
        Ok(Self {
            version: data[0],
            batch_index: u64_be(&data[1..9]),
            l1_message_popped: u64_be(&data[9..17]),
            total_l1_message_popped: u64_be(&data[17..25]),
            data_hash: to_hash(&data[25..57]),
            blob_versioned_hash: to_hash(&data[57..89]),
            parent_batch_hash: to_hash(&data[89..121]),
            skipped_l1_message_bitmap: data[121..].to_vec(),
        })
    }

    fn total_l1_message_popped(&self) -> u64 {
        self.total_l1_message_popped
    }

    fn parent_batch_hash(&self) -> B256 {
        self.parent_batch_hash
    }

    fn batch_index(&self) -> u64 {
        self.batch_index
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DAChunk {
    pub blocks: Vec<DABlock>,
}

impl ChunkTrait for DAChunk {
    type Block = DABlock;
    fn add_block(&mut self, blk: Self::Block) {
        self.blocks.push(blk);
    }

    fn blocks(&self) -> &[Self::Block] {
        &self.blocks
    }

    fn hash(&self, _total_l1_msg_poped_before: u64) -> Result<B256, BatchError> {
        let mut data_bytes = vec![];
        for block in &self.blocks {
            let encoded_block = block.encode()?;
            // only the first 58 bytes are used in the hashing process
            data_bytes.extend_from_slice(&encoded_block[..58]);
        }

        for block in &self.blocks {
            for tx in &block.txs {
                if !tx.is_l1_msg() {
                    continue;
                }
                data_bytes.extend_from_slice(tx.hash().as_slice());
            }
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

pub(crate) fn compute_batch_data_hash<C: ChunkTrait>(
    chunks: &[C],
    total_l1_message_popped_before: u64,
) -> Result<B256, BatchError> {
    let mut data_bytes = Vec::with_capacity(chunks.len() * 32);
    let mut total_l1_message_popped_before_chunk = total_l1_message_popped_before;

    for chunk in chunks {
        let da_chunk_hash = chunk
            .hash(total_l1_message_popped_before_chunk)
            .map_err(BatchError::BuildChunkHash())?;
        total_l1_message_popped_before_chunk +=
            chunk.num_l1_messages(total_l1_message_popped_before_chunk);
        data_bytes.extend_from_slice(da_chunk_hash.as_slice());
    }

    let data_hash = keccak256(&data_bytes);

    Ok(data_hash)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_v1_da_batch() {
        test_dabatch::<DABatch>(testdata!("scroll-mainnet-v1", 175900)).unwrap();
    }
}

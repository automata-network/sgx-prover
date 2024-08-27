use super::prelude::*;

use super::v2;

// diffs from v2:
//   * removed skipped_l1_message_bitmap
//   * added last_block_timestamp
//   * added blob_data_proof

pub const MAX_NUM_CHUNKS: usize = v2::MAX_NUM_CHUNKS;
pub type DABlockTx = v2::DABlockTx;
pub type DABlock = v2::DABlock;

// DAChunk groups consecutive DABlocks with their transactions.
pub type DAChunk = v2::DAChunk;
pub(crate) use v2::compute_batch_data_hash;

pub struct CodecV3 {}
impl BatchVersionedType for CodecV3 {
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
    pub last_block_timestamp: u64,
    pub blob_data_proof: [B256; 2],
}

impl BatchTrait for DABatch {
    fn batch_index(&self) -> u64 {
        self.batch_index
    }

    fn encode(&self) -> Vec<u8> {
        let mut batch_bytes = Vec::with_capacity(193);
        batch_bytes.push(self.version);
        batch_bytes.extend_from_slice(&self.batch_index.to_be_bytes());
        batch_bytes.extend_from_slice(&self.l1_message_popped.to_be_bytes());
        batch_bytes.extend_from_slice(&self.total_l1_message_popped.to_be_bytes());
        batch_bytes.extend_from_slice(self.data_hash.as_slice());
        batch_bytes.extend_from_slice(self.blob_versioned_hash.as_slice());
        batch_bytes.extend_from_slice(self.parent_batch_hash.as_slice());
        batch_bytes.extend_from_slice(&self.last_block_timestamp.to_be_bytes());
        batch_bytes.extend_from_slice(self.blob_data_proof[0].as_slice());
        batch_bytes.extend_from_slice(self.blob_data_proof[1].as_slice());
        batch_bytes
    }

    fn from_bytes(data: &[u8]) -> Result<Self, BatchError> {
        if data.len() < 193 {
            return Err(BatchError::InvalidDABatchData {
                version: 3,
                want_at_least: 193,
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
            last_block_timestamp: u64_be(&data[121..129]),
            blob_data_proof: [to_hash(&data[129..161]), to_hash(&data[161..193])],
        })
    }

    fn new<B: BatchTrait, C: ChunkTrait>(parent: B, chunks: Vec<C>) -> Result<Self, BatchError> {
        check_chunks_size(&chunks, MAX_NUM_CHUNKS)?;

        let data_hash = compute_batch_data_hash(&chunks, parent.total_l1_message_popped())?;

        let batch_index = parent.batch_index() + 1;
        // skipped L1 messages bitmap
        let (_, total_l1_message_popped_after) =
            construct_skipped_bitmap(batch_index, &chunks, parent.total_l1_message_popped())?;

        let last_block = chunks.last().unwrap().last_block()?;

        let blob_payload = BlobPayload::build(&chunks, MAX_NUM_CHUNKS, BlobPayloadCompress::Zstd)?;

        Ok(Self {
            version: 3,
            batch_index,
            l1_message_popped: total_l1_message_popped_after - parent.total_l1_message_popped(),
            total_l1_message_popped: total_l1_message_popped_after,
            data_hash,
            blob_versioned_hash: blob_payload.blob_versioned_hash,
            parent_batch_hash: parent.hash(),
            last_block_timestamp: last_block.timestamp(),
            blob_data_proof: blob_payload.proof,
        })
    }

    fn parent_batch_hash(&self) -> B256 {
        self.parent_batch_hash
    }
    fn total_l1_message_popped(&self) -> u64 {
        self.total_l1_message_popped
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_v3_da_batch() {
        test_dabatch::<DABatch>(testdata!("scroll-mainnet-v3", 310004)).unwrap();
    }
}

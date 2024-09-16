use super::prelude::*;

use super::v1;

// diffs from v1:
//  * DAChunk.hash: MaxChunkSize 15 -> 45
//  * enabled zstd compress

pub const MAX_NUM_CHUNKS: usize = 45;
pub const VERSION: u8 = 2;
pub type DABlockTx = v1::DABlockTx;
pub type DABlock = v1::DABlock;

// DAChunk groups consecutive DABlocks with their transactions.
pub type DAChunk = v1::DAChunk;
pub(crate) use v1::compute_batch_data_hash;

pub struct CodecV2 {}
impl BatchVersionedType for CodecV2 {
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
        } = BlobPayload::build(&chunks, MAX_NUM_CHUNKS, BlobPayloadCompress::Zstd)?;

        Ok(Self {
            version: VERSION,
            batch_index: parent.batch_index() + 1,
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_v2_da_batch() {
        test_dabatch::<DABatch>(testdata!("scroll-mainnet-v2", 300000)).unwrap();
    }
}
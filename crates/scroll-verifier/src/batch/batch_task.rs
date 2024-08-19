use scroll_executor::{revm::primitives::keccak256, B256, U256};
use serde::{Deserialize, Serialize};

use crate::{batch::{calc_blob_hash, compress_scroll_batch_bytes}, HardforkConfig, BUILDIN_TRUSTED_SETTING};

use super::{
    copy, decode_block_numbers, set_bit, solidity_parse_array_bytes, solidity_parse_bytes,
    BatchChunk, BatchError, BatchHeader, BatchHeaderV1,
};

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchTask {
    pub chunks: Vec<Vec<u64>>,
    pub parent_batch_header: BatchHeader,
}

impl BatchTask {
    pub fn id(&self) -> u64 {
        self.parent_batch_header.batch_index() + 1
    }

    pub fn from_calldata(data: &[u8]) -> Result<BatchTask, BatchError> {
        let parent_batch_header_bytes = solidity_parse_bytes(32, data);
        let chunks_bytes = solidity_parse_array_bytes(64, data);
        let parent_batch_header = BatchHeader::from_bytes(&parent_batch_header_bytes)
            .map_err(BatchError::ParseBatchTaskFromCalldata())?;
        let mut outs = Vec::new();
        for chunk_byte in chunks_bytes {
            match decode_block_numbers(&chunk_byte) {
                Some(blks) => outs.push(blks),
                None => return Err(BatchError::InvalidBlockNumbers(chunk_byte.into())),
            }
        }
        Ok(BatchTask {
            chunks: outs,
            parent_batch_header,
        })
    }

    pub fn block_numbers(&self) -> Vec<u64> {
        self.chunks.iter().flatten().map(Clone::clone).collect()
    }

    pub fn start(&self) -> Option<u64> {
        Some(*self.chunks.get(0)?.get(0)?)
    }

    pub fn end(&self) -> Option<u64> {
        Some(*self.chunks.last()?.last()?)
    }

    pub fn build_header(
        &self,
        fork: HardforkConfig,
        chunks: &[BatchChunk],
    ) -> Result<BatchHeader, BatchError> {
        let version = fork.batch_version(self.block_numbers()[0]);
        let batch_id = self.parent_batch_header.batch_index() + 1;
        let total_l1_message_popped = self.parent_batch_header.total_l1_message_popped();
        let base_index = total_l1_message_popped;
        let mut next_index = total_l1_message_popped;
        let mut skipped_bitmap = vec![];
        let mut data_bytes = vec![];
        for (chunk_id, chunk) in chunks.iter().enumerate() {
            let total_l1_message_popped_before_chunk = next_index;
            let chunk_hash = chunk.hash(version, total_l1_message_popped_before_chunk)?;
            data_bytes.extend_from_slice(chunk_hash.as_slice());
            for (block_id, block) in chunk.blocks.iter().enumerate() {
                for tx in &block.txs {
                    if !tx.l1_msg {
                        continue;
                    }
                    let current_index = tx.nonce;
                    if current_index < next_index {
                        return Err(BatchError::InvalidL1Nonce {
                            expect: next_index,
                            current: current_index,
                            batch_id,
                            chunk_id,
                            block_id,
                            tx_hash: tx.tx_hash,
                        });
                    }

                    for skipped_index in next_index..current_index {
                        let quo = ((skipped_index - base_index) / 256) as usize;
                        let rem = ((skipped_index - base_index) % 256) as usize;
                        while skipped_bitmap.len() <= quo {
                            let bitmap = U256::ZERO;
                            skipped_bitmap.push(bitmap);
                        }
                        set_bit(&mut skipped_bitmap[quo], rem);
                    }

                    let quo = ((current_index - base_index) / 256) as usize;
                    while skipped_bitmap.len() <= quo {
                        skipped_bitmap.push(U256::default());
                    }
                    next_index = current_index + 1;
                }
            }
        }

        let data_hash = keccak256(&data_bytes);

        let mut bitmap_bytes = vec![0_u8; skipped_bitmap.len() * 32];
        for (ii, num) in skipped_bitmap.into_iter().enumerate() {
            bitmap_bytes[32 * ii..32 * (ii + 1)].copy_from_slice(&num.to_be_bytes::<32>());
        }

        let blob_versioned_hash = self.construct_blob_payload(version, chunks)?;
        let header = BatchHeaderV1 {
            version,
            batch_index: batch_id,
            l1_message_popped: next_index - total_l1_message_popped,
            total_l1_message_popped: next_index,
            data_hash,
            parent_batch_hash: self.parent_batch_header.hash(),
            blob_versioned_hash,
            skipped_l1_message_bitmap: bitmap_bytes,
        };

        Ok(match version {
            1 => BatchHeader::V1(header),
            2 => BatchHeader::V2(header),
            v => return Err(BatchError::UnknownBatchVersion(v)),
        })
    }

    fn construct_blob_payload(
        &self,
        version: u8,
        chunks: &[BatchChunk],
    ) -> Result<B256, BatchError> {
        const MAX_NUM_CHUNKS_V1: usize = 15;
        const MAX_NUM_CHUNKS_V2: usize = 45;
        let max_num_chunks = if version <= 1 {
            MAX_NUM_CHUNKS_V1
        } else {
            MAX_NUM_CHUNKS_V2
        };
        let metadata_len: usize = 2 + max_num_chunks * 4;

        let mut blob_bytes = vec![0_u8; metadata_len];
        let mut challenge_preimage = vec![0_u8; (1 + max_num_chunks + 1) * 32];
        copy(&mut blob_bytes, (chunks.len() as u16).to_be_bytes());

        let mut chunk_data_hash = B256::default();

        for (chunk_id, chunk) in chunks.into_iter().enumerate() {
            let current_chunk_start_index = blob_bytes.len();
            for block in &chunk.blocks {
                for tx in &block.txs {
                    if !tx.l1_msg {
                        blob_bytes.extend(&tx.encode);
                    }
                }
            }

            let chunk_size = blob_bytes.len() - current_chunk_start_index;
            if chunk_size != 0 {
                let off = 2 + 4 * chunk_id;
                blob_bytes[off..off + 4].copy_from_slice(&(chunk_size as u32).to_be_bytes());
            }

            chunk_data_hash = keccak256(&blob_bytes[current_chunk_start_index..]).into();
            copy(
                &mut challenge_preimage[32 + chunk_id * 32..],
                chunk_data_hash,
            );
        }

        for chunk_id in chunks.len()..max_num_chunks {
            copy(
                &mut challenge_preimage[32 + chunk_id * 32..],
                chunk_data_hash,
            );
        }

        let hash = keccak256(&blob_bytes[..metadata_len]);
        copy(&mut challenge_preimage, hash);

        if version >= 2 {
            blob_bytes =
                compress_scroll_batch_bytes(&blob_bytes).map_err(BatchError::ZstdEncode)?;
        }

        let blob = Self::make_blob_canonical(&blob_bytes)?;

        let c = c_kzg::KzgCommitment::blob_to_kzg_commitment(&blob, &BUILDIN_TRUSTED_SETTING)?;

        Ok(calc_blob_hash(1, &c.to_bytes()))
    }

    fn make_blob_canonical(blob_bytes: &[u8]) -> Result<c_kzg::Blob, BatchError> {
        if blob_bytes.len() > 126976 {
            return Err(BatchError::OversizedBatchPayload);
        }

        let mut blob = [0_u8; c_kzg::BYTES_PER_BLOB];
        let mut index = 0;
        for from in (0..blob_bytes.len()).step_by(31) {
            let to = (from + 31).min(blob_bytes.len());
            copy(&mut blob[index + 1..], &blob_bytes[from..to]);
            index += 32;
        }

        Ok(c_kzg::Blob::new(blob))
    }
}

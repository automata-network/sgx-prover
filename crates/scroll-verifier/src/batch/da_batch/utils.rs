use std::fmt::Debug;
use std::ops::Deref;

use scroll_executor::{
    revm::primitives::{keccak256, B256},
    Context, Transaction, U256,
};

use super::BatchError;

lazy_static::lazy_static! {
    static ref BLSModulus: U256 = U256::from_str_radix(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        16,
    )
    .unwrap();
}

#[cfg(test)]
use crate::BatchTestError;
use crate::{
    batch::{calc_blob_hash, compress_scroll_batch_bytes},
    BUILDIN_TRUSTED_SETTING,
};

#[macro_export]
macro_rules! testdata {
    ($a:expr,$n:expr) => {
        include_str!(concat!(
            "../../../../../../testdata/",
            $a,
            "-commit-",
            $n,
            ".calldata"
        ))
    };
}

pub(crate) fn check_chunks_size<C: ChunkTrait>(chunks: &[C], max: usize) -> Result<(), BatchError> {
    if chunks.len() > max {
        return Err(BatchError::TooManyChunks { max });
    }
    if chunks.len() == 0 {
        return Err(BatchError::MissingChunks);
    }
    Ok(())
}

pub(crate) fn u64_be(data: &[u8]) -> u64 {
    let mut tmp = [0_u8; 8];
    tmp.copy_from_slice(data);
    u64::from_be_bytes(tmp)
}

pub(crate) fn write_u16(dst: &mut [u8], val: u16) {
    dst[..2].copy_from_slice(&val.to_be_bytes());
}

pub(crate) fn write_u32(dst: &mut [u8], val: u32) {
    dst[..4].copy_from_slice(&val.to_be_bytes());
}

pub(crate) fn to_hash(data: &[u8]) -> B256 {
    let mut hash = B256::default();
    hash.0.copy_from_slice(data);
    hash
}

pub(crate) fn make_blob_canonical(blob_bytes: &[u8]) -> Result<c_kzg::Blob, BatchError> {
    // FIXME: check min_check_size
    if blob_bytes.len() > 131072 {
        // CheckCompressedDataCompatibility
    }
    if blob_bytes.len() > 126976 {
        return Err(BatchError::OversizedBatchPayload {
            size: blob_bytes.len(),
        });
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

#[cfg(test)]
pub(crate) fn checked_da_batch<T: BatchTrait>(data: &str) -> Result<T, BatchTestError> {
    let bytes = hex::decode(data.trim_start_matches("0x"))?;
    let bytes = &bytes[4..];
    let bytes = solidity_parse_bytes(32, bytes);
    let batch = T::from_bytes(&bytes)?;
    let encoded = batch.encode();
    if encoded != bytes {
        return Err(BatchTestError::TestEncode {
            want: hex::encode(bytes),
            got: hex::encode(encoded),
        });
    }
    Ok(batch)
}

#[cfg(test)]
pub(crate) fn solidity_parse_bytes(offset: usize, slice: &[u8]) -> Vec<u8> {
    let mut data: Vec<u8> = vec![];
    let data_offset: usize = U256::from_be_slice(&slice[offset..offset + 32]).to();
    let data_len: usize = U256::from_be_slice(&slice[data_offset..data_offset + 32]).to();
    let content_offset = data_offset + 32;
    data.extend_from_slice(&slice[content_offset..content_offset + data_len]);
    data
}

#[cfg(test)]
pub(crate) fn test_dabatch<T: BatchTrait>(testdata: &str) -> Result<(), BatchTestError> {
    let _ = checked_da_batch::<T>(testdata)?;
    Ok(())
}

pub trait TxTrait: Sized + Debug {
    fn new(tx: &Transaction, rlp: Vec<u8>) -> Self;
    fn is_l1_msg(&self) -> bool;
    fn nonce(&self) -> u64;
    fn hash(&self) -> B256;
    fn rlp_bytes(&self) -> &[u8];
}

pub trait ChunkTrait: Sized + Debug + Default {
    type Block: BlockTrait;
    fn add_block(&mut self, blk: Self::Block);
    fn blocks(&self) -> &[Self::Block];
    fn num_l1_messages(&self, total_l1_message_popped_before: u64) -> u64;
    fn hash(&self, total_l1_msg_poped_before: u64) -> Result<B256, BatchError>;

    fn last_block(&self) -> Result<&Self::Block, BatchError> {
        self.blocks()
            .last()
            .ok_or(BatchError::TooFewBlocksInLastChunk)
    }
}

pub trait BlockTrait: Sized + Debug {
    type Tx: TxTrait;
    fn new<C: Context>(ctx: &C, txs: Vec<Self::Tx>) -> Self;
    fn number(&self) -> u64;
    fn timestamp(&self) -> u64;
    fn txs(&self) -> &[Self::Tx];
    fn num_l1_messages(&self, total_l1_message_popped_before: u64) -> u64;
    fn encode(&self) -> Result<Vec<u8>, BatchError>;
}

pub trait BatchTrait: Sized + Debug {
    // func (b *DABatch) Encode() []byte
    fn encode(&self) -> Vec<u8>;

    // func NewDABatch(batch *encoding.Batch) (*DABatch, error)
    fn new<B: BatchTrait, C: ChunkTrait>(parent: B, chunks: Vec<C>) -> Result<Self, BatchError>;

    // func NewDABatchFromBytes(data []byte) (*DABatch, error);
    fn from_bytes(data: &[u8]) -> Result<Self, BatchError>;

    fn parent_batch_hash(&self) -> B256;
    fn batch_index(&self) -> u64;
    fn total_l1_message_popped(&self) -> u64;

    fn hash(&self) -> B256 {
        keccak256(&self.encode())
    }
}

pub(crate) fn copy<N: AsRef<[u8]>>(dst: &mut [u8], src: N) {
    let src = src.as_ref();
    dst[..src.len()].copy_from_slice(src)
}

pub(crate) fn construct_skipped_bitmap<C: ChunkTrait>(
    batch_index: u64,
    chunks: &[C],
    total_l1_message_popped_before: u64,
) -> Result<(Vec<u8>, u64), BatchError> {
    // skipped L1 message bitmap, an array of 256-bit bitmaps
    let mut skipped_bitmap = vec![];

    // the first queue index that belongs to this batch
    let base_index = total_l1_message_popped_before;

    // the next queue index that we need to process
    let mut next_index = total_l1_message_popped_before;

    for (chunk_id, chunk) in chunks.iter().enumerate() {
        for (block_id, block) in chunk.blocks().iter().enumerate() {
            for tx in block.txs() {
                if !tx.is_l1_msg() {
                    continue;
                }

                let current_index = tx.nonce();

                if current_index < next_index {
                    return Err(BatchError::InvalidL1Nonce {
                        expect: next_index,
                        current: current_index,
                        batch_id: batch_index,
                        chunk_id,
                        block_id,
                        tx_hash: tx.hash(),
                    });
                }

                // mark skipped messages
                for skipped_index in next_index..current_index {
                    let quo = ((skipped_index - base_index) / 256) as usize;
                    let rem = ((skipped_index - base_index) % 256) as usize;
                    while skipped_bitmap.len() <= quo {
                        let bitmap = U256::default();
                        skipped_bitmap.push(bitmap);
                    }
                    skipped_bitmap[quo].set_bit(rem, true);
                }

                // process included message
                let quo = ((current_index - base_index) / 256) as usize;
                while skipped_bitmap.len() <= quo {
                    skipped_bitmap.push(U256::default());
                }

                next_index = current_index + 1
            }
        }
    }

    let mut bitmap_bytes = vec![0_u8; skipped_bitmap.len() * 32];
    for (ii, num) in skipped_bitmap.into_iter().enumerate() {
        bitmap_bytes[32 * ii..32 * (ii + 1)].copy_from_slice(&num.to_be_bytes::<32>());
    }

    Ok((bitmap_bytes, next_index))
}

pub struct BlobPayload {
    pub blob: c_kzg::Blob,
    pub blob_versioned_hash: B256,
    pub proof: [B256; 2],
}

pub enum BlobPayloadCompress {
    None,
    Zstd,
}

impl BlobPayload {
    pub fn build<C: ChunkTrait>(
        chunks: &[C],
        max_chunks: usize,
        compress: BlobPayloadCompress,
    ) -> Result<Self, BatchError> {
        // metadata consists of num_chunks (2 bytes) and chunki_size (4 bytes per chunk)
        let metadata_length = 2 + max_chunks * 4;

        // the raw (un-padded) blob payload
        let mut blob_bytes = vec![0_u8; metadata_length];

        // challenge digest preimage
        // 1 hash for metadata, 1 hash for each chunk, 1 hash for blob versioned hash
        let mut challenge_preimage = vec![0_u8; (1 + max_chunks + 1) * 32];

        // the chunk data hash used for calculating the challenge preimage
        let mut chunk_data_hash = B256::default();

        // blob metadata: num_chunks
        write_u16(&mut blob_bytes[..], chunks.len() as u16);

        // encode blob metadata and L2 transactions,
        // and simultaneously also build challenge preimage
        for (chunk_id, chunk) in chunks.into_iter().enumerate() {
            let current_chunk_start_index = blob_bytes.len();

            for block in chunk.blocks() {
                for tx in block.txs() {
                    if tx.is_l1_msg() {
                        continue;
                    }

                    // encode L2 txs into blob payload
                    blob_bytes.extend_from_slice(&tx.rlp_bytes());
                }
            }

            // blob metadata: chunki_size
            let chunk_size = blob_bytes.len() - current_chunk_start_index;
            if chunk_size != 0 {
                write_u32(&mut blob_bytes[2 + 4 * chunk_id..], chunk_size as u32);
            }

            // challenge: compute chunk data hash
            chunk_data_hash = keccak256(&blob_bytes[current_chunk_start_index..]);
            copy(
                &mut challenge_preimage[32 + chunk_id * 32..],
                &chunk_data_hash[..],
            );
        }

        // if we have fewer than max_chunks chunks, the rest
        // of the blob metadata is correctly initialized to 0,
        // but we need to add padding to the challenge preimage
        for chunk_id in chunks.len()..max_chunks {
            // use the last chunk's data hash as padding
            copy(
                &mut challenge_preimage[32 + chunk_id * 32..],
                &chunk_data_hash[..],
            );
        }

        // challenge: compute metadata hash
        let hash = keccak256(&blob_bytes[..metadata_length]);
        copy(&mut challenge_preimage[0..], &hash[..]);

        match compress {
            BlobPayloadCompress::None => {}
            BlobPayloadCompress::Zstd => {
                blob_bytes =
                    compress_scroll_batch_bytes(&blob_bytes).map_err(BatchError::ZstdEncode)?;
            }
        }

        // Only apply this check when the uncompressed batch data has exceeded 128 KiB.
        // convert raw data to BLSFieldElements
        let blob = make_blob_canonical(&blob_bytes)?;

        // compute blob versioned hash
        let c = c_kzg::KzgCommitment::blob_to_kzg_commitment(&blob, &BUILDIN_TRUSTED_SETTING)?;

        let blob_versioned_hash = calc_blob_hash(1, &c.to_bytes());

        // challenge: append blob versioned hash
        copy(
            &mut challenge_preimage[(1 + max_chunks) * 32..],
            &blob_versioned_hash[..],
        );

        // compute z = challenge_digest % BLS_MODULUS
        let challenge_digest = keccak256(&challenge_preimage);
        let point = U256::from_be_bytes(challenge_digest.0) % *BLSModulus;
        let z: B256 = point.to_be_bytes().into();

        // the challenge point z
        let (_, y) =
            c_kzg::KzgProof::compute_kzg_proof(&blob, &(z.0.into()), &BUILDIN_TRUSTED_SETTING)?;
        let proof = [z, y.deref().clone().into()];

        Ok(Self {
            blob,
            blob_versioned_hash,
            proof,
        })
    }
}

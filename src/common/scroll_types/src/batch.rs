use core::hash::{Hash, Hasher};
use std::prelude::v1::*;

use crypto::{keccak_hash, sha256_sum};
use eth_types::{SH256, SU256};
use serde::{Deserialize, Serialize};

use crate::{
    decode_block_numbers, BatchHeader, BatchHeaderV1, BlockHeader, RollupError, TraceTx,
    Transaction, TransactionInner, L1_MESSAGE_TX_TYPE_U64,
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

    pub fn from_calldata(data: &[u8]) -> Result<BatchTask, RollupError> {
        let parent_batch_header_bytes = solidity::parse_bytes(32, data);
        let chunks_bytes = solidity::parse_array_bytes(64, data);
        let parent_batch_header = BatchHeader::from_bytes(&parent_batch_header_bytes)
            .map_err(RollupError::ParseBatchTaskFromCalldata())?;
        let mut outs = Vec::new();
        for chunk_byte in chunks_bytes {
            match decode_block_numbers(&chunk_byte) {
                Some(blks) => outs.push(blks),
                None => return Err(RollupError::InvalidBlockNumbers(chunk_byte.into())),
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

    pub fn build_header(&self, chunks: &[BatchChunk]) -> Result<BatchHeader, RollupError> {
        let version = self.parent_batch_header.version();
        let batch_id = self.parent_batch_header.batch_index() + 1;
        let total_l1_message_popped = self.parent_batch_header.total_l1_message_popped();
        let base_index = total_l1_message_popped;
        let mut next_index = total_l1_message_popped;
        let mut skipped_bitmap = vec![];
        let mut data_bytes = vec![];
        for (chunk_id, chunk) in chunks.iter().enumerate() {
            let total_l1_message_popped_before_chunk = next_index;
            let chunk_hash = chunk.hash(version, total_l1_message_popped_before_chunk)?;
            data_bytes.extend_from_slice(chunk_hash.as_bytes());
            for (block_id, block) in chunk.blocks.iter().enumerate() {
                for tx in &block.txs {
                    if !tx.l1_msg {
                        continue;
                    }
                    let current_index = tx.nonce;
                    if current_index < next_index {
                        return Err(RollupError::InvalidL1Nonce {
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

        let blob_versioned_hash = self.construct_blob_payload(version, chunks)?;

        Ok(BatchHeader::V1(BatchHeaderV1 {
            version,
            batch_index: batch_id,
            l1_message_popped: next_index - total_l1_message_popped,
            total_l1_message_popped: next_index,
            data_hash,
            parent_batch_hash: self.parent_batch_header.hash(),
            blob_versioned_hash,
            skipped_l1_message_bitmap: bitmap_bytes,
        }))
    }

    fn construct_blob_payload(
        &self,
        version: u8,
        chunks: &[BatchChunk],
    ) -> Result<SH256, RollupError> {
        const MAX_NUM_CHUNKS: usize = 15;
        const METADATA_LEN: usize = 2 + MAX_NUM_CHUNKS * 4;

        let mut blob_bytes = vec![0_u8; METADATA_LEN];
        let mut challenge_preimage = vec![0_u8; (1 + MAX_NUM_CHUNKS + 1) * 32];
        copy(&mut blob_bytes, (chunks.len() as u16).to_be_bytes());

        let mut chunk_data_hash = SH256::default();

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

            chunk_data_hash = keccak_hash(&blob_bytes[current_chunk_start_index..]).into();
            copy(
                &mut challenge_preimage[32 + chunk_id * 32..],
                chunk_data_hash,
            );
        }

        for chunk_id in chunks.len()..MAX_NUM_CHUNKS {
            copy(
                &mut challenge_preimage[32 + chunk_id * 32..],
                chunk_data_hash,
            );
        }

        let hash = keccak_hash(&blob_bytes[..METADATA_LEN]);
        copy(&mut challenge_preimage, hash);

        let blob = Self::make_blob_canonical(&blob_bytes)?;

        let kzg_settings = &c_kzg::BUILDIN_TRUSTED_SETTING;
        let c = c_kzg::KzgCommitment::blob_to_kzg_commitment(&blob, kzg_settings)?;

        Ok(calc_blob_hash(version, &c.to_bytes()))
    }

    fn make_blob_canonical(blob_bytes: &[u8]) -> Result<c_kzg::Blob, RollupError> {
        if blob_bytes.len() > 126976 {
            return Err(RollupError::OversizedBatchPayload);
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

fn copy<N: AsRef<[u8]>>(dst: &mut [u8], src: N) {
    let src = src.as_ref();
    dst[..src.len()].copy_from_slice(src)
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

    pub fn chunks(self) -> Vec<BatchChunk> {
        self.chunks
    }

    pub fn add_block(
        &mut self,
        header: &BlockHeader,
        txs: Vec<BatchChunkBlockTx>,
    ) -> Result<(), String> {
        for (chunk_id, chunk) in self.numbers.iter().enumerate() {
            for (block_id, blkno) in chunk.iter().enumerate() {
                if blkno == &header.number.as_u64() {
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
                    chunk.blocks.push(BatchChunkBlock {
                        number: header.number.as_u64(),
                        timestamp: header.timestamp.as_u64(),
                        gas_limit: header.gas_limit.as_u64(),
                        base_fee: header.base_fee_per_gas,
                        hash: header.hash(),
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

fn calc_blob_hash<H: Hash>(version: u8, h: &H) -> SH256 {
    pub struct H {
        version: u8,
        hash: SH256,
    }
    impl Hasher for H {
        fn write(&mut self, bytes: &[u8]) {
            self.hash = sha256_sum(bytes).into();
            self.hash.as_bytes_mut()[0] = self.version;
        }

        fn finish(&self) -> u64 {
            0
        }
    }
    let mut def_hasher = H {
        version,
        hash: SH256::default(),
    };
    h.hash(&mut def_hasher);
    def_hasher.hash
}

#[derive(Clone, Debug)]
pub struct BatchChunk {
    blocks: Vec<BatchChunkBlock>,
}

impl BatchChunk {
    pub fn encode(&self, mut total_l1_msg_poped_before: u64) -> Result<Vec<u8>, RollupError> {
        let num_blocks = self.blocks.len();
        if num_blocks > 255 || num_blocks == 0 {
            return Err(RollupError::InvalidNumBlock(num_blocks));
        }

        let mut chunk_bytes = vec![num_blocks as u8];
        let mut l2_tx_data_bytes = vec![];
        for block in &self.blocks {
            let block_bytes = block.encode(total_l1_msg_poped_before)?;
            total_l1_msg_poped_before += block.num_l1_msg(total_l1_msg_poped_before);
            if block_bytes.len() != 60 {
                return Err(RollupError::InvalidBlockBytes(block_bytes.into()));
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

    pub fn hash(&self, version: u8, total_l1_msg_poped_before: u64) -> Result<SH256, RollupError> {
        let chunk_bytes = self
            .encode(total_l1_msg_poped_before)
            .map_err(RollupError::EncodeBatchChunk())?;
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
                    if version == 0 {
                        l2_tx_hashes.extend_from_slice(tx.tx_hash.as_bytes());
                    }
                }
            }
            data_bytes.extend_from_slice(&l1_tx_hashes);
            if version == 0 {
                data_bytes.extend_from_slice(&l2_tx_hashes);
            }
        }

        let hash = keccak_hash(&data_bytes);
        Ok(hash.into())
    }
}

#[derive(Clone, Debug)]
pub struct BatchChunkBlock {
    number: u64,
    timestamp: u64,
    base_fee: Option<SU256>,
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

    pub fn encode(&self, total_l1_msg_poped_before: u64) -> Result<Vec<u8>, RollupError> {
        let mut bytes = Vec::with_capacity(60);
        let num_l1_messages = self.num_l1_msg(total_l1_msg_poped_before);
        if num_l1_messages > u16::max_value() as _ {
            return Err(RollupError::NumL1TxTooLarge);
        }

        let num_l2_transactions = self.num_l2_txs();
        let num_transactions = num_l1_messages + num_l2_transactions;
        if num_transactions > u16::max_value() as _ {
            return Err(RollupError::NumTxTooLarge);
        }
        bytes.extend_from_slice(&self.number.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        let mut base_fee_bytes = [0_u8; 32];
        if let Some(base_fee) = self.base_fee {
            base_fee.to_big_endian(&mut base_fee_bytes);
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
    l1_msg: bool,
    nonce: u64,
    tx_hash: SH256,
    encode: Vec<u8>,
}

impl From<&TransactionInner> for BatchChunkBlockTx {
    fn from(tx: &TransactionInner) -> Self {
        Self {
            l1_msg: tx.ty() == L1_MESSAGE_TX_TYPE_U64,
            nonce: tx.nonce(),
            tx_hash: tx.hash(),
            encode: tx.to_bytes(),
        }
    }
}

impl From<Transaction> for BatchChunkBlockTx {
    fn from(tx: Transaction) -> Self {
        let tx = tx.inner().unwrap();
        Self {
            l1_msg: tx.ty() == L1_MESSAGE_TX_TYPE_U64,
            nonce: tx.nonce(),
            tx_hash: tx.hash(),
            encode: tx.to_bytes(),
        }
    }
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

fn set_bit(val: &mut SU256, i: usize) {
    let j = i / 4;
    let m = 1u64 << (i % 8);
    val.0[j] |= m;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_batch() {
        glog::init_test();
        let trace_bytes = include_bytes!("../testdata/blockTrace_02.json");
        let block_trace: BlockTrace = serde_json::from_slice(trace_bytes).unwrap();
        let chunk_numbers = vec![vec![2]];
        let mut builder = BatchChunkBuilder::new(chunk_numbers.clone());
        builder.add_block(&block_trace).unwrap();
        let mut task = BatchTask {
            batch_id: 0.into(),
            batch_hash: SH256::default(),
            chunks: chunk_numbers,
            parent_batch_header: BatchHeader::V1(BatchHeaderV1 {
                version: 1,
                ..BatchHeaderV1::default()
            }),
        };
        let chunks = builder.chunks();
        let mut header = task.build_header(1, &chunks).unwrap();
        if let BatchHeader::V1(header) = &mut header {
            header.parent_batch_hash = SH256::default();
        }
        assert_eq!(
            HexBytes::from_hex(b"010000000000000000000000000000000000000000000000009f81f6879f121da5b7a37535cdb21b3d53099266de57b1fdf603ce32100ed54101af944924715b48be6ce3c35aef7500a50e909265599bd2b3e544ac59fc75530000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            HexBytes::from(header.encode()),
        );

        assert_eq!(
            header.hash(),
            "0xd557b02638c0385d5124f7fc188a025b33f8819b7f78c000751404997148ab8b".into()
        );
    }
}

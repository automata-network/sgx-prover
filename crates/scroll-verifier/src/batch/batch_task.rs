use prover_types::{Poe, B256};
use serde::{Deserialize, Serialize};

use crate::HardforkConfig;

use super::{
    decode_block_numbers, solidity_parse_array_bytes, solidity_parse_bytes, BatchBuilder,
    BatchError, DABatch,
};

#[derive(Debug, Clone)]
pub struct Finalize {
    pub batch: DABatch,
    pub prev_state_root: Option<B256>,
    pub new_state_root: B256,
    pub new_withdrawal_root: B256,
}

impl Finalize {
    pub fn from_calldata(data: &[u8]) -> Result<Self, BatchError> {
        let batch = solidity_parse_bytes(0, data);
        let batch = DABatch::from_bytes(&batch)?;
        let mut off = 1;
        let mut prev_state_root = None;
        if batch.version() <= 2 {
            prev_state_root = Some(B256::from_slice(&data[off * 32..][..32]));
            off += 1;
        }
        let new_state_root = B256::from_slice(&data[off * 32..][..32]);
        off += 1;

        let new_withdrawal_root = B256::from_slice(&data[off * 32..][..32]);

        Ok(Self {
            batch,
            prev_state_root,
            new_state_root,
            new_withdrawal_root,
        })
    }

    pub fn assert_poe(&self, poe: &Poe) {
        assert_eq!(self.batch.hash(), poe.batch_hash, "batch");
        if let Some(prev_state_root) = self.prev_state_root {
            assert_eq!(prev_state_root, poe.prev_state_root, "prev_state_root");
        }
        assert_eq!(self.new_state_root, poe.new_state_root, "new_state_root");
        assert_eq!(
            self.new_withdrawal_root, poe.withdrawal_root,
            "withdrawal_root"
        );
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchTask {
    pub chunks: Vec<Vec<u64>>,
    pub parent_batch_header: DABatch,
}

impl BatchTask {
    pub fn id(&self) -> u64 {
        self.parent_batch_header.batch_index() + 1
    }

    pub fn builder(&self, fork: HardforkConfig) -> Result<BatchBuilder, BatchError> {
        BatchBuilder::new(fork, self.parent_batch_header.clone(), self.chunks.clone())
    }

    pub fn from_calldata(data: &[u8]) -> Result<BatchTask, BatchError> {
        let parent_batch_header_bytes = solidity_parse_bytes(32, data);
        let chunks_bytes = solidity_parse_array_bytes(64, data);
        let parent_batch_header = DABatch::from_bytes(&parent_batch_header_bytes)
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
}

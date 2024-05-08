use std::prelude::v1::*;

use crypto::keccak_hash;
use eth_types::{HexBytes, SH256};

base::stack_error! {
    name: RollupError,
    stack_name: RollupErrorStack,
    error: {
        UnknownBatchVersion(u8),
        InvalidBlockNumbers(HexBytes),
        InvalidBlockBytes(HexBytes),
        InvalidNumBlock(usize),
        InvalidL1Nonce{ expect: u64, current: u64, batch_id: usize, chunk_id: usize, block_id: usize, tx_hash: SH256 },
        NumL1TxTooLarge,
        NumTxTooLarge,
        OversizedBatchPayload,
        KzgError(String),
    },
    stack: {
        ParseBatchTaskFromCalldata(),
        EncodeBatchChunk(),
    }
}

impl From<c_kzg::Error> for RollupError {
    fn from(err: c_kzg::Error) -> Self {
        Self::KzgError(format!("{:?}", err))
    }
}

pub fn decode_block_numbers(mut data: &[u8]) -> Option<Vec<u64>> {
    if data.len() < 1 {
        return None;
    }
    let num_blocks = data[0] as usize;
    data = &data[1..];
    if data.len() < num_blocks * 60 {
        return None;
    }

    let mut numbers = Vec::new();
    let mut tmp = [0_u8; 8];
    for i in 0..num_blocks {
        tmp.copy_from_slice(&data[i * 60..i * 60 + 8]);
        let block_number = u64::from_be_bytes(tmp);
        numbers.push(block_number);
    }
    Some(numbers)
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub enum BatchHeader {
    V0(BatchHeaderV0),
    V1(BatchHeaderV1),
}

impl BatchHeader {
    pub fn total_l1_message_popped(&self) -> u64 {
        match self {
            Self::V0(v0) => v0.total_l1_message_popped,
            Self::V1(v1) => v1.total_l1_message_popped,
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            Self::V0(v0) => v0.version,
            Self::V1(v1) => v1.version,
        }
    }

    pub fn batch_index(&self) -> u64 {
        match self {
            Self::V0(v0) => v0.batch_index,
            Self::V1(v1) => v1.batch_index,
        }
    }

    pub fn hash(&self) -> SH256 {
        match self {
            BatchHeader::V0(v0) => v0.hash(),
            BatchHeader::V1(v1) => v1.hash(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            BatchHeader::V0(v0) => v0.encode(),
            BatchHeader::V1(v1) => v1.encode(),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, RollupError> {
        Ok(match data[0] {
            0 => Self::V0(BatchHeaderV0::from_bytes(data)),
            1 => Self::V1(BatchHeaderV1::from_bytes(data)),
            v => return Err(RollupError::UnknownBatchVersion(v)),
        })
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Default)]
pub struct BatchHeaderV0 {
    pub version: u8,
    pub batch_index: u64,
    pub l1_message_popped: u64,
    pub total_l1_message_popped: u64,
    pub data_hash: SH256,
    pub parent_batch_hash: SH256,
    pub skipped_l1_message_bitmap: Vec<u8>,
}

impl BatchHeaderV0 {
    pub fn hash(&self) -> SH256 {
        keccak_hash(&self.encode()).into()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut batch_bytes = Vec::with_capacity(89 + self.skipped_l1_message_bitmap.len());
        batch_bytes.push(self.version);
        batch_bytes.extend_from_slice(&self.batch_index.to_be_bytes());
        batch_bytes.extend_from_slice(&self.l1_message_popped.to_be_bytes());
        batch_bytes.extend_from_slice(&self.total_l1_message_popped.to_be_bytes());
        batch_bytes.extend_from_slice(self.data_hash.as_bytes());
        batch_bytes.extend_from_slice(self.parent_batch_hash.as_bytes());
        batch_bytes.extend_from_slice(&self.skipped_l1_message_bitmap);
        batch_bytes
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let version = data[0];
        let mut tmp = [0_u8; 8];
        let batch_index = {
            tmp.copy_from_slice(&data[1..9]);
            u64::from_be_bytes(tmp)
        };
        let l1_message_popped = {
            tmp.copy_from_slice(&data[9..17]);
            u64::from_be_bytes(tmp)
        };
        let total_l1_message_popped = {
            tmp.copy_from_slice(&data[17..25]);
            u64::from_be_bytes(tmp)
        };
        let mut data_hash = SH256::default();
        data_hash.0.copy_from_slice(&data[25..57]);
        let mut parent_batch_hash = SH256::default();
        parent_batch_hash.0.copy_from_slice(&data[57..89]);
        let skipped_l1_message_bitmap = data[89..].to_vec();
        Self {
            version,
            batch_index,
            l1_message_popped,
            total_l1_message_popped,
            data_hash,
            parent_batch_hash,
            skipped_l1_message_bitmap,
        }
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Default)]
pub struct BatchHeaderV1 {
    pub version: u8,
    pub batch_index: u64,
    pub l1_message_popped: u64,
    pub total_l1_message_popped: u64,
    pub data_hash: SH256,
    pub parent_batch_hash: SH256,
    pub blob_versioned_hash: SH256,
    pub skipped_l1_message_bitmap: Vec<u8>,
}

impl BatchHeaderV1 {
    pub fn hash(&self) -> SH256 {
        keccak_hash(&self.encode()).into()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut batch_bytes = Vec::with_capacity(121 + self.skipped_l1_message_bitmap.len());
        batch_bytes.push(self.version);
        batch_bytes.extend_from_slice(&self.batch_index.to_be_bytes());
        batch_bytes.extend_from_slice(&self.l1_message_popped.to_be_bytes());
        batch_bytes.extend_from_slice(&self.total_l1_message_popped.to_be_bytes());
        batch_bytes.extend_from_slice(self.data_hash.as_bytes());
        batch_bytes.extend_from_slice(self.blob_versioned_hash.as_bytes());
        batch_bytes.extend_from_slice(self.parent_batch_hash.as_bytes());
        batch_bytes.extend_from_slice(&self.skipped_l1_message_bitmap);
        batch_bytes
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let version = data[0];
        let mut tmp = [0_u8; 8];
        let batch_index = {
            tmp.copy_from_slice(&data[1..9]);
            u64::from_be_bytes(tmp)
        };
        let l1_message_popped = {
            tmp.copy_from_slice(&data[9..17]);
            u64::from_be_bytes(tmp)
        };
        let total_l1_message_popped = {
            tmp.copy_from_slice(&data[17..25]);
            u64::from_be_bytes(tmp)
        };
        let mut data_hash = SH256::default();
        data_hash.0.copy_from_slice(&data[25..57]);

        let mut blob_versioned_hash = SH256::default();
        blob_versioned_hash.0.copy_from_slice(&data[57..89]);

        let mut parent_batch_hash = SH256::default();
        parent_batch_hash.0.copy_from_slice(&data[89..121]);


        let skipped_l1_message_bitmap = data[121..].to_vec();
        Self {
            version,
            batch_index,
            l1_message_popped,
            total_l1_message_popped,
            data_hash,
            parent_batch_hash,
            blob_versioned_hash,
            skipped_l1_message_bitmap,
        }
    }
}

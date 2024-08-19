use scroll_executor::{revm::primitives::keccak256, B256};
use serde::{Serialize, Deserialize};

use super::BatchError;

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BatchHeader {
    V0(BatchHeaderV0),
    V1(BatchHeaderV1),
    V2(BatchHeaderV1),
}

impl BatchHeader {
    pub fn total_l1_message_popped(&self) -> u64 {
        match self {
            Self::V0(v0) => v0.total_l1_message_popped,
            Self::V1(v1) => v1.total_l1_message_popped,
            Self::V2(v2) => v2.total_l1_message_popped,
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            Self::V0(v0) => v0.version,
            Self::V1(v1) => v1.version,
            Self::V2(v2) => v2.version,
        }
    }

    pub fn batch_index(&self) -> u64 {
        match self {
            Self::V0(v0) => v0.batch_index,
            Self::V1(v1) => v1.batch_index,
            Self::V2(v2) => v2.batch_index,
        }
    }

    pub fn hash(&self) -> B256 {
        match self {
            BatchHeader::V0(v0) => v0.hash(),
            BatchHeader::V1(v1) => v1.hash(),
            BatchHeader::V2(v2) => v2.hash(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            BatchHeader::V0(v0) => v0.encode(),
            BatchHeader::V1(v1) => v1.encode(),
            BatchHeader::V2(v2) => v2.encode(),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, BatchError> {
        Ok(match data[0] {
            0 => Self::V0(BatchHeaderV0::from_bytes(data)),
            1 => Self::V1(BatchHeaderV1::from_bytes(data)),
            2 => Self::V2(BatchHeaderV1::from_bytes(data)),
            v => return Err(BatchError::UnknownBatchVersion(v)),
        })
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BatchHeaderV0 {
    pub version: u8,
    pub batch_index: u64,
    pub l1_message_popped: u64,
    pub total_l1_message_popped: u64,
    pub data_hash: B256,
    pub parent_batch_hash: B256,
    pub skipped_l1_message_bitmap: Vec<u8>,
}

impl BatchHeaderV0 {
    pub fn hash(&self) -> B256 {
        keccak256(&self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
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
        let mut data_hash = B256::default();
        data_hash.0.copy_from_slice(&data[25..57]);
        let mut parent_batch_hash = B256::default();
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

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BatchHeaderV1 {
    pub version: u8,
    pub batch_index: u64,
    pub l1_message_popped: u64,
    pub total_l1_message_popped: u64,
    pub data_hash: B256,
    pub blob_versioned_hash: B256,
    pub parent_batch_hash: B256,
    pub skipped_l1_message_bitmap: Vec<u8>,
}

impl BatchHeaderV1 {
    pub fn hash(&self) -> B256 {
        keccak256(&self.encode())
    }

    pub fn encode(&self) -> Vec<u8> {
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
        let mut data_hash = B256::default();
        data_hash.0.copy_from_slice(&data[25..57]);

        let mut blob_versioned_hash = B256::default();
        blob_versioned_hash.0.copy_from_slice(&data[57..89]);

        let mut parent_batch_hash = B256::default();
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

mod builder;
pub use builder::*;

pub mod v0;
pub mod v1;
pub mod v2;
pub mod v3;
pub mod v4;

pub(crate) mod prelude {
    pub use super::super::{BatchError, BatchVersionedType};
    pub use super::utils::*;
    pub use scroll_executor::{revm::primitives::keccak256, B256, U256, Transaction};
    pub use serde::{Deserialize, Serialize};
    #[cfg(test)]
    pub use crate::testdata;
}

use prelude::*;
mod utils;

pub trait BatchVersionedType {
    type Batch: BatchTrait;
    type Chunk: ChunkTrait<Block = Self::Block>;
    type Block: BlockTrait<Tx = Self::Tx>;
    type Tx: TxTrait;
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DABatch {
    V0(v0::DABatch),
    V1(v1::DABatch),
    V2(v2::DABatch),
    V3(v3::DABatch),
    V4(v4::DABatch),
}


impl DABatch {
    pub fn total_l1_message_popped(&self) -> u64 {
        match self {
            Self::V0(b) => b.total_l1_message_popped,
            Self::V1(b) => b.total_l1_message_popped,
            Self::V2(b) => b.total_l1_message_popped,
            Self::V3(b) => b.total_l1_message_popped,
            Self::V4(b) => b.total_l1_message_popped,
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            Self::V0(b) => b.version,
            Self::V1(b) => b.version,
            Self::V2(b) => b.version,
            Self::V3(b) => b.version,
            Self::V4(b) => b.version,
        }
    }

    pub fn batch_index(&self) -> u64 {
        match self {
            Self::V0(b) => b.batch_index,
            Self::V1(b) => b.batch_index,
            Self::V2(b) => b.batch_index,
            Self::V3(b) => b.batch_index,
            Self::V4(b) => b.batch_index,
        }
    }

    pub fn hash(&self) -> B256 {
        match self {
            Self::V0(b) => b.hash(),
            Self::V1(b) => b.hash(),
            Self::V2(b) => b.hash(),
            Self::V3(b) => b.hash(),
            Self::V4(b) => b.hash(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::V0(b) => b.encode(),
            Self::V1(b) => b.encode(),
            Self::V2(b) => b.encode(),
            Self::V3(b) => b.encode(),
            Self::V4(b) => b.encode(),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, BatchError> {
        Ok(match data[0] {
            0 => Self::V0(v0::DABatch::from_bytes(data)?),
            1 => Self::V1(v1::DABatch::from_bytes(data)?),
            2 => Self::V2(v2::DABatch::from_bytes(data)?),
            3 => Self::V3(v3::DABatch::from_bytes(data)?),
            4 => Self::V4(v4::DABatch::from_bytes(data)?),
            v => return Err(BatchError::UnknownBatchVersion(v)),
        })
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_v0_codec() {
        
    }
}
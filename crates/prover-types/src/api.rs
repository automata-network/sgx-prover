use alloy::primitives::{Bytes, B256};
use base::prover::keccak_encode;
use serde::{Deserialize, Serialize};

use crate::{Poe, TaskType};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProveTaskParams {
    pub batch: Option<Bytes>,
    pub pob_hash: B256,
    pub task_type: Option<u64>,
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub starting_state_root: Option<B256>,
    pub final_state_root: Option<B256>,
    pub from: Option<serde_json::Value>,
}

impl ProveTaskParams {
    pub fn task_type(&self) -> TaskType {
        match self.task_type {
            Some(n) => TaskType::from_u64(n),
            None => TaskType::Scroll,
        }
    }
    pub fn batch(&self) -> Result<&[u8], ParamsError> {
        self.batch
            .as_ref()
            .ok_or(ParamsError::MissingBatch)
            .map(|n| &n[..])
    }
}

#[derive(Debug)]
pub enum ParamsError {
    MissingBatch,
}

#[derive(Clone, Debug, Serialize)]
pub struct PoeResponse {
    pub not_ready: bool,
    pub batch_id: u64,
    pub start_block: u64,
    pub end_block: u64,
    pub poe: Option<Poe>,
    pub poe_signature: Option<Bytes>,
}

pub fn poe_digest(poe: &Poe) -> B256 {
    keccak_encode(|hash| {
        hash(poe.batch_hash.as_slice());
        hash(poe.state_hash.as_slice());
        hash(poe.prev_state_root.as_slice());
        hash(poe.new_state_root.as_slice());
        hash(poe.withdrawal_root.as_slice());
    })
}
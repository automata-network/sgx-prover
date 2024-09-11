use alloy::primitives::{Bytes, B256};
use serde::{Deserialize, Serialize};

use crate::keccak_encode;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Poe {
    pub batch_hash: B256,
    pub state_hash: B256,
    pub prev_state_root: B256,
    pub new_state_root: B256,
    pub withdrawal_root: B256,
    pub signature: Bytes, // 65bytes
}

impl Poe {
    pub fn merge(batch_hash: B256, reports: &[Self]) -> Option<Self> {
        if reports.len() < 1 {
            return None;
        }

        let state_hash = keccak_encode(|hash| {
            for report in reports {
                hash(&report.state_hash.0);
            }
        })
        .into();
        let prev_state_root = reports.first().unwrap().prev_state_root;
        let new_state_root = reports.last().unwrap().new_state_root;
        let withdrawal_root = reports.last().unwrap().withdrawal_root;
        Some(Self {
            batch_hash,
            state_hash,
            prev_state_root,
            new_state_root,
            withdrawal_root,
            signature: vec![0_u8; 65].into(),
        })
    }
}

impl Default for Poe {
    fn default() -> Self {
        Self {
            batch_hash: B256::default(),
            state_hash: B256::default(),
            prev_state_root: B256::default(),
            new_state_root: B256::default(),
            withdrawal_root: B256::default(),
            signature: vec![0_u8; 65].into(),
        }
    }
}

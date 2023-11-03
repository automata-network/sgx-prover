use std::prelude::v1::*;

use eth_types::SH256;

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

#[derive(Debug, Clone)]
pub struct BatchHeader {
    pub version: u8,
    pub batch_index: u64,
    pub l1_message_popped: u64,
    pub total_l1_message_popped: u64,
    pub data_hash: SH256,
    pub parent_batch_hash: SH256,
    pub skipped_l1_message_bitmap: Vec<u8>,
}

impl BatchHeader {
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

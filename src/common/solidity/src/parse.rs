use std::prelude::v1::*;

use eth_types::{H256, U256, SH256, H160, SH160, SU256};

pub fn parse_bytes(offset: usize, slice: &[u8]) -> Vec<u8> {
    let mut data: Vec<u8> = vec![];
    let data_offset = U256::from_big_endian(&slice[offset..offset + 32]).as_usize();
    let data_len = U256::from_big_endian(&slice[data_offset..data_offset + 32]).as_usize();
    let content_offset = data_offset + 32;
    data.extend_from_slice(&slice[content_offset..content_offset + data_len]);
    data
}

pub fn parse_h256(offset: usize, slice: &[u8]) -> SH256 {
    H256::from_slice(&slice[offset..offset + 32]).into()
}

pub fn parse_h160(offset: usize, slice: &[u8]) -> SH160 {
    H160::from_slice(&slice[offset + 12..offset + 32]).into()
}

pub fn parse_u256(offset: usize, slice: &[u8]) -> SU256 {
    U256::from_big_endian(&slice[offset..offset + 32]).into()
}

pub fn parse_array_bytes(offset: usize, slice: &[u8]) -> Vec<Vec<u8>> {
    let len_offset = U256::from_big_endian(&slice[offset..offset + 32]).as_usize();
    let len = U256::from_big_endian(&slice[len_offset..len_offset + 32]).as_usize();

    let tail_offset = len_offset + 32;
    let tail = &slice[tail_offset..];

    let mut vs = vec![];
    for i in 0..len {
        let data = parse_bytes(i * 32, tail);
        vs.push(data);
    }
    vs
}
use std::prelude::v1::*;

use linea_mimc::keccak_hash;
use alloy::primitives::B256;

use crate::Error;
lazy_static::lazy_static! {
    pub static ref EMPTY_KECCAK_CODE_HASH: B256 = keccak_hash(&[]).into();
    pub static ref EMPTY_MIMC_CODE_HASH: B256 = trie_hash(B256::default().as_slice()).unwrap();
}

pub fn trie_hash(data: &[u8]) -> Result<B256, Error> {
    linea_mimc::sum(data).map(|n| n.into()).map_err(Error::HashFail)
}

pub fn mimc_safe(hash: &[u8]) -> Result<B256, Error> {
    assert_eq!(hash.len(), 32);
    let mut buf = [0_u8; 64];
    buf[16..32].copy_from_slice(&hash[16..]);
    buf[48..64].copy_from_slice(&hash[..16]);
    trie_hash(&buf)
}

pub fn mimc_safe_encode(hash: &[u8]) -> [u8; 64] {
    assert_eq!(hash.len(), 32);
    let mut buf = [0_u8; 64];
    buf[16..32].copy_from_slice(&hash[16..]);
    buf[48..64].copy_from_slice(&hash[..16]);
    buf
}

fn cell(a: usize, b: usize) -> usize {
    let val = a / b;
    if a & (b - 1) != 0 {
        return val + 1;
    }
    val
}

pub fn mimc_safe_code_hash(code: &[u8]) -> B256 {
    const CHUNK_SIZE: usize = 16;
    let num_chunks = cell(code.len(), CHUNK_SIZE);
    let mut buf = vec![0_u8; num_chunks * 32];
    let mut offset = 0;
    for i in 0..num_chunks {
        let length = CHUNK_SIZE.min(code.len() - offset);
        buf[(i + 1) * 32 - length..(i + 1) * 32].copy_from_slice(&code[offset..offset + length]);
        offset += length;
    }
    trie_hash(&buf).unwrap()
}

use std::prelude::v1::*;

use eth_types::{SU256, U256};

use crate::{HashScheme, HASH_DOMAIN_BYTE32};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Byte32([u8; 32]);

impl Byte32 {
    pub fn from_bytes_padding(mut b: &[u8]) -> Self {
        let mut bytes = [0_u8; 32];
        if b.len() > bytes.len() {
            b = &b[..bytes.len()];
        }
        let dst = if b.len() > bytes.len() {
            &mut bytes[..]
        } else {
            &mut bytes[..b.len()]
        };
        dst.copy_from_slice(b);
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn hash<H: HashScheme>(&self) -> SU256 {
        let first16 = U256::from_big_endian(&self.0[0..16]).into();
        let last16 = U256::from_big_endian(&self.0[16..32]).into();
        let domain = HASH_DOMAIN_BYTE32.into();
        H::hash_scheme(&[first16, last16], &domain)
    }

    pub fn u256(&self) -> SU256 {
        U256::from_big_endian(&self.0).into()
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_vec_bytes(data: &[u8]) -> Vec<Byte32> {
        let mut len = data.len() / 32;
        if data.len() % 32 != 0 {
            len += 1;
        }
        let mut out = vec![0_u8; len * 32];
        out[len * 32 - data.len()..].copy_from_slice(data);
        let ptr = out.as_ptr() as *const Byte32;
        unsafe { std::slice::from_raw_parts(ptr, len) }.to_owned()
    }
}

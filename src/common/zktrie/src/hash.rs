use std::prelude::v1::*;

use core::cmp::Ordering;
use eth_types::{SH256, SU256, U256};
use num_bigint::BigInt;
use std::sync::Arc;

use crate::{reverse_byte_order, Byte32};

pub const HASH_DOMAIN_ELEMS_BASE: usize = 256;
pub const HASH_DOMAIN_BYTE32: usize = 2 * HASH_DOMAIN_ELEMS_BASE;
pub const HASH_BYTE_LEN: usize = 32;

lazy_static::lazy_static! {
    pub static ref Q: SU256 = {
        let val = U256::from_str_radix("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10).unwrap();
        val.into()
    };
    pub static ref Q_BIG: BigInt = to_bigint(&Q);
    pub static ref ZERO: Arc<Hash> = Arc::new(Hash::default());
}

pub fn copy_truncated(dst: &mut [u8], src: &[u8]) {
    if dst.len() >= src.len() {
        dst[..src.len()].copy_from_slice(src);
    } else {
        dst.copy_from_slice(&src[..dst.len()])
    }
}

pub fn from_bigint(val: &BigInt) -> SU256 {
    let (_, bytes) = val.to_bytes_be();
    SU256::from_big_endian(&bytes)
}

pub fn to_bigint(val: &SU256) -> BigInt {
    let mut bytes = [0_u8; 32];
    val.to_big_endian(&mut bytes);
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes)
}

pub trait HashScheme {
    fn hash_scheme(list: &[SU256], val: &SU256) -> SU256;
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Copy, PartialOrd, Ord)]
pub struct Hash(SH256);

impl Hash {
    pub fn is_zero(&self) -> bool {
        self == ZERO.as_ref()
    }

    pub fn u256(&self) -> SU256 {
        SU256::from_big_endian(self.0.as_bytes())
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.0 .0[..]
    }

    pub fn h256(&self) -> SH256 {
        self.0
    }

    pub fn bytes(&self) -> [u8; 32] {
        let mut dst = [0_u8; 32];
        reverse_byte_order(&mut dst, self.raw_bytes());
        dst
    }
    pub fn from_bytes(b: &[u8]) -> Self {
        let mut h = Hash::default();
        copy_truncated(&mut h.0 .0, b);
        h
    }
}

impl From<Byte32> for Hash {
    fn from(v: Byte32) -> Self {
        let mut hash = Hash::default();
        reverse_byte_order(&mut hash.0 .0, v.bytes());
        hash
    }
}

impl From<[u8; 32]> for Hash {
    fn from(val: [u8; 32]) -> Self {
        Self(val.into())
    }
}

impl From<SU256> for Hash {
    fn from(val: SU256) -> Self {
        let mut hash = Hash::default();
        val.to_big_endian(&mut hash.0 .0);
        hash
    }
}

pub fn check_in_field(val: &SU256) -> bool {
    matches!(val.cmp(&Q), Ordering::Less)
}

use std::prelude::v1::*;

use crate::{Error, Node, HashScheme};

lazy_static::lazy_static!{
    pub static ref MAGIC_SMT_BYTES: &'static [u8] = b"THIS IS SOME MAGIC BYTES FOR SMT m1rRXgP2xpDI";
}

pub fn decode_smt_proofs<H: HashScheme>(buf: &[u8]) -> Result<Option<Node>, Error>{
    if MAGIC_SMT_BYTES.eq(buf) {
        return Ok(None)
    }
    Ok(Some(Node::from_bytes::<H>(buf)?))
}
use std::prelude::v1::*;

use eth_types::{BlockHeader, StateAccount, TransactionAccessTuple, SH160, SH256, SU256, HexBytes};
use std::sync::Arc;

#[derive(Debug)]
pub enum Error {
    DecodeError(rlp::DecoderError),
    CallRemoteFail(String),
}

pub trait StateDB: Send + 'static + Clone {
    // fn get_client(&self) -> &Arc<ExecutionClient>;
    fn fork(&self) -> Self;
    fn suicide(&mut self, address: &SH160) -> Result<(), Error>;
    fn get_state(&mut self, address: &SH160, index: &SH256) -> Result<SH256, Error>;
    fn exist(&mut self, address: &SH160) -> Result<bool, Error>;
    fn get_balance(&mut self, address: &SH160) -> Result<SU256, Error>;
    fn state_root(&self) -> SH256;
    fn prefetch<'a, I>(&mut self, list: I) -> Result<usize, Error>
    where
        I: Iterator<Item = &'a TransactionAccessTuple>;
    fn parent(&self) -> &Arc<BlockHeader>;
    fn flush(&mut self) -> Result<SH256, Error>;
    fn revert(&mut self, root: SH256);
    fn try_get_acc(&mut self, address: &SH160) -> Result<Option<StateAccount>, Error>;
    fn get_code(&mut self, address: &SH160) -> Result<Arc<HexBytes>, Error>;
    fn set_code(&mut self, address: &SH160, code: Vec<u8>) -> Result<(), Error>;
    fn get_nonce(&mut self, address: &SH160) -> Result<u64, Error>;
    fn set_nonce(&mut self, address: &SH160, val: SU256) -> Result<(), Error>;
    fn sub_balance(&mut self, address: &SH160, val: &SU256) -> Result<(), Error>;
    fn set_state(&mut self, address: &SH160, index: &SH256, value: SH256) -> Result<(), Error>;
    fn add_balance(&mut self, address: &SH160, val: &SU256) -> Result<(), Error>;
    fn set_balance(&mut self, address: &SH160, val: SU256) -> Result<(), Error>;
    fn export_access_list(&self, exclude_miner: Option<&SH160>) -> Vec<TransactionAccessTuple>;
    fn try_get_nonce(&mut self, address: &SH160) -> Option<u64>;
    fn get_account_basic(&mut self, address: &SH160) -> Result<(SU256, u64), Error>;
    fn get_block_hash(&self, number: SU256) -> Result<SH256, Error>;
}


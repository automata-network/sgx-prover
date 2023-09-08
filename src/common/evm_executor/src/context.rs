use super::PrecompileSet;
use eth_types::{BlockHeader, PoolTx, SH160, SU256};

#[derive(Debug, Clone)]
pub struct Context<'a> {
    pub chain_id: &'a SU256,
    pub caller: &'a SH160,
    pub cfg: &'a evm::Config,
    pub precompile: &'a PrecompileSet,
    pub tx: &'a PoolTx,
    pub header: &'a BlockHeader,
}

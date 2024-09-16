use alloy::primitives::U64;
use base::PrimitivesConvert;
use clients::{Eth, EthError};
use scroll_executor::BlockTrace;

#[derive(Clone)]
pub struct ScrollExecutionNode {
    eth: Eth,
}

impl ScrollExecutionNode {
    pub fn dial(url: &str) -> Result<Self, EthError> {
        let eth = Eth::dial(url, None)?;
        Ok(Self { eth })
    }

    pub async fn trace_block(&self, blk: u64) -> Result<BlockTrace, EthError> {
        let blk: U64 = blk.to();
        let block_trace = self
            .eth
            .client()
            .request("scroll_getBlockTraceByNumberOrHash", (blk,))
            .await?;
        Ok(block_trace)
    }
}

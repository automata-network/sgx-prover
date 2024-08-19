use std::sync::Arc;

use alloy::providers::Provider;
use alloy::{
    primitives::U64,
    providers::{ProviderBuilder, RootProvider},
    transports::http::{Client, Http},
};
use scroll_executor::BlockTrace;
// use jsonrpsee_core::{client::ClientT, ClientError};
// use jsonrpsee_http_client::HttpClient;

#[derive(Clone)]
pub struct Eth {
    client: Arc<RootProvider<Http<Client>>>,
}

impl Eth {
    pub fn new(client: Arc<RootProvider<Http<Client>>>) -> Self {
        // let provider = ProviderBuilder::new().on_http(endpoint);
        Self { client }
    }

    pub fn dial(endpoint: &str) -> Self {
        let url = endpoint.try_into().unwrap();
        let provider = ProviderBuilder::new().on_http(url);
        Self::new(Arc::new(provider))
    }

    pub async fn trace_block(&self, blk: u64) -> BlockTrace {
        let block_trace = self
            .client
            .client()
            .request("scroll_getBlockTraceByNumberOrHash", (U64::from(blk),))
            .await
            .unwrap();
        block_trace
    }
}

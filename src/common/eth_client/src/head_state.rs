use std::prelude::v1::*;

use crate::ExecutionClient;
use base::channel::Boardcast;
use base::thread::spawn;
use base::trace::Alive;
use scroll_types::{BlockHeader, BlockSimple};
use jsonrpc::{JsonrpcWsClient, RpcError, WsClientConfig, WsClientError};
use std::sync::{mpsc, Arc};
use std::time::Duration;

#[derive(Clone)]
pub struct HeadState {
    _client: Arc<JsonrpcWsClient>,
    bcast: Boardcast<Arc<BlockHeader>>,
    blk_bcast: Boardcast<Arc<BlockSimple>>,
}

impl HeadState {
    pub fn new(alive: Alive, endpoint: &str, block_time: u64) -> Result<Self, RpcError> {
        let state_client = Arc::new(
            JsonrpcWsClient::new(WsClientConfig {
                endpoint: endpoint.into(),
                ws_frame_size: 64 << 10,
                keep_alive: None,
                auto_resubscribe: true,
                poll_interval: Duration::from_millis(0),
                concurrent_bench: Some(2),
                alive: alive.clone(),
            })
            .map_err(|err| match err {
                WsClientError::InitError(msg) => RpcError::InitError(msg),
                other => unreachable!("{:?}", other),
            })?,
        );

        let blk = {
            let jsonrpc_client = ExecutionClient::new(state_client.clone());
            jsonrpc_client.get_block_simple(eth_types::BlockSelector::Latest)?
        };

        let head_bcast = Boardcast::new_with(Arc::new(blk.header.clone()));
        let blk_bcast = Boardcast::new_with(Arc::new(blk));
        spawn("head-subscriber".into(), {
            let subscribe_timeout = Duration::from_secs(block_time) * 2;
            let sub = state_client
                .subscribe("eth_subscribe", "eth_unsubscribe", ["newHeads"])
                .map_err(|err| RpcError::InitError(format!("{:?}", err)))?;
            let bcast = head_bcast.clone();
            move || {
                loop {
                    let head: BlockHeader = match sub.must_recv_within(subscribe_timeout) {
                        Ok(item) => item,
                        Err(_) => break,
                    };
                    let head = Arc::new(head);
                    glog::info!("new block: [{}]", head.number);
                    bcast.boardcast(head);
                }

                bcast.clean();
            }
        });
        spawn("blk-subscriber".into(), {
            let blk_bcast = blk_bcast.clone();
            let receiver = head_bcast.new_subscriber();
            let alive = alive.clone();
            let poll = Duration::from_secs(1);
            let el = ExecutionClient::new(state_client.clone());
            move || {
                for new_head in alive.recv_iter(&receiver, poll) {
                    if blk_bcast.len() == 0 {
                        continue;
                    }
                    match el.get_block_simple(new_head.number.into()) {
                        Ok(n) => blk_bcast.boardcast(Arc::new(n)),
                        Err(err) => {
                            glog::error!("get block simple fail: {:?}", err);
                        }
                    }
                }
                blk_bcast.clean();
            }
        });
        Ok(Self {
            _client: state_client,
            bcast: head_bcast,
            blk_bcast,
        })
    }

    pub fn subscribe_new_head(&self) -> mpsc::Receiver<Arc<BlockHeader>> {
        self.bcast.new_subscriber()
    }

    pub fn subscribe_new_block(&self) -> mpsc::Receiver<Arc<BlockSimple>> {
        self.blk_bcast.new_subscriber()
    }

    pub fn el(&self) -> ExecutionClient<Arc<JsonrpcWsClient>> {
        ExecutionClient::new(self._client.clone())
    }

    pub fn get(&self) -> Arc<BlockHeader> {
        self.bcast.get_latest().unwrap()
    }

    pub fn get_block(&self) -> Arc<BlockSimple> {
        self.blk_bcast.get_latest().unwrap()
    }
}

use base::trace::Alive;
use eth_tools::{EthLogSubscriber, ExecutionClient, LogFilter, RpcClient, RpcError};
use eth_types::{Log, SH160, SH256, SU256};


#[derive(Clone, Debug)]
pub struct BatchTask {
    pub data_hash: SH256,
    pub blocks: Vec<u64>,
}

pub struct BatchTaskSubscriber<C: RpcClient> {
    subscriber: EthLogSubscriber<C>,
    cfg: BatchTaskSubscriberConfig,
}

pub struct BatchTaskSubscriberConfig {
    pub tag: String,
    pub contract: SH160,
    pub max_block: u64,
    pub wait_block: u64,
}

impl<C> BatchTaskSubscriber<C>
where
    C: RpcClient + Clone + Send + 'static,
{
    pub fn new(alive: Alive, cfg: BatchTaskSubscriberConfig, el: ExecutionClient<C>) -> Self {
        let subscriber = EthLogSubscriber::new(alive, el, cfg.max_block, cfg.wait_block);
        Self { subscriber, cfg }
    }

    pub fn subscribe<F>(&self, f: F) -> Result<(), RpcError>
    where
        F: Fn(BatchTask),
    {
        let filter = LogFilter {
            address: vec![self.cfg.contract],
            topics: vec![vec![solidity::encode_eventsig(
                "DataSubmitted(bytes32,uint256,uint256)",
            )]],
            ..Default::default()
        };
        let handler = |block, logs: Vec<Log>| {
            let mut task = BatchTask {
                data_hash: SH256::default(),
                blocks: Vec::new(),
            };
            let mut tmp_tx = None;
            for log in logs {
                let current_tx = match tmp_tx {
                    Some(hash) => hash,
                    None => {
                        tmp_tx = Some(log.transaction_hash);
                        log.transaction_hash
                    }
                };
                let start_block: SU256 = (&log.topics[2]).into();
                let end_block: SU256 = (&log.topics[3]).into();
                if log.transaction_hash != current_tx {
                    task = BatchTask {
                        data_hash: log.topics[1],
                        blocks: (start_block.as_u64()..=end_block.as_u64()).collect(),
                    };
                    tmp_tx = Some(log.transaction_hash);
                } else {
                    task.data_hash = log.topics[1];
                    task.blocks = (start_block.as_u64()..=end_block.as_u64()).collect();
                }
            }
            f(task);
            Ok(())
        };

        self.subscriber
            .subscribe(&self.cfg.tag, 0, filter, handler)
    }
}

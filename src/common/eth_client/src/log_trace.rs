use std::prelude::v1::*;

use crate::{ExecutionClient, LogFilter};
use base::trace::Alive;
use eth_types::Log;
use jsonrpc::{RpcClient, RpcError};

pub struct LogTrace<C: RpcClient> {
    el: ExecutionClient<C>,
    alive: Alive,
    max: u64,
    wait: u64,
}

impl<C: RpcClient> LogTrace<C> {
    pub fn new(alive: Alive, el: ExecutionClient<C>, max: u64, wait: u64) -> Self {
        Self {
            el,
            alive,
            max,
            wait,
        }
    }

    pub fn subscribe<F>(
        &self,
        tag: &str,
        mut start: u64,
        mut filter: LogFilter,
        f: F,
    ) -> Result<(), RpcError>
    where
        F: Fn(Vec<Log>) -> Result<(), String>,
    {
        let mut head = self.el.head()?.as_u64() - self.wait;

        if start > head || start == 0 {
            glog::warn!(
                "[{}]incorrect start offset={}, head={}, reset to head",
                tag,
                start,
                head
            );
            start = head;
        }

        while self.alive.is_alive() {
            head = match self.el.head() {
                Ok(head) => head.as_u64() - self.wait,
                Err(err) => {
                    glog::error!("fetch head fail: {:?}, retry in 1 secs...", err);
                    self.alive.sleep_ms(1000);
                    continue;
                }
            };

            if start >= head {
                self.alive.sleep_ms(4000);
                continue;
            }

            let mut end = head;
            if end - start > self.max {
                end = start + self.max;
            }

            filter.from_block = Some(start.into());
            filter.to_block = Some(end.into());

            let logs = match self.el.get_logs(&filter) {
                Ok(logs) => logs,
                Err(err) => {
                    glog::error!(
                        "[{}-{}] fetch logs fail: {:?} => {:?}",
                        start,
                        end,
                        filter,
                        err
                    );
                    self.alive.sleep_ms(4000);
                    continue;
                }
            };
            if logs.len() > 0 {
                match f(logs) {
                    Ok(_) => {}
                    Err(err) => {
                        glog::error!("[{}-{}] process logs fail => {:?}", start, end, err);
                        self.alive.sleep_ms(4000);
                        continue;
                    }
                }
            }
            glog::info!("[{}] finish scan to {} -> {}", tag, start, end);
            start = end + 1;
        }
        Ok(())
    }
}

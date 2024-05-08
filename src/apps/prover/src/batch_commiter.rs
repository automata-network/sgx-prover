use core::time::Duration;
use std::prelude::v1::*;

use base::{format::debug, trace::Alive};
use eth_client::LogFilter;
use eth_client::{ExecutionClient, LogTrace};
use eth_types::SU256;
use jsonrpc::MixRpcClient;
use scroll_types::{BatchTask, Poe};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::{mpsc, Arc, Mutex};

use crate::ScrollChain;

pub struct TaskManager {
    tasks: Mutex<(BTreeMap<BatchTask, TaskContext>, Vec<BatchTask>)>,
    cap: usize,
}

impl TaskManager {
    pub fn new(cap: usize) -> TaskManager {
        Self {
            tasks: Mutex::new((BTreeMap::new(), Vec::new())),
            cap,
        }
    }

    fn add_task(&self, task: BatchTask) -> Option<TaskContext> {
        let mut tasks = self.tasks.lock().unwrap();
        let result = match tasks.0.entry(task.clone()) {
            Entry::Occupied(entry) => Some(entry.get().clone()),
            Entry::Vacant(entry) => {
                entry.insert(TaskContext { result: None });
                tasks.1.push(task);
                None
            }
        };
        while tasks.1.len() > self.cap {
            let task = tasks.1.remove(0);
            tasks.0.remove(&task);
        }
        result
    }

    pub fn process_task(&self, task: BatchTask) -> Option<Result<Poe, String>> {
        let alive = Alive::new();
        let alive = alive.fork_with_timeout(Duration::from_secs(120));

        while alive.is_alive() {
            match self.add_task(task.clone()) {
                Some(tc) => match tc.result {
                    Some(poe) => return Some(poe),
                    None => {
                        glog::info!("polling task result: {:?}", task);
                        alive.sleep_ms(5000);
                        continue;
                    }
                },
                None => return None,
            }
        }
        None
    }

    pub fn update_task(&self, task: BatchTask, poe: Result<Poe, String>) -> bool {
        let mut tasks = self.tasks.lock().unwrap();
        match tasks.0.entry(task) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().result = Some(poe);
                true
            }
            Entry::Vacant(entry) => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TaskContext {
    pub result: Option<Result<Poe, String>>,
}

#[derive(Debug, Clone)]
pub struct BatchCommiter {
    alive: Alive,
    cfg: ScrollChain,
}

impl BatchCommiter {
    pub fn new(alive: &Alive, cfg: ScrollChain) -> Self {
        Self {
            alive: alive.clone(),
            cfg,
        }
    }

    pub fn run(&self) -> Result<mpsc::Receiver<BatchTask>, String> {
        let (sender, receiver) = mpsc::channel();
        let start = 0;
        base::thread::spawn("batch monitor".into(), {
            let alive = self.alive.clone();
            let cfg = self.cfg.clone();
            let mut client = MixRpcClient::new(Some(Duration::from_secs(60)));
            client
                .add_endpoint(&alive, &[cfg.endpoint.clone()])
                .map_err(debug)?;
            move || {
                let client = ExecutionClient::new(Arc::new(client));
                let log_trace =
                    LogTrace::new(alive.clone(), client.clone(), cfg.max_block, cfg.wait_block);
                let topic = solidity::encode_eventsig("CommitBatch(uint256,bytes32)");
                let filter = LogFilter {
                    address: vec![cfg.contract],
                    topics: vec![vec![topic]],
                    ..Default::default()
                };
                log_trace
                    .subscribe("BatchCommiter", start, filter, |logs| {
                        'nextLog: for log in logs {
                            let batch_id = SU256::from_big_endian(log.topics[1].as_bytes());
                            let batch_hash = log.topics[2];
                            let tx = client
                                .get_transaction(&log.transaction_hash)
                                .map_err(debug)?;
                            let task = match BatchTask::from_calldata(
                                batch_id,
                                batch_hash,
                                &tx.input[4..],
                            ) {
                                Ok(task) => task,
                                Err(_) => continue 'nextLog,
                            };
                            let _ = sender.send(task);
                        }
                        Ok(())
                    })
                    .unwrap();
            }
        });
        Ok(receiver)
    }
}

use std::{prelude::v1::*, sync::Mutex};

use base::thread::spawn;
use base::trace::{Alive, Counter};
use eth_types::{Bundle, PoolTx, Signer};
use jsonrpc::{JsonrpcWsClient, WsClientConfig};
use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::Duration;

use crate::HashPool;

#[derive(Debug)]
pub enum MempoolItem {
    Seq(PoolTx),
    Price(PoolTx),
    Bundle(Bundle),
}

impl MempoolItem {
    pub fn pool_tx(&self) -> Option<&PoolTx> {
        match self {
            MempoolItem::Seq(tx) | MempoolItem::Price(tx) => Some(tx),
            MempoolItem::Bundle(_) => None,
        }
    }
}

pub struct TxFetcher {
    alive: Alive,
    signer: Signer,
    hash_pool: HashPool,
    receiver: Mutex<Option<mpsc::Receiver<MempoolItem>>>,
    exts: BTreeMap<&'static str, Box<dyn Fn() -> Box<dyn TxFetcherExtension> + Sync + Send>>,
}

impl TxFetcher {
    pub fn new(alive: Alive, signer: Signer, hash_pool: HashPool) -> Self {
        let mut fetcher = Self {
            alive: alive.clone(),
            signer,
            hash_pool,
            receiver: Default::default(),
            exts: BTreeMap::new(),
        };

        fetcher.add_ext("with-hash", ext::WithHash::new);
        fetcher.add_ext("with-body", || {
            ext::WithBody::new(("newPendingTransactions", true))
        });
        fetcher.add_ext("alchemy", || {
            ext::WithBody::new(("alchemy_pendingTransactions",))
        });
        fetcher.add_ext("self-hosted", ext::SelfHosted::new);
        fetcher
    }

    pub fn recv_iter<F>(&self, poll: Duration, f: F)
    where
        F: Fn(MempoolItem),
    {
        let receiver = self.receiver.lock().unwrap();
        let receiver = receiver.as_ref().expect("should start txFetcher first");
        for item in self.alive.recv_iter(receiver, poll) {
            f(item)
        }
    }

    pub fn add_ext<F>(&mut self, name: &'static str, f: F)
    where
        F: Fn() -> Box<dyn TxFetcherExtension> + 'static + Sync + Send,
    {
        self.exts.insert(name, Box::new(f));
    }

    pub fn start(&mut self, endpoints: BTreeMap<String, String>) -> Result<(), String> {
        let (sender, receiver) = mpsc::channel();
        let mut counters = BTreeMap::new();
        for (endpoint, scope) in endpoints {
            if !endpoint.starts_with("ws") {
                return Err(format!("unsupport non-ws endpoint: {}", endpoint));
            }
            let ext = match self.exts.get(scope.as_str()) {
                Some(ext) => ext(),
                None => {
                    return Err(format!("unknown scope for {}", scope));
                }
            };
            let cfg = ext.get_config(self.alive.fork(), endpoint.clone());
            let client = JsonrpcWsClient::new(cfg)
                .map_err(|err| format!("connect to {:?} fail: {:?}", endpoint, err))?;
            let counter = Counter::new();
            counters.insert(client.tag.clone(), counter.clone());

            let ctx = TxFetcherExtensionContext {
                signer: self.signer.clone(),
                client,
                hash_pool: self.hash_pool.clone(),
                counter,
                sender: sender.clone(),
                alive: self.alive.clone(),
            };
            ext.run_in_background(ctx);
        }

        base::thread::spawn("tx-client-stat".into(), {
            let alive = self.alive.clone();
            let counter = counters.clone();
            move || loop {
                use std::fmt::Write;
                if !alive.sleep_ms(1000) {
                    break;
                }
                let mut stat = "".to_owned();
                let mut total = 0;
                for k in &counter {
                    let val = k.1.take();
                    total += val;
                    write!(stat, "[{}] {} tx/secs, ", k.0, val).unwrap();
                }
                glog::info!("tx-client stat: {} tx/secs, ({})", total, stat);
            }
        });

        *self.receiver.lock().unwrap() = Some(receiver);

        Ok(())
    }
}

#[derive(Clone)]
pub struct TxFetcherExtensionContext {
    pub alive: Alive,
    pub client: JsonrpcWsClient,
    pub hash_pool: HashPool,
    pub counter: Counter,
    pub sender: mpsc::Sender<MempoolItem>,
    pub signer: Signer,
}

pub trait TxFetcherExtension: Send + Sync {
    fn get_config(&self, alive: Alive, endpoint: String) -> WsClientConfig {
        self.default_config(alive, endpoint)
    }

    fn default_config(&self, alive: Alive, endpoint: String) -> WsClientConfig {
        WsClientConfig {
            endpoint,
            ws_frame_size: 64 << 10,
            keep_alive: None,
            auto_resubscribe: true,
            poll_interval: Duration::from_millis(0),
            concurrent_bench: None,
            alive,
        }
    }
    fn run_in_background(&self, ctx: TxFetcherExtensionContext);
}

pub mod ext {
    use eth_types::{HexBytes, PoolTx, Transaction, SH256};
    use jsonrpc::{Batchable, JsonrpcRawRequest, JsonrpcResponseRawResult};
    use serde::Serialize;
    use serde_json::BoxRawValue;

    use super::*;

    #[derive(Clone)]
    pub struct WithHash {}

    impl WithHash {
        pub fn new() -> Box<dyn TxFetcherExtension> {
            Box::new(WithHash {})
        }
    }

    impl TxFetcherExtension for WithHash {
        fn run_in_background(&self, ctx: TxFetcherExtensionContext) {
            let name = ctx.client.tag.clone();
            let (tx_sender, tx_receiver) = mpsc::channel();
            spawn(format!("subscribe-ptx-{}", name), {
                let hash_pool = ctx.hash_pool.clone();
                let pending_tx_sub = ctx
                    .client
                    .subscribe(
                        "eth_subscribe",
                        "eth_unsubscribe",
                        &("newPendingTransactions",),
                    )
                    .unwrap();
                move || {
                    let client = ctx.client;
                    loop {
                        let hash: SH256 = match pending_tx_sub.recv() {
                            Ok(n) => n,
                            Err(err) => {
                                glog::error!("err: {:?}", err);
                                break;
                            }
                        };
                        if hash_pool.exists(&hash) {
                            continue;
                        }
                        let req = JsonrpcRawRequest::new(0, "eth_getTransactionByHash", &(hash,))
                            .unwrap();
                        let _ = client.jsonrpc_async_sender(
                            req.into(),
                            Box::new(()),
                            tx_sender.clone(),
                        );
                    }
                }
            });
            spawn(format!("subscribe-ptx.body.{}", name), {
                let hash_pool = ctx.hash_pool.clone();
                move || loop {
                    let tx = match tx_receiver.recv() {
                        Ok(Ok((_, Batchable::Single(JsonrpcResponseRawResult::Ok(result))))) => {
                            result.result
                        }
                        Err(_) => break,
                        _ => continue,
                    };
                    let tx: Transaction = match serde_json::from_raw_value(&tx) {
                        Ok(tx) => tx,
                        Err(_) => continue,
                    };
                    let tx = match tx.inner() {
                        Some(tx) => tx,
                        None => continue,
                    };
                    let hash = tx.hash();
                    if !hash_pool.first_seen(&hash) {
                        continue;
                    }
                    glog::debug!(target: "txpool", "[{}] receive ptx {:?}", name, hash);
                    ctx.counter.add();
                    if let Err(_) = ctx
                        .sender
                        .send(MempoolItem::Price(PoolTx::with_tx(&ctx.signer, tx)))
                    {
                        break;
                    }
                }
            });
        }
    }

    pub struct WithBody {
        pub params: BoxRawValue,
    }

    impl WithBody {
        pub fn new<T>(params: T) -> Box<dyn TxFetcherExtension>
        where
            T: Serialize + std::fmt::Debug,
        {
            let params = serde_json::to_raw_value(&params).unwrap();
            Box::new(Self { params })
        }
    }

    impl TxFetcherExtension for WithBody {
        fn run_in_background(&self, ctx: TxFetcherExtensionContext) {
            let name = ctx.client.tag.clone();
            spawn(format!("subscribe-ptx-{}", name), {
                let pending_tx_sub = ctx
                    .client
                    .subscribe("eth_subscribe", "eth_unsubscribe", &self.params)
                    .unwrap();
                move || {
                    let _client = ctx.client;
                    loop {
                        let tx: Transaction = match pending_tx_sub.recv() {
                            Ok(n) => n,
                            Err(err) => {
                                glog::error!("err: {:?}", err);
                                break;
                            }
                        };
                        let tx = match tx.inner() {
                            Some(n) => n,
                            None => continue,
                        };
                        let hash = tx.hash();
                        if !ctx.hash_pool.first_seen(&hash) {
                            continue;
                        }
                        glog::debug!(target: "txpool", "[{}] receive ptx {:?}", name, hash);
                        ctx.counter.add();
                        if let Err(_) = ctx
                            .sender
                            .send(MempoolItem::Price(PoolTx::with_tx(&ctx.signer, tx)))
                        {
                            break;
                        }
                    }
                }
            });
        }
    }

    pub struct SelfHosted {}

    impl SelfHosted {
        pub fn new() -> Box<dyn TxFetcherExtension> {
            Box::new(SelfHosted {})
        }
    }

    impl TxFetcherExtension for SelfHosted {
        fn run_in_background(&self, ctx: TxFetcherExtensionContext) {
            let name = ctx.client.tag.clone();
            spawn(format!("subscribe-ptx-{}", name), {
                let pending_tx_sub = ctx
                    .client
                    .subscribe(
                        "eth_subscribe",
                        "eth_unsubscribe",
                        &("transactionWithAccessList",),
                    )
                    .unwrap();
                move || {
                    let _client = ctx.client;
                    loop {
                        let tx: HexBytes =
                            match pending_tx_sub.must_recv_within(Duration::from_secs(5)) {
                                Ok(tx) => tx,
                                Err(err) => {
                                    glog::error!("err: {:?}", err);
                                    break;
                                }
                            };
                        let tx = match PoolTx::from_bytes(&ctx.signer, &tx) {
                            Ok(n) => n,
                            Err(err) => {
                                glog::error!("{:?}", err);
                                continue;
                            }
                        };
                        if !ctx.hash_pool.first_seen(&tx.hash) {
                            continue;
                        }
                        glog::debug!(target: "txpool", "[{}] receive ptx {:?}, acl: {}", name, tx.hash, tx.access_list.len());
                        ctx.counter.add();
                        if let Err(_) = ctx.sender.send(MempoolItem::Price(tx)) {
                            break;
                        }
                    }
                }
            });
        }
    }
}

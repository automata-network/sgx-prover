use std::prelude::v1::*;

use crate::HashPool;
use base::thread::spawn;
use base::trace::{Alive, Counter};
use crypto::{Aes128Key, Sr25519PublicKey};
use eth_types::{Bundle, HexBytes, PoolTx, Signer, TimeBasedSigner, Transaction, SH256};
use jsonrpc::{
    Batchable, JsonrpcRawRequest, JsonrpcResponseRawResult, JsonrpcWsClient, WsClientConfig,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

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

pub struct TxClient {
    pub signer: Signer,
    alive: Alive,
    receiver: Mutex<mpsc::Receiver<MempoolItem>>,
    pub hash_pool: HashPool,
    pub counters: BTreeMap<String, Counter>,
}

impl TxClient {
    pub fn new(
        alive: Alive,
        signer: Signer,
        endpoints: BTreeMap<String, String>,
        hash_pool: HashPool,
        prvkey: Option<crypto::Secp256k1PrivateKey>,
    ) -> Self {
        let mut counters = BTreeMap::new();
        let (sender, receiver) = mpsc::channel();
        for (endpoint, scope) in endpoints {
            if !endpoint.starts_with("ws") {
                glog::warn!("unsupport non-ws endpoint: {}", endpoint);
                continue;
            }
            let client = JsonrpcWsClient::new(WsClientConfig {
                endpoint,
                ws_frame_size: 64 << 10,
                keep_alive: None,
                auto_resubscribe: true,
                poll_interval: Duration::from_millis(0),
                concurrent_bench: None,
                alive: alive.fork(),
            })
            .unwrap();

            let counter = Counter::new();
            counters.insert(client.tag.clone(), counter.clone());

            match scope.as_str() {
                "with-hash" => Self::with_hash(
                    signer,
                    client,
                    hash_pool.clone(),
                    sender.clone(),
                    counter.clone(),
                    ["newPendingTransactions"],
                ),
                "with-body" => Self::with_body(
                    signer,
                    client,
                    hash_pool.clone(),
                    sender.clone(),
                    counter.clone(),
                    ("newPendingTransactions", true),
                ),
                "self-hosted" => Self::with_pool_tx(
                    signer,
                    client,
                    hash_pool.clone(),
                    sender.clone(),
                    counter.clone(),
                    ["transactionWithAccessList"],
                ),
                "automata-mempool" => {
                    let prvkey = TimeBasedSigner::new(prvkey.unwrap());
                    Self::with_mempool_bundle(
                        signer,
                        client.clone(),
                        hash_pool.clone(),
                        sender.clone(),
                        counter.clone(),
                        None,
                    );
                    Self::with_mempool_tx(
                        signer,
                        client,
                        hash_pool.clone(),
                        sender.clone(),
                        counter.clone(),
                        None,
                    );
                }
                "alchemy" => Self::with_body(
                    signer,
                    client,
                    hash_pool.clone(),
                    sender.clone(),
                    counter.clone(),
                    ["alchemy_pendingTransactions"],
                ),
                other => {
                    glog::warn!("unknown scope: {}", other);
                    continue;
                }
            }
        }

        base::thread::spawn("tx-client-stat".into(), {
            let alive = alive.clone();
            let counter = counters.clone();
            move || loop {
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

        return Self {
            alive: alive.clone(),
            signer,
            hash_pool,
            receiver: Mutex::new(receiver),
            counters,
        };
    }

    pub fn recv_iter<F>(&self, poll: Duration, f: F)
    where
        F: Fn(MempoolItem),
    {
        let receiver = self.receiver.lock().unwrap();
        for item in self.alive.recv_iter(&receiver, poll) {
            f(item)
        }
    }

    pub fn receiver<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mpsc::Receiver<MempoolItem>) -> T,
    {
        let receiver = self.receiver.lock().unwrap();
        f(&receiver)
    }

    fn with_hash<T>(
        signer: Signer,
        client: JsonrpcWsClient,
        hash_pool: HashPool,
        sender: mpsc::Sender<MempoolItem>,
        counter: Counter,
        params: T,
    ) where
        T: Serialize + std::fmt::Debug,
    {
        let name = client.tag.clone();
        let (tx_sender, tx_receiver) = mpsc::channel();
        spawn(format!("subscribe-ptx-{}", name), {
            let hash_pool = hash_pool.clone();
            let pending_tx_sub = client
                .subscribe("eth_subscribe", "eth_unsubscribe", params)
                .unwrap();
            move || {
                let client = client;
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
                    let req =
                        JsonrpcRawRequest::new(0, "eth_getTransactionByHash", &(hash,)).unwrap();
                    let _ =
                        client.jsonrpc_async_sender(req.into(), Box::new(()), tx_sender.clone());
                }
            }
        });
        spawn(format!("subscribe-ptx.body.{}", name), {
            let hash_pool = hash_pool.clone();
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
                counter.add();
                if let Err(_) = sender.send(MempoolItem::Price(PoolTx::with_tx(&signer, tx))) {
                    break;
                }
            }
        });
    }

    fn with_body<T>(
        signer: Signer,
        client: JsonrpcWsClient,
        hash_pool: HashPool,
        sender: mpsc::Sender<MempoolItem>,
        counter: Counter,
        params: T,
    ) where
        T: Serialize + std::fmt::Debug,
    {
        let name = client.tag.clone();
        spawn(format!("subscribe-ptx-{}", name), {
            let pending_tx_sub = client
                .subscribe("eth_subscribe", "eth_unsubscribe", params)
                .unwrap();
            move || {
                let _client = client;
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
                    if !hash_pool.first_seen(&hash) {
                        continue;
                    }
                    glog::debug!(target: "txpool", "[{}] receive ptx {:?}", name, hash);
                    counter.add();
                    if let Err(_) = sender.send(MempoolItem::Price(PoolTx::with_tx(&signer, tx))) {
                        break;
                    }
                }
            }
        });
    }

    fn with_pool_tx<T>(
        signer: Signer,
        client: JsonrpcWsClient,
        hash_pool: HashPool,
        sender: mpsc::Sender<MempoolItem>,
        counter: Counter,
        params: T,
    ) where
        T: Serialize + std::fmt::Debug,
    {
        let name = client.tag.clone();
        spawn(format!("subscribe-ptx-{}", name), {
            let pending_tx_sub = client
                .subscribe("eth_subscribe", "eth_unsubscribe", params)
                .unwrap();
            move || {
                let _client = client;
                loop {
                    let tx: HexBytes = match pending_tx_sub.must_recv_within(Duration::from_secs(5))
                    {
                        Ok(tx) => tx,
                        Err(err) => {
                            glog::error!("err: {:?}", err);
                            break;
                        }
                    };
                    let tx = match PoolTx::from_bytes(&signer, &tx) {
                        Ok(n) => n,
                        Err(err) => {
                            glog::error!("{:?}", err);
                            continue;
                        }
                    };
                    if !hash_pool.first_seen(&tx.hash) {
                        continue;
                    }
                    glog::debug!(target: "txpool", "[{}] receive ptx {:?}, acl: {}", name, tx.hash, tx.access_list.len());
                    counter.add();
                    if let Err(_) = sender.send(MempoolItem::Price(tx)) {
                        break;
                    }
                }
            }
        });
    }

    fn with_mempool_bundle(
        signer: Signer,
        client: JsonrpcWsClient,
        hash_pool: HashPool,
        sender: mpsc::Sender<MempoolItem>,
        counter: Counter,
        key: Option<(Sr25519PublicKey, Aes128Key)>,
    ) {
        let name = client.tag.clone();
        spawn(format!("subscribe-ptx-{}", name), {
            move || {
                let client = mempool::Client::new(client, signer.clone(), key);
                let pending_tx_sub = client.subscribe_bundle().unwrap();
                loop {
                    let bundle = match pending_tx_sub.must_recv_within(Duration::from_secs(300)) {
                        Ok(tx) => tx,
                        Err(err) => {
                            glog::error!("err: {:?}", err);
                            break;
                        }
                    };
                    let bundle = match Bundle::from_rlp(&signer, bundle) {
                        Ok(n) => n,
                        Err(err) => {
                            glog::error!("{:?}", err);
                            continue;
                        }
                    };
                    let hash = bundle.hash();
                    if !hash_pool.first_seen(&hash) {
                        continue;
                    }
                    glog::debug!(target: "txpool", "[{}] receive bundle {:?}, len: {}", name, hash, bundle.txs.len());
                    counter.add();
                    if let Err(_) = sender.send(MempoolItem::Bundle(bundle)) {
                        break;
                    }
                }
            }
        });
    }

    fn with_mempool_tx(
        signer: Signer,
        client: JsonrpcWsClient,
        hash_pool: HashPool,
        sender: mpsc::Sender<MempoolItem>,
        counter: Counter,
        key: Option<(Sr25519PublicKey, Aes128Key)>,
    ) {
        let name = client.tag.clone();
        spawn(format!("subscribe-ptx-{}", name), {
            move || {
                let client = mempool::Client::new(client, signer.clone(), key);
                let txs = client.get_transaction().unwrap();
                for tx in txs {
                    if let Err(_) = sender.send(MempoolItem::Seq(tx)) {
                        break;
                    }
                }
                let pending_tx_sub = client.subscribe_tx().unwrap();
                loop {
                    let tx = match pending_tx_sub.must_recv_within(Duration::from_secs(300)) {
                        Ok(tx) => tx,
                        Err(err) => {
                            glog::error!("err: {:?}", err);
                            break;
                        }
                    };
                    let tx = match PoolTx::from_rlp(&signer, tx) {
                        Ok(n) => n,
                        Err(err) => {
                            glog::error!("{:?}", err);
                            continue;
                        }
                    };
                    if !hash_pool.first_seen(&tx.hash) {
                        continue;
                    }
                    glog::debug!(target: "txpool", "[{}] receive bundle {:?}, acl: {}", name, tx.hash, tx.access_list.len());
                    counter.add();
                    if let Err(_) = sender.send(MempoolItem::Seq(tx)) {
                        break;
                    }
                }
            }
        });
    }
}

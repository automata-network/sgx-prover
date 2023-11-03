use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::time::Duration;
use std::prelude::v1::*;

use base::time::Time;
use base::trace::Alive;
use crypto::Secp256k1PrivateKey;
use eth_types::{BlockSelector, HexBytes, Receipt, TransactionInner, SH256};
use eth_types::{LegacyTx, SH160, SU256};
use jsonrpc::{RpcClient, RpcError};
use scroll_types::Transaction;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::{mpsc, Arc};

use crate::ExecutionClient;

#[derive(Debug, Clone)]
pub struct TransactionArg {
    pub to: Option<SH160>,
    pub value: SU256,
    pub data: HexBytes,
}

impl TransactionArg {
    pub fn to_legacy(
        &self,
        sender: &TxSenderAccount,
        nonce: SU256,
        gas_price: SU256,
        gas_limit: SU256,
    ) -> TransactionInner {
        let mut tx = TransactionInner::Legacy(LegacyTx {
            nonce: nonce.as_u64().into(),
            gas: gas_limit.as_u64().into(),
            gas_price,
            to: self.to.into(),
            value: self.value,
            data: self.data.clone(),
            ..Default::default()
        });
        tx.sign(&sender.signer, sender.chain_id);
        tx
    }
}

#[derive(Debug, Clone)]
pub struct TxSender<C: RpcClient> {
    alive: Alive,
    chain_id: u64,
    el: ExecutionClient<C>,
    senders: Arc<Mutex<BTreeMap<SH160, Arc<TxSenderAccount>>>>,
    mempool: Arc<Mutex<BTreeMap<SH160, BTreeMap<usize, MempoolTx>>>>,
    seq: Arc<AtomicUsize>,
    timeout: Duration,
    started: Arc<AtomicBool>,
}

impl<C: RpcClient + Clone + Send + 'static> TxSender<C> {
    pub fn new(alive: &Alive, chain_id: u64, el: ExecutionClient<C>, timeout: Duration) -> Self {
        let sender = Self {
            alive: alive.clone(),
            chain_id,
            el,
            senders: Default::default(),
            seq: Arc::new(AtomicUsize::new(0)),
            mempool: Default::default(),
            started: Default::default(),
            timeout,
        };
        base::thread::spawn("TxSender".into(), {
            let sender = sender.clone();
            move || {
                sender.run();
            }
        });
        sender
    }

    fn get_sender_by_acc(&self, acc: &SH160) -> Option<Arc<TxSenderAccount>> {
        let senders = self.senders.lock().unwrap();
        senders.get(acc).cloned()
    }

    fn get_sender(&self, signer: &Secp256k1PrivateKey) -> Result<Arc<TxSenderAccount>, RpcError> {
        let mut senders = self.senders.lock().unwrap();
        let addr: SH160 = signer.public().eth_accountid().into();
        let sender = match senders.entry(addr.clone()) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let nonce = self.el.nonce(&addr, BlockSelector::Latest)?;
                let nonce_mgr = NonceManager::new(nonce.into());
                entry
                    .insert(Arc::new(TxSenderAccount {
                        acc: addr,
                        chain_id: self.chain_id,
                        signer: signer.clone(),
                        nonce_mgr,
                    }))
                    .clone()
            }
        };
        Ok(sender)
    }

    fn estimate_gas(&self, sender: &SH160, tx: &TransactionArg) -> Result<SU256, RpcError> {
        let tx = Transaction {
            from: Some(*sender),
            input: tx.data.clone(),
            to: tx.to,
            value: tx.value,
            ..Default::default()
        };
        let gas = self.el.estimate_gas(&tx, BlockSelector::Latest)?;
        Ok(gas)
    }

    fn gas_price(&self) -> Result<SU256, RpcError> {
        self.el.gas_price()
    }

    pub fn send(
        &self,
        signer: &Secp256k1PrivateKey,
        to: Option<SH160>,
        value: SU256,
        data: HexBytes,
    ) -> Result<TxReceipt, RpcError> {
        if !self.started.load(Ordering::SeqCst) {
            return Err(RpcError::InitError("TxSender not inited".into()));
        }
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let sender = self.get_sender(signer)?;
        let tx = Arc::new(TransactionArg {
            to: to.into(),
            value,
            data,
        });

        let gas_limit = self.estimate_gas(&sender.acc, &tx)?;
        let gas_price = self.gas_price()?;
        let nonce = sender.nonce_mgr.new_nonce();

        let hash = self.el.send_raw_transaction(&tx.to_legacy(
            &sender,
            nonce.nonce,
            gas_price,
            gas_limit.clone(),
        ))?;

        let (status_sender, status_receiver) = mpsc::sync_channel(1);

        let mut mempool = self.mempool.lock().unwrap();
        let user_txs = mempool
            .entry(sender.acc.clone())
            .or_insert_with(|| BTreeMap::new());
        user_txs.insert(
            seq,
            MempoolTx {
                tx: tx.clone(),
                nonce: nonce.nonce.clone(),
                status: MempoolTxStatus::Sent((hash, None)),
                sender: status_sender,
                send_time: Time::now(),
                last_check: Time::now(),
                tx_hashes: vec![],
                gas_limit,
            },
        );
        nonce.commit();

        Ok(TxReceipt {
            addr: sender.acc,
            seq,
            receiver: status_receiver,
            status: TxReceiptStatus::Sent((hash, None)),
        })
    }

    fn remove_tx_notify(&self, acc: &SH160, seq: usize, status: TxReceiptStatus) {
        if let Some(tx) = self.remove_tx(acc, seq) {
            let _ = tx.sender.send(status);
        }
    }

    fn remove_tx(&self, acc: &SH160, seq: usize) -> Option<MempoolTx> {
        let mut mempool = self.mempool.lock().unwrap();
        let sender_txs = mempool.get_mut(acc)?;
        sender_txs.remove(&seq)
    }

    fn peek_tx(&self, acc: &SH160, start_seq: usize) -> Option<(usize, MempoolTx)> {
        let mempool = self.mempool.lock().unwrap();
        let user_txs = mempool.get(acc)?;
        for (seq, tx) in user_txs {
            if *seq >= start_seq {
                return Some((*seq, tx.clone()));
            }
        }
        return None;
    }

    fn mut_tx<F>(&self, acc: &SH160, seq: usize, f: F) -> bool
    where
        F: FnOnce(&mut MempoolTx),
    {
        let mut mempool = self.mempool.lock().unwrap();
        let sender_txs = match mempool.get_mut(acc) {
            Some(tx) => tx,
            None => return false,
        };
        match sender_txs.get_mut(&seq) {
            Some(tx) => f(tx),
            None => return false,
        }
        return true;
    }

    fn senders(&self) -> Vec<SH160> {
        let senders = self.senders.lock().unwrap();
        senders.keys().cloned().collect()
    }

    fn get_any_receipt(&self, hashes: &[SH256]) -> Result<Option<Receipt>, RpcError> {
        for hash in hashes {
            match self.el.get_receipt(hash)? {
                Some(receipt) => return Ok(Some(receipt)),
                None => continue,
            }
        }
        return Ok(None);
    }

    fn run(&self) {
        self.started.store(true, Ordering::SeqCst);
        'nextLoop: while self.alive.is_alive() {
            self.alive.sleep_ms(1000);

            let senders = self.senders();
            let mut updated = false;
            let sec = Duration::from_secs(1);

            'nextSender: for acc in senders {
                let mut start_seq = 0;
                'nextTx: while self.alive.is_alive() {
                    let (seq, tx) = match self.peek_tx(&acc, start_seq) {
                        Some(tx) => tx,
                        None => continue 'nextSender,
                    };
                    start_seq = seq + 1;
                    updated = true;

                    match tx.status {
                        MempoolTxStatus::Sent((hash, _)) => {
                            if Time::now() < tx.last_check + sec {
                                continue 'nextTx;
                            }
                            glog::info!(
                                "checking tx receipt: {:?}, live_time: {:?}",
                                hash,
                                Time::now().checked_sub_time(&tx.send_time)
                            );
                            let mut hashes = vec![];
                            hashes.extend_from_slice(&tx.tx_hashes);
                            hashes.push(hash);

                            let result = self.get_any_receipt(&hashes);
                            self.mut_tx(&acc, seq, |tx| tx.last_check = Time::now());

                            match result {
                                Ok(Some(receipt)) => {
                                    self.mut_tx(&acc, seq, |tx| {
                                        tx.status = MempoolTxStatus::Confirmed(receipt.clone())
                                    });
                                    let _ = tx.sender.send(TxReceiptStatus::Confirmed(receipt));
                                }
                                Ok(None) => {
                                    if Time::now() - tx.send_time > self.timeout {
                                        glog::info!("tx[{:?}] timeout, try resend", hash);
                                        // timeout, resend
                                        let sender = match self.get_sender_by_acc(&acc) {
                                            Some(sender) => sender,
                                            None => {
                                                let _ = self.remove_tx(&acc, seq);
                                                continue 'nextSender;
                                            }
                                        };

                                        let gas_price = match self.gas_price() {
                                            Ok(gas_price) => gas_price,
                                            Err(err) => {
                                                glog::error!("fetch gas price fail: {:?}", err);
                                                self.alive.sleep_ms(1000);
                                                continue 'nextLoop;
                                            }
                                        };
                                        let gas_price =
                                            gas_price * SU256::from(120) / SU256::from(100);

                                        let gas_limit = match self.estimate_gas(&acc, &tx.tx) {
                                            Ok(gas_limit) => gas_limit,
                                            Err(err) => {
                                                glog::info!(
                                                    "[tx:{:?}] estimate gas fail: {:?}",
                                                    hash,
                                                    err
                                                );
                                                tx.gas_limit
                                            }
                                        };

                                        let tx_inner = tx.tx.to_legacy(
                                            &sender,
                                            tx.nonce,
                                            gas_price,
                                            gas_limit.clone(),
                                        );
                                        match self.el.send_raw_transaction(&tx_inner) {
                                            Ok(new_hash) => {
                                                self.mut_tx(&acc, seq, |tx| {
                                                    tx.gas_limit = gas_limit;
                                                    tx.status =
                                                        MempoolTxStatus::Sent((new_hash, None));
                                                    tx.tx_hashes.push(hash); // save the old hash;
                                                });
                                                let _ = tx
                                                    .sender
                                                    .send(TxReceiptStatus::Sent((new_hash, None)));
                                            }
                                            Err(err) => {
                                                let _ = tx
                                                    .sender
                                                    .send(TxReceiptStatus::Sent((hash, Some(err))));
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    self.mut_tx(&acc, seq, |tx| {
                                        tx.status = MempoolTxStatus::Sent((
                                            hash.clone(),
                                            Some(format!("{:?}", err)),
                                        ))
                                    });
                                    let _ =
                                        tx.sender.send(TxReceiptStatus::Sent((hash, Some(err))));
                                }
                            };
                        }
                        MempoolTxStatus::Confirmed(_) => {
                            self.remove_tx_notify(&acc, seq, TxReceiptStatus::Finished);
                        }
                    }
                }
            }

            if !updated {
                self.alive.sleep_ms(6000);
            }
        }
    }
}

#[derive(Debug)]
pub struct TxSenderAccount {
    acc: SH160,
    chain_id: u64,
    signer: Secp256k1PrivateKey,
    nonce_mgr: NonceManager,
}

#[derive(Clone, Debug)]
struct MempoolTx {
    tx: Arc<TransactionArg>,
    nonce: SU256,
    sender: mpsc::SyncSender<TxReceiptStatus>,
    status: MempoolTxStatus,
    send_time: Time,
    gas_limit: SU256,
    last_check: Time,
    tx_hashes: Vec<SH256>,
}

#[derive(Clone, Debug)]
enum MempoolTxStatus {
    Sent((SH256, Option<String>)),
    Confirmed(Receipt),
}

#[derive(Debug)]
pub struct TxReceipt {
    pub addr: SH160,
    pub seq: usize,
    pub receiver: mpsc::Receiver<TxReceiptStatus>,
    pub status: TxReceiptStatus,
}

impl TxReceipt {
    pub fn wait_finished<F>(&mut self, alive: &Alive, f: F) -> Option<Receipt>
    where
        F: Fn(&TxReceipt),
    {
        if let TxReceiptStatus::Confirmed(receipt) = &self.status {
            return Some(receipt.clone());
        }
        for item in alive.recv_iter(&self.receiver, Duration::from_secs(1)) {
            if matches!(item, TxReceiptStatus::Finished) {
                break;
            }
            self.status = item;
            f(self);
        }
        if let TxReceiptStatus::Confirmed(receipt) = &self.status {
            return Some(receipt.clone());
        }
        return None;
    }
}

#[derive(Debug)]
pub enum TxReceiptStatus {
    EstimateGasError(RpcError),
    SendError(RpcError),
    Sent((SH256, Option<RpcError>)),
    Finished,
    Confirmed(Receipt),
}

#[derive(Debug)]
pub struct NonceGuard<'a> {
    mgr: &'a NonceManager,
    pub(self) committed: bool,
    nonce: SU256,
}

impl<'a> NonceGuard<'a> {
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl<'a> std::ops::Deref for NonceGuard<'a> {
    type Target = SU256;
    fn deref(&self) -> &Self::Target {
        &self.nonce
    }
}

impl<'a> Drop for NonceGuard<'a> {
    fn drop(&mut self) {
        if !self.committed {
            self.mgr.set_failed(self.nonce);
        }
    }
}

// NonceManager enables submiting transactions concurrently.
// Usage:
//  let nonce = NonceManager.new_nonce();
//  send_transaction()?; <- If it's failed, NonceManager will collect this nonce and reuse it next time.
//  NonceManager.commit(nonce);
#[derive(Debug)]
pub struct NonceManager(Mutex<InternalNonceManager>);

#[derive(Debug, PartialEq, Clone)]
struct InternalNonceManager {
    committed: SU256, // nonce we already sent to the chain
    staging: SU256,   // nonce not sure whether committed to the chain, staging should >= committed
    failed: BTreeSet<SU256>,
}

impl InternalNonceManager {
    #[allow(dead_code)]
    pub(self) fn new(committed: u64, staging: u64, failed: Vec<u64>) -> InternalNonceManager {
        let mut failed_set = BTreeSet::new();
        for item in failed {
            failed_set.insert(item.into());
        }
        InternalNonceManager {
            committed: committed.into(),
            staging: staging.into(),
            failed: failed_set,
        }
    }
}

impl NonceManager {
    pub fn new(nonce: SU256) -> NonceManager {
        NonceManager(Mutex::new(InternalNonceManager {
            committed: nonce,
            staging: nonce,
            failed: BTreeSet::new(),
        }))
    }

    #[cfg(test)]
    pub fn force_reset(&self, nonce: SU256) {
        let mut guard = self.0.lock().unwrap();
        guard.committed = nonce.clone();
        guard.staging = nonce;
        guard.failed = BTreeSet::new();
    }

    #[allow(dead_code)]
    pub(self) fn internal(&self) -> InternalNonceManager {
        let guard = self.0.lock().unwrap();
        (*guard).clone()
    }

    pub fn reset(&self, nonce: SU256) {
        let mut guard = self.0.lock().unwrap();
        let old_staging = guard.staging;
        let old_committed = guard.committed;
        if nonce >= guard.committed {
            guard.committed = nonce;
            if nonce > guard.staging {
                // | committed | staging | new_nonce |
                guard.staging = nonce;
            } else {
                // | committed | new_nonce | staging |
                // we ignore staging in this case.
            }
            let mut new_failed = BTreeSet::new();
            for entry in &guard.failed {
                if guard.committed.le(entry) {
                    new_failed.insert(entry.clone());
                }
            }
            glog::info!(
                "reset nonce from {} to {}, new failedSet: {:?}",
                old_staging,
                nonce,
                new_failed
            );
            guard.failed = new_failed;
        } else {
            // | new_nonce | committed | staging |
            // should not happen, maybe the chain has been reset?
            // or we're fetching the nonce from a out-of-sync node.
            // we ignore this case.
            glog::warn!(
                "try reset from {}/{} to {}, but we ignore this",
                old_committed,
                old_staging,
                nonce
            );
        }
    }

    fn pop_first(set: &mut BTreeSet<SU256>) -> Option<SU256> {
        let first_elem = set.iter().next().cloned();
        match first_elem {
            Some(val) => set.take(&val),
            None => None,
        }
    }

    pub fn new_nonce(&self) -> NonceGuard<'_> {
        let mut guard = self.0.lock().unwrap();
        let nonce = match Self::pop_first(&mut guard.failed) {
            Some(nonce) => nonce,
            None => {
                let nonce = guard.staging;
                guard.staging += SU256::from(1u64);
                nonce
            }
        };
        NonceGuard {
            mgr: self,
            committed: false,
            nonce,
        }
    }

    pub(self) fn set_failed(&self, nonce: SU256) {
        let mut guard = self.0.lock().unwrap();
        if nonce >= guard.committed {
            guard.failed.insert(nonce);
        }
    }
}

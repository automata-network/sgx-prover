use std::prelude::v1::*;

use base::format::parse_ether;
use base::lru::LruMap;
use base::time::{SignedDuration, Time};
use eth_types::{Block, Receipt, SH256, SU256};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::BeaconSlot;

#[derive(Clone)]
pub struct HashPool(Arc<Mutex<LruMap<SH256, HashPoolTrace>>>);
impl HashPool {
    pub fn new(pool_size: usize) -> HashPool {
        HashPool(Arc::new(Mutex::new(LruMap::new(pool_size))))
    }

    pub fn exists(&self, hash: &SH256) -> bool {
        let pool = self.0.lock().unwrap();
        pool.contains_key(hash)
    }

    pub fn get(&self, hash: &SH256) -> Option<HashPoolTrace> {
        let mut pool = self.0.lock().unwrap();
        pool.get(hash).cloned()
    }

    pub fn simulated(&self, hash: &SH256) {
        let mut pool = self.0.lock().unwrap();
        match pool.modify(hash) {
            Some(item) => {
                item.simulated = Some(Time::now());
            }
            None => {}
        }
    }

    pub fn first_seen(&self, hash: &SH256) -> bool {
        let mut pool = self.0.lock().unwrap();
        if pool.contains_key(hash) {
            return false;
        }
        pool.insert(
            hash.clone(),
            HashPoolTrace {
                first_seen: Time::now(),
                simulated: None,
            },
        );
        true
    }

    pub fn report(
        &self,
        slot: &BeaconSlot,
        blk: Block,
        receipts: Option<&[Receipt]>,
    ) -> BlockReport {
        let txs = blk
            .transactions
            .into_iter()
            .enumerate()
            .map(|(idx, item)| {
                let tx = item.inner().unwrap();
                (idx, tx.hash(), tx)
            })
            .collect::<Vec<_>>();

        let profit = match txs.last() {
            Some(tx) if tx.2.input().len() == 0 => tx.2.value(),
            _ => SU256::zero(),
        };

        let gas_useds: Vec<u64> = match receipts {
            Some(receipts) => receipts.iter().map(|r| r.gas_used.as_u64()).collect(),
            None => txs.iter().map(|tx| tx.2.gas().as_u64()).collect(),
        };

        let block_instant = Time::from_secs(blk.header.timestamp.as_u64());
        let missing_time = block_instant - Duration::from_secs(1);
        let base_fee = blk.header.base_fee_per_gas;
        let missing = {
            let hashes = self.0.lock().unwrap();
            txs.iter()
                .filter(|(_, hash, _)| match hashes.peek(hash) {
                    Some(n) => n.first_seen > missing_time,
                    None => true,
                })
                .map(|(idx, hash, _)| (*idx, hash.clone()))
                .collect::<Vec<_>>()
        };
        let missing_profit = missing
            .iter()
            .map(|(idx, _)| {
                txs[*idx]
                    .2
                    .reward(gas_useds[*idx], Some(&base_fee))
                    .unwrap()
            })
            .reduce(|a, b| a + b)
            .unwrap_or(SU256::zero());
        let txs = {
            let mut hashes = self.0.lock().unwrap();
            txs.into_iter()
                .map(|(idx, hash, tx)| (idx, hash, tx, hashes.get(&hash).cloned()))
                .collect::<Vec<_>>()
        };
        let mut tx_report = Vec::with_capacity(txs.len());
        let mut tx_fee = SU256::zero();
        for (idx, hash, tx, report) in txs {
            let mut first_seen_millis = 0;
            let mut simulated_millis = 0;
            if let Some(report) = report {
                first_seen_millis = if block_instant > report.first_seen {
                    (block_instant - report.first_seen).as_millis() as i64
                } else {
                    -((report.first_seen - block_instant).as_millis() as i64)
                };
                if let Some(simulated) = report.simulated {
                    simulated_millis = if block_instant > simulated {
                        (block_instant - simulated).as_millis() as i64
                    } else {
                        -((simulated - block_instant).as_millis() as i64)
                    }
                }
            }
            let gas_tip = tx
                .effective_gas_tip(Some(&base_fee))
                .unwrap_or(SU256::zero());
            let tip_fee = gas_tip * SU256::from(gas_useds[idx]);
            tx_fee += tip_fee;
            tx_report.push(BlockTxReport {
                hash,
                gas_tip: format!("{} Gwei", parse_ether(&gas_tip, 9)),
                gas_used: gas_useds[idx],
                tip_fee: parse_ether(&tip_fee, 18),
                first_seen_millis,
                simulated_millis,
            })
        }
        let missing_gas = missing
            .iter()
            .map(|n| gas_useds[n.0])
            .reduce(|a, b| a + b)
            .unwrap_or(0);
        BlockReport {
            number: blk.header.number.as_u64(),
            hash: blk.header.hash(),
            slot: slot.slot(blk.header.timestamp.as_u64()),
            timestamp: blk.header.timestamp.as_u64(),
            gas_used: blk.header.gas_used.as_u64(),
            gas_limit: blk.header.gas_limit.as_u64(),
            tx_fee: parse_ether(&tx_fee, 18),
            txs: tx_report,
            profit: parse_ether(&profit, 18),
            expect_profit: parse_ether(&(tx_fee.saturating_sub(*missing_profit).into()), 18),
            missing_profit: parse_ether(&missing_profit, 18),
            missing,
            expect_gas_used: blk.header.gas_used.as_u64() - missing_gas,
        }
    }
}

#[derive(Clone)]
pub struct HashPoolTrace {
    first_seen: Time,
    simulated: Option<Time>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BlockReport {
    pub number: u64,
    pub hash: SH256,
    pub slot: u64,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub timestamp: u64,
    pub txs: Vec<BlockTxReport>,
    pub missing_profit: String,
    pub missing: Vec<(usize, SH256)>,
    pub profit: String,
    pub tx_fee: String,
    pub expect_profit: String,
    pub expect_gas_used: u64,
}

impl std::fmt::Display for BlockReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "\nBLOCK: {}, slot: {}", self.number, self.slot)?;
        writeln!(f, "Timestamp: {}", self.timestamp)?;
        writeln!(
            f,
            "GasUsed: {} / {}%, expect: {} / {}%",
            self.gas_used,
            self.gas_used * 100 / self.gas_limit,
            self.expect_gas_used,
            self.expect_gas_used * 100 / self.gas_limit,
        )?;
        writeln!(
            f,
            "Offer: {}, txFee: {}, expectFee: {}",
            self.profit, self.tx_fee, self.expect_profit
        )?;
        writeln!(
            f,
            "Txs: {} (missing: {})",
            self.txs.len(),
            self.missing.len()
        )?;
        for (idx, tx) in self.txs.iter().enumerate() {
            let flag = if self.missing.iter().any(|n| n.1 == tx.hash) {
                " [M]"
            } else {
                "    "
            };
            writeln!(
                f,
                "{}[{}]: {:?} [tip:{}/{}] [time:{:?}]",
                flag,
                idx,
                tx.hash,
                tx.gas_tip,
                tx.tip_fee,
                SignedDuration::from_millis(tx.first_seen_millis),
            )?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BlockTxReport {
    hash: SH256,
    tip_fee: String,
    gas_tip: String,
    gas_used: u64,
    first_seen_millis: i64,
    simulated_millis: i64,
}

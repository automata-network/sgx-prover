use std::prelude::v1::*;

use crate::{Error, StateDB, StateFetcher};
use eth_types::{
    BlockHeader, FetchState, FetchStateResult, HexBytes, StateAccount, TransactionAccessTuple,
    SH160, SH256, SU256,
};
use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct MapStateAccount {
    pub state: StateAccount,
    pub code: Arc<HexBytes>,
    pub storage: BTreeMap<SH256, SH256>,
}

#[derive(Clone, Debug)]
pub struct MapState<F: StateFetcher> {
    fetcher: F,
    parent: Arc<BlockHeader>,
    account: BTreeMap<SH160, MapStateAccount>,
}

impl<F: StateFetcher> MapState<F> {
    pub fn new(parent: Arc<BlockHeader>, fetcher: F) -> Self {
        Self {
            fetcher,
            parent,
            account: BTreeMap::new(),
        }
    }

    pub fn with_storage<N, R>(&mut self, address: &SH160, key: &SH256, f: N) -> Result<R, Error>
    where
        N: FnOnce(&mut SH256) -> R,
    {
        let fetcher = self.fetcher.fork();
        self.with_acc(address, |acc| {
            let val = match acc.storage.entry(key.clone()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => match fetcher.get_storage(address, key) {
                    Ok(value) => entry.insert(value),
                    Err(err) => return Err(err),
                },
            };
            Ok(f(val))
        })?
    }

    pub fn with_acc<N, R>(&mut self, address: &SH160, f: N) -> Result<R, Error>
    where
        N: FnOnce(&mut MapStateAccount) -> R,
    {
        let entry = match self.account.entry(address.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let (balance, nonce, code) = self.fetcher.get_account(address)?;
                entry.insert(MapStateAccount {
                    state: StateAccount {
                        nonce,
                        balance,
                        ..Default::default()
                    },
                    code: Arc::new(code),
                    storage: BTreeMap::new(),
                })
            }
        };
        Ok(f(entry))
    }
}

impl<F: StateFetcher> StateDB for MapState<F> {
    fn add_balance(&mut self, address: &SH160, val: &SU256) -> Result<(), Error> {
        self.with_acc(address, |acc| acc.state.balance += val)
    }

    fn exist(&mut self, address: &SH160) -> Result<bool, Error> {
        self.with_acc(address, |acc| acc.state.is_exist())
    }

    fn fork(&self) -> Self {
        self.clone()
    }

    fn export_access_list(&self, exclude_miner: Option<&SH160>) -> Vec<TransactionAccessTuple> {
        let mut out = Vec::new();
        for (addr, state) in &self.account {
            let mut acl = TransactionAccessTuple::new(addr.clone());
            acl.storage_keys.reserve(state.storage.len());
            for (k, _) in &state.storage {
                acl.storage_keys.push(k.clone());
            }
            if let Some(addr) = exclude_miner {
                if &acl.address == addr && acl.storage_keys.len() == 0 {
                    continue;
                }
            }
            out.push(acl);
        }
        out
    }

    fn flush(&mut self) -> Result<SH256, Error> {
        Ok(SH256::default())
    }

    fn get_account_basic(&mut self, address: &SH160) -> Result<(SU256, u64), Error> {
        self.with_acc(address, |acc| (acc.state.balance, acc.state.nonce))
    }

    fn get_balance(&mut self, address: &SH160) -> Result<SU256, Error> {
        self.with_acc(address, |acc| acc.state.balance)
    }

    fn get_block_hash(&self, number: SU256) -> Result<SH256, Error> {
        if number.as_u64() == self.parent.number.as_u64() {
            return Ok(self.parent.hash());
        }
        self.fetcher.get_block_hash(number.as_u64())
    }

    fn get_code(&mut self, address: &SH160) -> Result<Arc<HexBytes>, Error> {
        self.with_acc(address, |acc| acc.code.clone())
    }

    fn get_nonce(&mut self, address: &SH160) -> Result<u64, Error> {
        self.with_acc(address, |acc| acc.state.nonce)
    }

    fn get_state(&mut self, address: &SH160, index: &SH256) -> Result<SH256, Error> {
        self.with_storage(address, index, |val| val.clone())
    }

    fn parent(&self) -> &Arc<BlockHeader> {
        &self.parent
    }

    fn prefetch<'a, I>(&mut self, list: I) -> Result<usize, Error>
    where
        I: Iterator<Item = &'a TransactionAccessTuple>,
    {
        let mut out = Vec::new();
        let mut duplicated = 0;
        let start = Instant::now();
        for item in list {
            let mut fetch = FetchState {
                access_list: None,
                code: None,
            };
            match self.account.get(&item.address) {
                Some(acc) => {
                    let mut item = Cow::Borrowed(item);
                    let mut new_keys = Vec::new();
                    for key in &item.storage_keys {
                        if !acc.storage.contains_key(key) {
                            new_keys.push(key.clone());
                        }
                    }
                    if new_keys.len() == 0 {
                        fetch.access_list = None;
                    } else if new_keys.len() != item.storage_keys.len() {
                        item.to_mut().storage_keys = new_keys;
                        fetch.access_list = Some(item);
                    } else {
                        fetch.access_list = Some(item);
                    }
                }
                None => {
                    fetch.code = Some(item.address);
                    fetch.access_list = Some(Cow::Borrowed(item));
                }
            }
            if fetch.get_addr().is_some() {
                match out.iter_mut().find(|item| fetch.is_match(item)) {
                    Some(item) => {
                        duplicated += 1;
                        item.merge(fetch)
                    }
                    None => out.push(fetch),
                }
            }
        }
        if out.len() > 0 {
            let result = self.fetcher.prefetch_states(&out, false)?;
            // glog::info!("prefetch: {:?}", out);
            for FetchStateResult { acc, code } in result {
                if let Some(acc) = acc {
                    let old_acc = match self.account.entry(acc.address) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) => entry.insert(MapStateAccount {
                            state: StateAccount {
                                nonce: acc.nonce.as_u64(),
                                balance: acc.balance,
                                root: acc.storage_hash,
                                code_hash: acc.code_hash,
                            },
                            code: Arc::new(code.unwrap()),
                            storage: BTreeMap::new(),
                        }),
                    };
                    for storage in acc.storage_proof {
                        let mut key = SH256::default();
                        key.0.copy_from_slice(&storage.key);
                        match old_acc.storage.entry(key) {
                            Entry::Occupied(_) => {}
                            Entry::Vacant(entry) => {
                                entry.insert(storage.value.into());
                            }
                        }
                    }
                }
            }
            glog::info!(
                exclude:"dry_run",
                "prefetch: total={:?}, duplicated={}, items={}",
                start.elapsed(),
                duplicated,
                out.len()
            );
        }
        Ok(out.len())
    }

    fn revert(&mut self, _: SH256) {
        unimplemented!()
    }

    fn set_balance(&mut self, address: &SH160, val: SU256) -> Result<(), Error> {
        self.with_acc(address, |acc| acc.state.balance = val)
    }

    fn set_code(&mut self, address: &SH160, code: Vec<u8>) -> Result<(), Error> {
        self.with_acc(address, |acc| acc.code = Arc::new(code.into()))
    }

    fn set_nonce(&mut self, address: &SH160, val: SU256) -> Result<(), Error> {
        self.with_acc(address, |acc| acc.state.nonce = val.as_u64())
    }

    fn set_state(&mut self, address: &SH160, index: &SH256, value: SH256) -> Result<(), Error> {
        self.with_storage(address, index, |val| *val = value)
    }

    fn state_root(&self) -> SH256 {
        unimplemented!()
    }

    fn sub_balance(&mut self, address: &SH160, val: &SU256) -> Result<(), Error> {
        self.with_acc(address, |acc| acc.state.balance -= val)
    }

    fn suicide(&mut self, address: &SH160) -> Result<(), Error> {
        self.with_acc(address, |acc| {
            let keys = acc.storage.keys().map(|m| m.clone()).collect::<Vec<_>>();
            for k in keys {
                acc.storage.insert(k, SH256::default());
            }
        })
    }

    fn try_get_acc(&mut self, address: &SH160) -> Result<Option<StateAccount>, Error> {
        match self.account.get(address) {
            Some(acc) => Ok(Some(acc.state.clone())),
            None => Ok(None),
        }
    }

    fn try_get_nonce(&mut self, address: &SH160) -> Option<u64> {
        match self.account.get(address) {
            Some(acc) => Some(acc.state.nonce),
            None => None,
        }
    }
}

use std::prelude::v1::*;

use core::fmt::Debug;
use eth_types::{FetchStateResult, HexBytes, StateAccount, SH160, SH256, SU256};
use statedb::{Error, MissingState};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;
use zktrie::{Database, Node, PrefixDB, Trace};

use crate::{StorageValue, Trie, TrieCache, TrieCacheCtx, ZkStateAccount, ZkTrie};

pub fn account_key(acc: &[u8]) -> SH256 {
    let hash = zktrie::hash(acc);
    hash
}

pub fn storage_slot(slot: &[u8]) -> SH256 {
    zktrie::mimc_safe(slot).unwrap()
}

type ZkTrieCache<D, K, V> = TrieCache<ZkTrie<D, V>, K, V>;
type ZkTrieCtx<'a, D, V> = TrieCacheCtx<'a, ZkTrie<D, V>, V, D>;

#[derive(Debug)]
pub struct ZkTrieState {
    db: PrefixDB,
    acc_cache: ZkTrieCache<PrefixDB, SH160, ZkStateAccount>,
    storages: BTreeMap<SH160, Box<ZkTrieCache<PrefixDB, SH256, StorageValue>>>,
}

impl ZkTrieState {
    pub fn new_from_trace(db: PrefixDB, root: SH256) -> Self {
        let acc_cache = TrieCache::new(ZkTrie::new(root));
        let storages = BTreeMap::new();
        ZkTrieState {
            db,
            acc_cache,
            storages,
        }
    }

    fn with_acc<Fn, O>(&mut self, address: &SH160, f: Fn) -> Result<O, Error>
    where
        Fn: FnOnce(ZkTrieCtx<'_, PrefixDB, ZkStateAccount>) -> O,
    {
        self.acc_cache
            .with_key(&mut self.db, address, f)
            .map_err(|err| Error::WithKey(err))
    }

    fn with_storage<Fn, O>(&mut self, address: &SH160, index: &SH256, f: Fn) -> Result<O, Error>
    where
        Fn: FnOnce(ZkTrieCtx<'_, PrefixDB, StorageValue>) -> O,
    {
        let root = self.with_acc(address, |ctx| ctx.val.root)?;
        let storage = match self.storages.entry(address.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(n) => {
                let new_trie = ZkTrie::new(root.into());
                n.insert(Box::new(TrieCache::new(new_trie)))
            }
        };
        glog::info!("acc root_hash: {:?}, {:?}", root, storage.root_hash());
        if storage.root_hash() != root {
            storage.revert(root);
        }
        // self.db.get_node(key)

        let mut storage_db = self.db.new_prefix(*address);
        let out = storage
            .with_key(&mut storage_db, index, f)
            .map_err(|err| Error::WithKey(err))?;
        if storage.is_dirty(index) {
            self.with_acc(address, |ctx| *ctx.dirty = true)?;
        }
        Ok(out)
    }
}

impl statedb::StateDB for ZkTrieState {
    type StateAccount = StateAccount;
    fn add_balance(&mut self, address: &SH160, val: &SU256) -> Result<(), Error> {
        glog::info!(
            "[MOD][BEGIN] add balance: addr={:?}, val={:?}",
            address,
            val
        );
        self.with_acc(address, |ctx| {
            *ctx.dirty = true;
            glog::info!(
                "[MOD][END] add balance: addr={:?}, val={:?}, current={:?}",
                address,
                val,
                ctx.val.balance
            );
            ctx.val.balance += val;
        })
    }

    fn apply_states(&mut self, result: Vec<FetchStateResult>) -> Result<(), Error> {
        unreachable!()
    }

    fn check_missing_state(
        &mut self,
        address: &SH160,
        storages: &[SH256],
    ) -> Result<MissingState, Error> {
        unreachable!()
    }

    fn exist(&mut self, address: &SH160) -> Result<bool, Error> {
        self.with_acc(address, |ctx| ctx.val.is_exist())
    }

    fn flush(&mut self) -> Result<SH256, Error> {
        let mut reduction_nodes = Vec::new();
        let mut storage_dirty = 0;
        let mut account_dirty = 0;
        for (addr, item) in &mut self.acc_cache.cache {
            let mut dirty = self.acc_cache.dirty.contains_key(addr);
            let mut current_storage_dirty = 0;
            if let Some(storage) = self.storages.get_mut(addr) {
                storage_dirty += storage.dirty.len();
                current_storage_dirty = storage.dirty.len();
                glog::info!("flush storage at {:?}", addr);
                let mut storage_db = self.db.new_prefix(*addr);
                if let Err(nodes) = storage.flush(&mut storage_db) {
                    if nodes.len() > 0 {
                        reduction_nodes.extend(nodes);
                        continue;
                    }
                }

                glog::info!("flush storage at {:?} to root: {:?}", addr, storage.root_hash());
                item.set_root(&mut dirty, storage.root_hash());
            }
            glog::info!(
                "addr={:?}: dirty={}, storage_dirty={}",
                addr,
                dirty,
                current_storage_dirty
            );
            if dirty {
                self.acc_cache.dirty.insert(addr.clone(), ());
            }
        }
        account_dirty += self.acc_cache.dirty.len();
        if let Err(err) = self.acc_cache.flush(&mut self.db) {
            reduction_nodes.extend(err);
        }
        assert!(reduction_nodes.len() == 0);
        Ok(self.acc_cache.root_hash())
    }

    fn fork(&self) -> Self {
        unreachable!()
    }

    fn get_account_basic(&mut self, address: &SH160) -> Result<(SU256, u64), Error> {
        glog::info!("get account basic: {:?}", address);
        self.with_acc(address, |ctx| (ctx.val.balance, ctx.val.nonce))
    }

    fn get_balance(&mut self, address: &SH160) -> Result<SU256, Error> {
        self.with_acc(address, |ctx| ctx.val.balance)
    }

    fn get_code(&mut self, address: &SH160) -> Result<Arc<HexBytes>, Error> {
        glog::info!("get code: {:?}", address);
        let (code_hash, code_size) =
            self.with_acc(address, |ctx| (ctx.val.keccak_code_hash, ctx.val.code_size))?;
        if code_size == 0 {
            return Ok(Arc::new(HexBytes::new()));
        }
        match self.db.get_code(&code_hash) {
            Some(code) => Ok(code),
            None => Err(Error::CodeNotFound(code_hash)),
        }
    }

    fn get_nonce(&mut self, address: &SH160) -> Result<u64, Error> {
        self.with_acc(address, |ctx| ctx.val.nonce)
    }

    fn get_state(&mut self, address: &SH160, index: &SH256) -> Result<SH256, Error> {
        glog::info!("[BEGIN] get state: {:?} {:?}", address, index);
        let value: SH256 = self.with_storage(address, index, |ctx| ctx.val.0)?.into();
        glog::info!("[END] get state: {:?} {:?}: {:?}", address, index, value);
        Ok(value)
    }

    fn revert(&mut self, root: SH256) {
        unreachable!()
    }

    fn set_balance(&mut self, address: &SH160, val: SU256) -> Result<(), Error> {
        glog::info!("[MOD][BEGIN] set balance: addr={:?} val={:?}", address, val);
        let value = self.with_acc(address, |ctx| {
            glog::info!(
                "[MOD][END] set balance: addr={:?} val={:?}, origin={:?}",
                address,
                val,
                ctx.val
            );
            ctx.val.set_balance(ctx.dirty, val)
        })?;

        Ok(())
    }

    fn set_code(&mut self, address: &SH160, code: Vec<u8>) -> Result<(), Error> {
        self.with_acc(address, |mut ctx| ctx.val.set_code(ctx.dirty, code, ctx.db))
    }

    fn set_nonce(&mut self, address: &SH160, val: SU256) -> Result<(), Error> {
        self.with_acc(address, |mut ctx| {
            ctx.val.set_nonce(ctx.dirty, val.as_u64())
        })
    }

    fn set_state(&mut self, address: &SH160, index: &SH256, value: SH256) -> Result<(), Error> {
        glog::info!(
            "[MOD][BEGIN] set state: addr={:?}, slot={:?}, val={:?}",
            address,
            index,
            value
        );
        self.with_storage(address, index, |ctx| {
            glog::info!(
                "[MOD][END] set state: addr={:?}, slot={:?}, val={:?}, origin={:?}",
                address,
                index,
                value,
                ctx.val,
            );
            ctx.val.set_val(ctx.dirty, value);
        })
    }

    fn state_root(&self) -> SH256 {
        unreachable!()
    }

    fn sub_balance(&mut self, address: &SH160, val: &SU256) -> Result<(), Error> {
        glog::info!(
            "[MOD][BEGIN] sub balance: addr={:?}, val={:?}",
            address,
            val
        );
        self.with_acc(address, |ctx| {
            *ctx.dirty = true;
            glog::info!(
                "[MOD][END] sub balance: addr={:?}, val={:?}, current={:?}",
                address,
                val,
                ctx.val.balance
            );
            ctx.val.balance -= val;
        })
    }

    fn suicide(&mut self, address: &SH160) -> Result<(), Error> {
        glog::info!("[MOD][BEGIN] suicide: addr={:?}", address,);
        self.with_acc(address, |ctx| ctx.val.suicide(ctx.dirty))?;
        self.storages.remove(address);
        Ok(())
    }

    fn try_get_acc(&mut self, address: &SH160) -> Result<Option<Self::StateAccount>, Error> {
        unreachable!()
    }

    fn try_get_nonce(&mut self, address: &SH160) -> Option<u64> {
        unreachable!()
    }
}

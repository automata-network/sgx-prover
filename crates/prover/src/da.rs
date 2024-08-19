use base::Time;
use core::time::Duration;
use prover_types::B256;
use serde::Deserialize;
use serde::Serialize;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

pub struct DaManager<T> {
    data: Mutex<BTreeMap<B256, DaItem<T>>>,
}

#[derive(Debug)]
pub struct DaItem<T> {
    pub raw: Option<Arc<T>>, // none: locked
    pub alive_secs: u64,
    pub dead_time: Time,
}

impl<T> DaItem<T> {
    pub fn lock(lock_time: u64) -> Self {
        let dead_time = Time::now() + Duration::from_secs(lock_time);
        Self {
            raw: None,
            alive_secs: lock_time,
            dead_time,
        }
    }

    pub fn new(raw: Arc<T>, alive_secs: u64) -> Self {
        let dead_time = Time::now() + Duration::from_secs(alive_secs);
        Self {
            raw: Some(raw),
            alive_secs,
            dead_time,
        }
    }

    pub fn touch(&mut self) {
        self.dead_time = Time::now() + Duration::from_secs(self.alive_secs);
    }

    pub fn try_lock(&mut self) -> DaItemLockStatus {
        self.touch();
        match self.raw {
            Some(_) => DaItemLockStatus::Exist,
            None => DaItemLockStatus::Failed,
        }
    }

    pub fn is_dead(&self) -> bool {
        Time::now() > self.dead_time
    }

    pub fn get(&self) -> Option<Arc<T>> {
        let raw = self.raw.as_ref()?;
        if Time::now() > self.dead_time {
            return None;
        }
        Some(raw.clone())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum DaItemLockStatus {
    Failed, // owned by other
    Locked, // owned
    Exist,  // exists
}

impl<T> DaManager<T> {
    pub fn new() -> Self {
        DaManager {
            data: Mutex::new(BTreeMap::new()),
        }
    }

    fn clean(&self, raw: &mut BTreeMap<B256, DaItem<T>>) {
        let mut keys = Vec::new();
        for (k, item) in raw.iter() {
            if item.is_dead() {
                keys.push(*k);
            }
        }
        for key in keys {
            raw.remove(&key);
        }
    }

    pub fn get(&self, hash: &B256) -> Option<Arc<T>> {
        let data = self.data.lock().unwrap();
        data.get(hash).map(|n| n.get()).flatten()
    }

    pub fn put(&self, hash: B256, raw: Arc<T>, alive_secs: u64) {
        let da_item = DaItem::new(raw.clone(), alive_secs);
        let mut data = self.data.lock().unwrap();
        let da_item = data.entry(hash).or_insert_with(|| da_item);
        if da_item.raw.is_none() {
            da_item.raw = Some(raw);
        }
        da_item.touch();

        self.clean(&mut data);
    }

    pub fn try_lock(&self, hashes: &[B256], alive_secs: u64) -> Vec<DaItemLockStatus> {
        let mut status = Vec::new();
        let mut data = self.data.lock().unwrap();
        for hash in hashes {
            match data.entry(*hash) {
                Entry::Occupied(mut entry) => {
                    status.push(entry.get_mut().try_lock());
                }
                Entry::Vacant(entry) => {
                    let _ = entry.insert(DaItem::lock(alive_secs));
                    status.push(DaItemLockStatus::Locked)
                }
            }
        }

        self.clean(&mut data);
        status
    }
}

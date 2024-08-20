use core::marker::PhantomData;
use base::format::debug;
use eth_types::{HexBytes, SH256};
use statedb::TrieUpdate;
use zktrie::{mimc_safe, trie_hash, Database, Node};

pub trait Trie: Sized {
    type DB: Database;
    type Value;
    fn root_hash(&self) -> SH256;
    fn try_get(&self, db: &mut Self::DB, key: &[u8]) -> Option<Self::Value>;
    fn get(&self, db: &mut Self::DB, key: &[u8]) -> Result<Self::Value, String>;
    fn update(
        &mut self,
        db: &mut Self::DB,
        updates: Vec<(&[u8], Option<&Self::Value>)>,
    ) -> Vec<TrieUpdate>;
    fn reset(&self, new_root: SH256) -> Self;
}

pub trait ZkTrieValue: std::fmt::Debug + Sized + Default {
    fn is_empty(&self) -> bool;
    fn encode_mimc_safe(&self) -> Vec<u8>;
    fn encode(&self) -> Vec<u8>;
    fn decode(buf: &[u8]) -> Result<Self, String>;
}

#[derive(Debug)]
pub struct ZkTrie<D: Database<Node = Node>, V: ZkTrieValue> {
    raw: zktrie::ZkTrie<D>,
    _marker: PhantomData<V>,
}

impl<D, V> ZkTrie<D, V>
where
    D: Database<Node = Node>,
    V: ZkTrieValue,
{
    pub fn new(root: SH256) -> Self {
        let t = <zktrie::ZkTrie<D>>::new(root);
        Self {
            raw: t,
            _marker: PhantomData,
        }
    }

    fn get_hkey(&self, key: &[u8]) -> Result<SH256, String> {
        Ok(match key.len() {
            20 => trie_hash(key).map_err(debug)?,
            32 => mimc_safe(key).map_err(debug)?,
            _ => unreachable!(),
        })
    }

    fn sort_updates<'a, 'b>(
        &self,
        mut updates: Vec<(&'a [u8], Option<&'b V>)>,
    ) -> Vec<(SH256, &'a [u8], Option<&'b V>)> {
        let mut new_updates = updates
            .into_iter()
            .map(|(key, b)| {
                let hkey = self.get_hkey(key).unwrap();
                (hkey, key, b)
            })
            .collect::<Vec<_>>();
        new_updates.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));
        new_updates
    }
}

impl<D, V> Trie for ZkTrie<D, V>
where
    D: Database<Node = Node>,
    V: ZkTrieValue,
{
    type DB = D;
    type Value = V;
    fn get(&self, db: &mut Self::DB, key: &[u8]) -> Result<V, String> {
        let hkey = self.get_hkey(key)?;
        let val = self
            .raw
            .read(db, hkey, key)
            .map_err(debug)?
            .unwrap_or_default();
        let val = V::decode(&val)?;
        Ok(val)
    }

    fn reset(&self, new_root: SH256) -> Self {
        ZkTrie::new(new_root)
    }

    fn root_hash(&self) -> SH256 {
        *self.raw.top_root_hash()
    }

    fn try_get(&self, db: &mut Self::DB, key: &[u8]) -> Option<V> {
        unimplemented!()
    }

    fn update(&mut self, db: &mut Self::DB, updates: Vec<(&[u8], Option<&V>)>) -> Vec<TrieUpdate> {
        let updates = self.sort_updates(updates);
        glog::info!("updates: {:?}", updates);
        let mut result = Vec::new();
        for (hkey, key, new_val) in updates {
            glog::info!(
                "update: {:?}(hkey={:?}) -> {:?}",
                HexBytes::from(key),
                hkey,
                new_val
            );
            match new_val {
                Some(new_val) if !new_val.is_empty() => {
                    let hval = trie_hash(&new_val.encode_mimc_safe()).unwrap();
                    glog::info!(
                        "new_val bytes: {:?}, mimc: {:?}, hval: {:?}",
                        HexBytes::from(new_val.encode()),
                        HexBytes::from(new_val.encode_mimc_safe()),
                        hval,
                    );
                    let value = new_val.encode();
                    self.raw.put(db, hkey, key, hval, value).unwrap()
                }
                _ => self.raw.remove(db, hkey, key).unwrap(),
            };
            glog::info!(
                "update result: root:{:?}, sub:{:?}",
                self.raw.top_root_hash(),
                self.raw.sub_root_hash(db).unwrap()
            );
            result.push(TrieUpdate::Success);
        }
        result
    }
}

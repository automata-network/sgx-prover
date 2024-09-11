use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    sync::{Arc, Mutex},
};

use alloy::primitives::{Address, Bytes, U256};
use base::PrimitivesConvert;
use linea_executor::{
    account_key, storage_slot, AccountInfo, Bytecode, CommitState, ExecutionError, ZkStateAccount,
};
use linea_revm::{db::DbAccount, DatabaseRef};
use linea_shomei::MerkleAccountProof;
use linea_zktrie::{
    mimc_safe, mimc_safe_code_hash, mimc_safe_encode, parse_prefix, trie_hash, Database, MemStore,
    PrefixDB, Trace, ZkTrie,
};
use prover_types::B256;

pub fn build_mem_db(
    traces: &[Trace],
    codes: Vec<Bytes>,
    state_proof: &[MerkleAccountProof],
) -> Result<MemStore, DBError> {
    let mut db = MemStore::from_traces(traces).map_err(DBError::BuildFromTrace())?;

    db.add_codes(codes);

    for proof in state_proof {
        let hkey = account_key(&proof.account_proof.key);
        let acc = parse_prefix(&proof.account_proof.key);
        match proof.account_proof.proof() {
            Ok(inclusion) => db
                .add_inclusion_proof(
                    Address::default(),
                    inclusion.leaf_index,
                    &proof.account_proof.key,
                    hkey,
                    inclusion.proof.value.as_ref().map(|n| n.as_ref()),
                    &inclusion.proof.proof_related_nodes,
                )
                .map_err(DBError::BuildAccInclusionProof())?,
            Err(non_inclusion) => db
                .add_non_inclusion_proof(
                    Address::default(),
                    non_inclusion.left_leaf_index,
                    non_inclusion.right_leaf_index,
                    &proof.account_proof.key,
                    hkey,
                    &non_inclusion.left_proof.proof_related_nodes,
                    &non_inclusion.right_proof.proof_related_nodes,
                )
                .map_err(DBError::BuildAccNonInclusionProof())?,
        };
        for slot_proof in &proof.storage_proofs {
            let hkey = storage_slot(&slot_proof.key);
            match slot_proof.proof() {
                Ok(inclusion) => {
                    db.add_inclusion_proof(
                        acc,
                        inclusion.leaf_index,
                        &slot_proof.key,
                        hkey,
                        inclusion.proof.value.as_ref().map(|n| n.as_ref()),
                        &inclusion.proof.proof_related_nodes,
                    )
                    .map_err(DBError::BuildSlotInclusionProof())?;
                }
                Err(non_inclusion) => {
                    db.add_non_inclusion_proof(
                        acc,
                        non_inclusion.left_leaf_index,
                        non_inclusion.right_leaf_index,
                        &slot_proof.key,
                        hkey,
                        &non_inclusion.left_proof.proof_related_nodes,
                        &non_inclusion.right_proof.proof_related_nodes,
                    )
                    .map_err(DBError::BuildSlotNonInclusionProof())?;
                }
            }
        }
    }

    Ok(db)
}

pub(crate) fn get_hkey(key: &[u8]) -> Result<B256, linea_zktrie::Error> {
    Ok(match key.len() {
        20 => trie_hash(key)?,
        32 => mimc_safe(key)?,
        _ => unreachable!(),
    })
}

pub struct ContextDB {
    zktrie: ZkTrie<PrefixDB>,
    pub db: PrefixDB,
    pub block_hashes: BTreeMap<u64, B256>,

    cache: Arc<Mutex<BTreeMap<(Address, U256), U256>>>,
}

impl ContextDB {
    pub fn new(root: B256, db: Arc<Mutex<MemStore>>, block_hashes: BTreeMap<u64, B256>) -> Self {
        let db = PrefixDB::new(Address::default(), db);
        let zktrie = ZkTrie::new(root);
        let cache = Arc::new(Mutex::new(BTreeMap::new()));
        Self {
            db,
            zktrie,
            cache,
            block_hashes,
        }
    }

    pub fn get_acc(&self, addr: &Address) -> Option<ZkStateAccount> {
        let hkey = get_hkey(addr.as_ref()).unwrap();
        let result = self.zktrie.read(&self.db, hkey, addr.as_ref()).unwrap()?;
        ZkStateAccount::decode(&result)
    }

    pub fn sort_storage(
        &self,
        address: &Address,
        map: &HashMap<U256, U256>,
    ) -> Vec<(B256, U256, U256)> {
        let mut data = Vec::new();
        let cache = self.cache.lock().unwrap();
        let mut cache_key = (*address, 0u64.to());

        for (k, v) in map {
            cache_key.1 = *k;
            let old_val = cache.get(&cache_key);
            if old_val == Some(v) {
                continue;
            }
            let key_bytes = k.to_be_bytes::<32>();
            let hkey = get_hkey(&key_bytes).unwrap();
            data.push((hkey, *k, *v));
        }
        data.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));

        data
    }

    pub fn commit_changes(
        &mut self,
        old_root: B256,
        accounts: &HashMap<Address, DbAccount>,
    ) -> Result<CommitState, ExecutionError> {
        let cdb = self;
        let mut zktrie = ZkTrie::<PrefixDB>::new(old_root);
        let mut db_accounts = accounts
            .iter()
            .map(|(addr, acc)| (get_hkey(addr.as_ref()).unwrap(), addr, acc))
            .collect::<Vec<_>>();
        db_accounts.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));

        for (acc_hkey, addr, db_acc) in db_accounts {
            let Some(info): Option<AccountInfo> = db_acc.info() else {
                continue;
            };
            if info.is_empty() {
                continue;
            }
            let mut acc = cdb.get_acc(addr).unwrap_or_default();
            acc.balance = info.balance;
            acc.nonce = info.nonce;
            if acc.keccak_code_hash != info.code_hash {
                acc.mimc_code_hash = mimc_safe_code_hash(
                    info.code
                        .as_ref()
                        .map(|n| n.bytes_slice())
                        .unwrap_or_default(),
                );
                acc.keccak_code_hash = info.code_hash;
                acc.code_size = info.code.as_ref().map(|n| n.len()).unwrap_or_default().to();
            }

            if !db_acc.storage.is_empty() {
                let storage_root_before = acc.root;
                let mut db = cdb.db.new_prefix(*addr);
                let mut storage_tire = ZkTrie::<PrefixDB>::new(storage_root_before);
                for (hkey, key, value) in cdb.sort_storage(addr, &db_acc.storage) {
                    let key_bytes = key.to_be_bytes::<32>();

                    if !value.is_zero() {
                        let value_bytes = value.to_be_bytes::<32>();
                        let hval = trie_hash(&mimc_safe_encode(&value_bytes)).unwrap();
                        storage_tire
                            .put(&mut db, hkey, &key_bytes, hval, value_bytes.to_vec())
                            .map_err(ExecutionError::CommitStorage(addr, &key, &value))?;
                    } else {
                        storage_tire
                            .remove(&mut db, hkey, &key_bytes)
                            .map_err(ExecutionError::CommitStorage(addr, &key, &value))?;
                    }
                }
                acc.root = *storage_tire.top_root_hash();
            }

            // log::info!("addr: {:?} => {:?}", addr, acc);

            let val = acc.encode_mimc_safe();
            if val.len() == 0 {
                zktrie
                    .remove(&mut cdb.db, acc_hkey, addr.as_ref())
                    .map_err(ExecutionError::CommitAccount(&addr, &acc))?;
            } else {
                let hval = trie_hash(&val).unwrap();
                zktrie
                    .put(&mut cdb.db, acc_hkey, addr.as_ref(), hval, val)
                    .map_err(ExecutionError::CommitAccount(&addr, &acc))?;
            }
        }
        Ok(CommitState {
            new_state_root: *zktrie.top_root_hash(),
        })
    }
}

impl DatabaseRef for ContextDB {
    type Error = Infallible;
    fn basic_ref(&self, addr: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let Some(acc) = self.get_acc(&addr) else {
            return Ok(None);
        };
        let code = Bytecode::new_raw(
            self.db
                .get_code(&acc.keccak_code_hash)
                .unwrap()
                .as_ref()
                .clone(),
        );
        Ok(Some(AccountInfo {
            balance: acc.balance,
            nonce: acc.nonce,
            // code_size: acc.code_size.to(),
            code_hash: acc.keccak_code_hash,
            // poseidon_code_hash: B256::default(),
            code: Some(code),
        }))
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        Ok(self.block_hashes.get(&number).cloned().unwrap_or_default())
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        unimplemented!()
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let Some(acc) = self.get_acc(&address) else {
            return Ok(U256::default());
        };
        let db = self.db.new_prefix(address);
        let zktrie = ZkTrie::<PrefixDB>::new(acc.root);
        let index_bytes = index.to_be_bytes::<32>();
        let hkey = get_hkey(&index_bytes).unwrap();
        let result = zktrie.read(&db, hkey, &index_bytes).unwrap();
        let val = result.map(|n| U256::from_be_slice(&n)).unwrap_or_default();

        self.cache.lock().unwrap().insert((address, index), val);
        Ok(val)
    }
}

base::stack_error! {
    name: DBError,
    stack_name: DBErrorStack,
    error: {},
    wrap: {
        ZkTrie(linea_zktrie::Error),
        Json(serde_json::Error),
    },
    stack: {
        BuildFromTrace(),
        BuildAccInclusionProof(),
        BuildAccNonInclusionProof(),
        BuildSlotInclusionProof(),
        BuildSlotNonInclusionProof(),

        DecodeTrace(data: Bytes),
        DecodeProofs(data: Bytes),
    }
}

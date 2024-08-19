use std::{fmt::Debug, rc::Rc};

use eth_types::{Transaction, H256};
use mpt_zktrie::{AccountData, ZkTrie};
use scroll_revm::{
    db::CacheDB,
    primitives::{AccountInfo, Address, BlockEnv, Env, SpecId, TxEnv, B256, U256},
    DatabaseRef,
};
use zktrie::ZkMemoryDb;

pub struct ScrollEvmExecutor<D, E>
where
    D: DatabaseRef<Error = E>,
    E: Debug,
{
    db: CacheDB<D>,
    spec_id: SpecId,
    memdb: Rc<ZkMemoryDb>,
}

pub trait Context {
    fn chain_id(&self) -> u64;
    fn number(&self) -> u64;
    fn coinbase(&self) -> Address;
    fn transactions(&self) -> impl Iterator<Item = Transaction>;
    fn timestamp(&self) -> U256;
    fn gas_limit(&self) -> U256;
    fn base_fee_per_gas(&self) -> Option<U256>;
    fn difficulty(&self) -> U256;
    fn prevrandao(&self) -> Option<B256>;
    fn old_state_root(&self) -> B256;
    fn state_root(&self) -> B256;

    fn tx_env(&self, tx_idx: usize, rlp: Vec<u8>) -> TxEnv;

    fn block_env(&self) -> BlockEnv {
        BlockEnv {
            number: U256::from_limbs([self.number(), 0, 0, 0]),
            coinbase: self.coinbase(),
            timestamp: self.timestamp(),
            gas_limit: self.gas_limit(),
            basefee: self.base_fee_per_gas().unwrap_or_default(),
            difficulty: self.difficulty(),
            prevrandao: self.prevrandao(),
            blob_excess_gas_and_price: None,
        }
    }
}

impl<D, E> ScrollEvmExecutor<D, E>
where
    D: DatabaseRef<Error = E>,
    E: Debug,
{
    pub fn new(db: D, memdb: Rc<ZkMemoryDb>, spec_id: SpecId) -> Self {
        Self {
            db: CacheDB::new(db),
            spec_id,
            memdb,
        }
    }

    pub fn handle_block<C: Context>(&mut self, ctx: &C) -> B256 {
        let mut env = Box::<Env>::default();
        env.cfg.chain_id = ctx.chain_id();
        env.block = ctx.block_env();

        for (idx, tx) in ctx.transactions().enumerate() {
            let rlp = tx.rlp();
            let mut env = env.clone();
            env.tx = ctx.tx_env(idx, rlp.to_vec());
            if env.tx.scroll.is_l1_msg {
                env.cfg.disable_base_fee = true;
            }

            {
                let mut revm = scroll_revm::Evm::builder()
                    .with_spec_id(self.spec_id)
                    .with_db(&mut self.db)
                    .with_env(env)
                    .build();

                let _result = revm.transact_commit().unwrap(); // TODO: handle error
            }
        }

        let mut zktrie = self.memdb.new_trie(&ctx.old_state_root().0).unwrap();
        self.commit_changes(&mut zktrie);

        B256::from(zktrie.root())
    }

    fn commit_changes(&self, zktrie: &mut ZkTrie) {
        for (addr, db_acc) in self.db.accounts.iter() {
            let Some(info): Option<AccountInfo> = db_acc.info() else {
                continue;
            };
            if info.is_empty() {
                continue;
            }
            let mut acc_data = zktrie
                .get_account(addr.as_slice())
                .map(AccountData::from)
                .unwrap_or_default();

            acc_data.nonce = info.nonce;
            acc_data.balance = eth_types::U256(*info.balance.as_limbs());
            if !db_acc.storage.is_empty() {
                let storage_root_before = acc_data.storage_root;
                let mut storage_tire = self
                    .memdb
                    .new_trie(storage_root_before.as_fixed_bytes())
                    .expect("unable to get storage trie");
                for (key, value) in db_acc.storage.iter() {
                    if !value.is_zero() {
                        storage_tire
                            .update_store(&key.to_be_bytes::<32>(), &value.to_be_bytes())
                            .expect("failed to update storage");
                    } else {
                        storage_tire.delete(&key.to_be_bytes::<32>());
                    }
                }

                acc_data.storage_root = H256::from(storage_tire.root());
            }

            if acc_data.poseidon_code_hash.0 != info.poseidon_code_hash.0 {
                acc_data.poseidon_code_hash = H256::from(info.poseidon_code_hash.0);
                acc_data.keccak_code_hash = H256::from(info.code_hash.0);
                acc_data.code_size = self
                    .db
                    .contracts
                    .get(&db_acc.info.code_hash)
                    .map(|c| c.len())
                    .unwrap_or_default() as u64;
            }

            zktrie
                .update_account(addr.as_slice(), &acc_data.into())
                .expect("failed to update account");
        }
    }
}

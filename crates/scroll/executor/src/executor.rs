use std::{convert::Infallible, rc::Rc, str::FromStr};

use eth_types::{Transaction, H256};
use mpt_zktrie::{AccountData, ZkTrie};
use scroll_revm::{
    db::CacheDB,
    primitives::{AccountInfo, Address, BlockEnv, Env, SpecId, TxEnv, B256, U256},
    DatabaseRef,
};
use serde::{Deserialize, Serialize};
use zktrie::ZkMemoryDb;

use crate::ExecutionError;

pub struct ScrollEvmExecutor<D>
where
    D: DatabaseRef<Error = Infallible>,
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
    fn withdrawal_root(&self) -> B256;
    fn block_hash(&self) -> B256;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub new_state_root: B256,
    pub new_withdrawal_root: B256,
}

impl<D> ScrollEvmExecutor<D>
where
    D: DatabaseRef<Error = Infallible>,
{
    pub fn new(db: D, memdb: Rc<ZkMemoryDb>, spec_id: SpecId) -> Self {
        Self {
            db: CacheDB::new(db),
            spec_id,
            memdb,
        }
    }

    pub fn handle_block<C: Context>(&mut self, ctx: &C) -> Result<ExecutionResult, ExecutionError> {
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
                    .with_env(env.clone())
                    .build();

                let _result = revm
                    .transact_commit()
                    .map_err(ExecutionError::CommitTx(&ctx.number(), &tx.hash()))?;
            }
        }

        let mut zktrie = self.memdb.new_trie(&ctx.old_state_root().0).ok_or(
            ExecutionError::GenOldStateTrieFail {
                block_number: ctx.number(),
            },
        )?;
        self.commit_changes(&mut zktrie, ctx)?;
        let new_withdrawal_root = self.get_withdrawal_root(&zktrie, ctx)?;

        Ok(ExecutionResult {
            new_state_root: zktrie.root().into(),
            new_withdrawal_root,
        })
    }

    fn get_withdrawal_root<C: Context>(
        &self,
        zktrie: &ZkTrie,
        ctx: &C,
    ) -> Result<B256, ExecutionError> {
        let l1_message_queue_addr =
            Address::from_str("0x5300000000000000000000000000000000000000").unwrap();

        let acc = zktrie
            .get_account(l1_message_queue_addr.as_slice())
            .map(AccountData::from)
            .ok_or_else(|| ExecutionError::WithdrawalAccNotFound {
                block_number: ctx.number(),
                acc: l1_message_queue_addr,
            })?;
        let trie = match self.memdb.new_trie(&acc.storage_root.0) {
            Some(trie) => trie,
            None => return Ok(ctx.withdrawal_root()),
        };
        let index = B256::default();
        Ok(trie.get_store(&index.0).unwrap_or_default().into())
    }

    fn commit_changes<C: Context>(
        &self,
        zktrie: &mut ZkTrie,
        ctx: &C,
    ) -> Result<(), ExecutionError> {
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
                .map_err(ExecutionError::UpdateAccount(&ctx.number(), addr))?;
        }
        Ok(())
    }
}

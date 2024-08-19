use std::{convert::Infallible, rc::Rc};

use prover_types::Pob;
use scroll_executor::{
    eth_types::{self, state_db::CodeDB},
    init_hash_scheme,
    revm::{
        primitives::{keccak256, AccountInfo, Bytecode},
        DatabaseRef,
    },
    AccessListItem, AccountData, Address, Bytes, Context, ScrollFields, SpecId, TransactTo,
    Transaction, TxEnv, ZkMemoryDb, ZkTrie, B256, U256,
};

use crate::HardforkConfig;

pub struct PobContext {
    pub pob: Pob<Bytes>,
    txs: Vec<eth_types::Transaction>,
}

impl PobContext {
    pub fn new(pob: Pob<Bytes>) -> Self {
        init_hash_scheme();

        let mut txs = vec![];
        for tx in &pob.block.transactions {
            txs.push(rlp::decode(tx).unwrap());
        }

        Self { pob, txs }
    }

    pub fn spec_id(&self) -> SpecId {
        let cfg = HardforkConfig::default_from_chain_id(self.pob.data.chain_id);
        cfg.get_spec_id(self.number())
    }

    pub fn db(&self, memdb: Rc<ZkMemoryDb>) -> PobContextDB {
        let zktrie = memdb.new_trie(&self.pob.data.prev_state_root).unwrap();
        let mut code_db = CodeDB::new();
        for item in &self.pob.data.codes {
            let hash = keccak256(&item).0.into();
            code_db.insert_with_hash(hash, item.clone().into());
        }
        PobContextDB {
            zktrie,
            memdb,
            code_db,
        }
    }

    pub fn memdb(&self) -> Rc<ZkMemoryDb> {
        let mut memdb = ZkMemoryDb::new();
        for node in &self.pob.data.mpt_nodes {
            memdb.add_node_bytes(&node, None).unwrap();
        }
        Rc::new(memdb)
    }

    pub fn tx_rlps(&self) -> &[Bytes] {
        &self.pob.block.transactions
    }

    pub fn txs(&self) -> &[Transaction] {
        &self.txs
    }
}

impl Context for PobContext {
    #[inline]
    fn old_state_root(&self) -> B256 {
        self.pob.data.prev_state_root
    }

    #[inline]
    fn number(&self) -> u64 {
        self.pob.block.number.to()
    }

    #[inline]
    fn base_fee_per_gas(&self) -> Option<scroll_executor::U256> {
        self.pob.block.base_fee_per_gas
    }

    #[inline]
    fn chain_id(&self) -> u64 {
        self.pob.data.chain_id
    }

    #[inline]
    fn coinbase(&self) -> Address {
        self.pob.data.coinbase
    }

    #[inline]
    fn timestamp(&self) -> U256 {
        self.pob.block.timestamp.to()
    }
    #[inline]
    fn gas_limit(&self) -> U256 {
        self.pob.block.gas_limit.to()
    }

    #[inline]
    fn difficulty(&self) -> U256 {
        self.pob.block.difficulty.to()
    }
    #[inline]
    fn prevrandao(&self) -> Option<B256> {
        Some(self.pob.block.mix_hash)
    }

    fn transactions(&self) -> impl Iterator<Item = eth_types::Transaction> {
        self.txs.clone().into_iter()
    }

    fn tx_env(&self, tx_idx: usize, rlp: Vec<u8>) -> TxEnv {
        let tx = &self.txs[tx_idx];
        let from = tx.recover_from().unwrap();
        let mut nonce = Some(tx.nonce.as_u64());

        let is_l1_msg = tx
            .transaction_type
            .map(|n| n.as_u64() == 0x7E)
            .unwrap_or_default();

        if is_l1_msg {
            nonce = None;
        }

        TxEnv {
            caller: from.0.into(),
            gas_limit: tx.gas.as_u64(),
            gas_price: U256::from_limbs(tx.gas_price.unwrap().0),
            transact_to: match tx.to {
                Some(to) => TransactTo::Call(to.0.into()),
                None => TransactTo::Create,
            },
            value: U256::from_limbs(tx.value.0),
            data: Bytes::copy_from_slice(&tx.input.as_ref()),
            nonce,
            chain_id: Some(self.chain_id()),
            access_list: tx
                .access_list
                .as_ref()
                .map(|v| {
                    v.0.iter()
                        .map(|e| AccessListItem {
                            address: e.address.0.into(),
                            storage_keys: e
                                .storage_keys
                                .iter()
                                .map(|s| s.to_fixed_bytes().into())
                                .collect(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            gas_priority_fee: tx.max_priority_fee_per_gas.map(|g| U256::from_limbs(g.0)),
            scroll: ScrollFields {
                is_l1_msg,
                rlp_bytes: Some(Bytes::from(rlp)),
            },
            ..Default::default()
        }
    }
}

pub struct PobContextDB {
    memdb: Rc<ZkMemoryDb>,
    zktrie: ZkTrie,
    code_db: CodeDB,
}

impl DatabaseRef for PobContextDB {
    type Error = Infallible;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(match self.zktrie.get_account(address.as_slice()) {
            Some(acc) => {
                let acc: AccountData = acc.into();
                Some(AccountInfo {
                    balance: U256::from_limbs(acc.balance.0),
                    nonce: acc.nonce,
                    code_size: acc.code_size as usize,
                    code_hash: acc.keccak_code_hash.0.into(),
                    poseidon_code_hash: acc.poseidon_code_hash.0.into(),
                    code: self
                        .code_db
                        .0
                        .get(&acc.keccak_code_hash)
                        .map(|vec| Bytecode::new_raw(Bytes::from(vec.clone()))),
                })
            }
            None => None,
        })
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        unimplemented!("BLOCKHASH is disabled")
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        panic!("Should not be called. Code is already loaded");
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let acc: AccountData = match self.zktrie.get_account(address.as_slice()) {
            Some(n) => n.into(),
            None => return Ok(U256::default()),
        };

        let storage_trie = self.memdb.new_trie(&(acc.storage_root.into())).unwrap();
        let index: [u8; 32] = index.to_be_bytes();
        let val = storage_trie.get_store(&index[..]).unwrap_or_default();
        let val = U256::from_be_slice(&val);

        Ok(val)
    }
}

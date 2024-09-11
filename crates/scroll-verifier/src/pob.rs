use std::{convert::Infallible, rc::Rc};

use prover_types::Pob;
use scroll_executor::{
    eth_types::{self, state_db::CodeDB},
    init_hash_scheme,
    revm::{
        primitives::{keccak256, AccountInfo, Bytecode},
        DatabaseRef,
    },
    AccountData, Address, Bytes, Context, EthPrimitivesConvert, ScrollFields, SpecId, TransactTo,
    Transaction, TxEnv, ZkMemoryDb, ZkTrie, B256, U256,
};

use crate::{BatchContext, HardforkConfig};

pub struct PobContext {
    pub pob: Pob<Bytes>,
    txs: Vec<eth_types::Transaction>,
}

impl PobContext {
    pub fn new(pob: Pob<Bytes>) -> Self {
        init_hash_scheme();

        let mut txs = vec![];
        for tx in &pob.block.transactions {
            let mut tx = rlp::decode(tx).unwrap();
            Self::fix_tx(&mut tx, pob.block.base_fee_per_gas);
            txs.push(tx);
        }

        Self { pob, txs }
    }

    fn fix_tx(tx: &mut eth_types::Transaction, base_fee_per_gas: Option<U256>) {
        let tx_type = tx.transaction_type.unwrap_or_default().as_u64();
        if tx_type == 2 {
            let mut base_fee = eth_types::U256::default();
            base_fee
                .0
                .copy_from_slice(base_fee_per_gas.unwrap().as_limbs());
            let priority_fee_per_gas = std::cmp::min(
                tx.max_priority_fee_per_gas.unwrap(),
                tx.max_fee_per_gas.unwrap() - base_fee,
            );
            let effective_gas_price = priority_fee_per_gas + base_fee;
            tx.gas_price = Some(effective_gas_price);
        }

        if tx_type != 0x7E {
            tx.from = tx.recover_from().expect("recover_from");
        } else {
            tx.gas_price = Some(0.into());
        }
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

impl BatchContext for PobContext {
    fn tx_rlp(&self, idx: usize) -> Vec<u8> {
        self.pob.block.transactions[idx].to_vec()
    }

    fn txs(&self) -> &[Transaction] {
        &self.txs
    }
}

impl Context for PobContext {
    #[inline]
    fn old_state_root(&self) -> B256 {
        self.pob.data.prev_state_root
    }

    fn block_hash(&self) -> B256 {
        self.pob
            .block
            .block_hash
            .expect("should have the block_hash")
    }

    #[inline]
    fn state_root(&self) -> B256 {
        self.pob.block.state_root
    }

    #[inline]
    fn withdrawal_root(&self) -> B256 {
        self.pob.data.withdrawal_root
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
        self.pob.data.coinbase.unwrap_or(self.pob.block.miner)
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
        self.pob.block.difficulty
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
        let mut nonce = Some(tx.nonce.as_u64());

        let is_l1_msg = tx
            .transaction_type
            .map(|n| n.as_u64() == 0x7E)
            .unwrap_or_default();

        if is_l1_msg {
            nonce = None;
        }

        TxEnv {
            caller: tx.from.to(),
            gas_limit: tx.gas.as_u64(),
            gas_price: tx.gas_price.unwrap().to(),
            transact_to: TransactTo::from(tx.to.to()),
            value: tx.value.to(),
            data: tx.input.clone().to(),
            nonce,
            chain_id: Some(self.chain_id()),
            access_list: tx.access_list.clone().map(|n| n.0.to()).unwrap_or_default(),
            gas_priority_fee: tx.max_priority_fee_per_gas.to(),
            scroll: ScrollFields {
                is_l1_msg,
                rlp_bytes: Some(rlp.into()),
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
                    balance: acc.balance.to(),
                    nonce: acc.nonce,
                    code_size: acc.code_size as usize,
                    code_hash: acc.keccak_code_hash.to(),
                    poseidon_code_hash: acc.poseidon_code_hash.to(),
                    code: self
                        .code_db
                        .0
                        .get(&acc.keccak_code_hash)
                        .map(|vec| Bytecode::new_raw(vec.clone().into())),
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

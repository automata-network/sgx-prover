use std::{convert::Infallible, rc::Rc};

use scroll_executor::{
    eth_types::{
        self,
        state_db::{self, CodeDB, StateDB},
        ToWord, Word, H256,
    },
    revm::{
        primitives::{keccak256, AccountInfo, Bytecode},
        DatabaseRef,
    },
    Address, BlockTrace, Context, EthPrimitivesConvert, ScrollFields, SpecId, TransactTo,
    Transaction, TxEnv, ZkMemoryDb, ZktrieState, B256, U256,
};

use crate::HardforkConfig;

pub struct BlockContext {
    trace: BlockTrace,

    code_db: CodeDB,
    pub(crate) sdb: StateDB,
}

impl BlockContext {
    pub fn new(trace: BlockTrace) -> Self {
        let mut ctx = Self {
            trace,
            sdb: StateDB::new(),
            code_db: CodeDB::new(),
        };
        ctx.init();
        ctx
    }

    fn init(&mut self) {
        for (addr, account) in Self::accounts(&self.trace) {
            self.sdb.set_account(&addr, account);
        }
        for ((addr, key), val) in Self::storages(&self.trace) {
            let key = key.to_word();
            *self.sdb.get_storage_mut(&addr, &key).1 = val;
        }
        for (_, code) in Self::codes(&self.trace) {
            let hash = keccak256(&code).0.into();
            self.code_db.insert_with_hash(hash, code);
        }
    }

    fn accounts(
        trace: &BlockTrace,
    ) -> impl Iterator<Item = (eth_types::Address, state_db::Account)> + '_ {
        ZktrieState::parse_account_from_proofs(
            trace
                .storage_trace
                .proofs
                .iter()
                .map(|(addr, b)| (addr, b.iter().map(|b| b.as_ref()))),
        )
        .map(|parsed| {
            let (addr, acc) = parsed.unwrap();
            (addr, state_db::Account::from(&acc))
        })
    }

    fn storages(
        trace: &BlockTrace,
    ) -> impl Iterator<Item = ((eth_types::Address, H256), Word)> + '_ {
        ZktrieState::parse_storage_from_proofs(trace.storage_trace.storage_proofs.iter().flat_map(
            |(addr, map)| {
                map.iter()
                    .map(move |(sk, bts)| (addr, sk, bts.iter().map(|b| b.as_ref())))
            },
        ))
        .map(|parsed| {
            let ((addr, key), val) = parsed.unwrap();
            ((addr, key), val.into())
        })
    }

    fn codes(trace: &BlockTrace) -> impl Iterator<Item = (H256, Vec<u8>)> + '_ {
        trace
            .codes
            .iter()
            .map(|trace| (trace.hash, trace.code.to_vec()))
    }

    pub fn memdb(&self) -> Rc<ZkMemoryDb> {
        let old_root = self.trace.storage_trace.root_before;
        let zktrie_state = ZktrieState::from_trace_with_additional(
            old_root,
            self.trace
                .storage_trace
                .proofs
                .iter()
                .map(|(addr, b)| (addr, b.iter().map(|b| b.as_ref()))),
            self.trace
                .storage_trace
                .storage_proofs
                .iter()
                .flat_map(|(addr, map)| {
                    map.iter()
                        .map(move |(sk, bts)| (addr, sk, bts.iter().map(|b| b.as_ref())))
                }),
            self.trace
                .storage_trace
                .deletion_proofs
                .iter()
                .map(|s| s.as_ref()),
        )
        .unwrap();

        zktrie_state.into_inner()
    }

    pub fn spec_id(&self) -> SpecId {
        let cfg = HardforkConfig::default_from_chain_id(self.chain_id());
        cfg.get_spec_id(self.number())
    }
}

impl scroll_executor::Context for BlockContext {
    #[inline]
    fn number(&self) -> u64 {
        self.trace.header.number.expect("incomplete block").as_u64()
    }

    fn block_hash(&self) -> B256 {
        self.trace.header.hash.unwrap().to()
    }

    fn state_root(&self) -> B256 {
        self.trace.header.state_root.to()
    }
    fn withdrawal_root(&self) -> B256 {
        self.trace.withdraw_trie_root.to()
    }

    #[inline]
    fn chain_id(&self) -> u64 {
        self.trace.chain_id
    }
    #[inline]
    fn coinbase(&self) -> Address {
        self.trace.coinbase.address.to()
    }
    #[inline]
    fn timestamp(&self) -> U256 {
        self.trace.header.timestamp.to()
    }
    #[inline]
    fn gas_limit(&self) -> U256 {
        self.trace.header.gas_limit.to()
    }
    #[inline]
    fn base_fee_per_gas(&self) -> Option<U256> {
        self.trace.header.base_fee_per_gas.to()
    }
    #[inline]
    fn old_state_root(&self) -> B256 {
        self.trace.storage_trace.root_before.to()
    }
    #[inline]
    fn difficulty(&self) -> U256 {
        self.trace.header.difficulty.to()
    }
    #[inline]
    fn prevrandao(&self) -> Option<B256> {
        self.trace.header.mix_hash.to()
    }

    fn transactions(&self) -> impl Iterator<Item = Transaction> {
        let block_hash = self.trace.header.hash;
        let block_number = self.trace.header.number;
        let base_fee_per_gas = self.trace.header.base_fee_per_gas;
        self.trace
            .transactions
            .iter()
            .enumerate()
            .map(move |(idx, tx)| {
                tx.to_eth_tx(block_hash, block_number, Some(idx.into()), base_fee_per_gas)
            })
    }

    fn tx_env(&self, tx_idx: usize, rlp: Vec<u8>) -> TxEnv {
        let tx = &self.trace.transactions[tx_idx];
        let mut nonce = Some(tx.nonce);
        if tx.is_l1_tx() {
            nonce = None;
        }

        TxEnv {
            caller: tx.from.to(),
            gas_limit: tx.gas,
            gas_price: tx.gas_price.to(),
            transact_to: TransactTo::from(tx.to.to()),
            value: tx.value.to(),
            data: tx.data.clone().to(),
            nonce,
            chain_id: Some(self.chain_id()),
            access_list: tx.access_list.clone().to().unwrap_or_default(),
            gas_priority_fee: tx.gas_tip_cap.to(),
            scroll: ScrollFields {
                is_l1_msg: tx.is_l1_tx(),
                rlp_bytes: Some(rlp.into()),
            },
            ..Default::default()
        }
    }
}

impl DatabaseRef for BlockContext {
    type Error = Infallible;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let (exist, acc) = self.sdb.get_account(&address.to());
        if exist {
            let acc = AccountInfo {
                balance: acc.balance.to(),
                nonce: acc.nonce.as_u64(),
                code_size: acc.code_size.as_usize(),
                code_hash: acc.keccak_code_hash.to(),
                poseidon_code_hash: acc.code_hash.to(),
                // if None, means CodeDB did not include the code, could cause by: EXTCODESIZE
                code: self
                    .code_db
                    .0
                    .get(&acc.keccak_code_hash)
                    .map(|vec| Bytecode::new_legacy(vec.clone().into())),
            };
            Ok(Some(acc))
        } else {
            Ok(None)
        }
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        unimplemented!("BLOCKHASH is disabled")
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        panic!("Should not be called. Code is already loaded");
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let (_, val) = self.sdb.get_storage(&address.to(), &index.to());
        Ok(val.to())
    }
}

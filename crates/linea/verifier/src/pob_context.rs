use std::sync::{Arc, Mutex};

use alloy::{
    consensus::{Transaction, TxEnvelope},
    primitives::{keccak256, Address, Bytes, U256},
    rlp::{encode_list, Encodable},
};
use base::eth::Keypair;
use linea_executor::{Context, ExecutionError, SpecId, TxEnv};
use linea_revm::db::CacheDB;
use linea_zktrie::MemStore;
use prover_types::{Pob, PobBlock, B256};

use crate::{build_mem_db, ContextDB, DBError};

pub struct PobContext {
    pub pob: Pob<Bytes>,
    db: Arc<Mutex<MemStore>>,
    txs: Vec<TxEnvelope>,
}

impl PobContext {
    pub fn new(pob: Pob<Bytes>) -> Result<Self, DBError> {
        let mut txs = vec![];
        for tx in &pob.block.transactions {
            let tx: TxEnvelope = alloy::rlp::decode_exact(tx).unwrap();
            txs.push(tx)
        }
        let mut linea_traces = vec![];
        for item in &pob.data.linea_traces {
            linea_traces.push(serde_json::from_slice(&item).map_err(DBError::DecodeTrace(&item))?);
        }
        let mut linea_proofs = vec![];
        for item in &pob.data.linea_proofs {
            linea_proofs.push(serde_json::from_slice(&item).map_err(DBError::DecodeProofs(&item))?);
        }
        let db = Arc::new(Mutex::new(build_mem_db(
            &linea_traces,
            pob.data.codes.clone(),
            &linea_proofs,
        )?));
        Ok(Self { pob, txs, db })
    }

    fn blk(&self) -> &PobBlock {
        &self.pob.block
    }

    pub fn seal_header(&self) -> B256 {
        let header = self.blk();

        // Remove the last 65 bytes of extra_data
        let extra_data = Bytes::copy_from_slice(&header.extra_data[..header.extra_data.len() - 65]);
        // May need to handle the case where base_fee_per_gas is nil

        // https://github.com/ethereum/go-ethereum/blob/81fd1b3cf9c4c4c9f0e06f8bdcbaa8b29c81b052/consensus/clique/clique.go#L763
        let mut buf = alloy::rlp::bytes::BytesMut::new();
        let enc: [&dyn Encodable; 16] = [
            &header.parent_hash,
            &header.uncles_hash,
            &header.miner,
            &header.state_root,
            &header.transactions_root,
            &header.receipts_root,
            &header.logs_bloom,
            &header.difficulty,
            &header.number,
            &header.gas_limit,
            &header.gas_used,
            &header.timestamp,
            &extra_data,
            &header.mix_hash,
            &header.nonce,
            &header.base_fee_per_gas.as_ref().unwrap(),
        ];

        encode_list::<_, dyn Encodable>(&enc, &mut buf);

        keccak256(&buf)
    }
}

impl Context for PobContext {
    type ExecutionResult = linea_revm::primitives::ExecutionResult;
    type CommitState = linea_executor::CommitState;
    type DB = ContextDB;

    fn db(&self) -> Self::DB {
        ContextDB::new(self.old_state_root(), self.db.clone(), self.pob.data.block_hashes.clone())
    }

    fn spec_id(&self) -> SpecId {
        SpecId::LONDON
    }

    fn base_fee_per_gas(&self) -> Option<U256> {
        self.blk().base_fee_per_gas
    }

    fn block_hash(&self) -> B256 {
        self.blk().block_hash.unwrap_or_default()
    }

    fn chain_id(&self) -> u64 {
        self.pob.data.chain_id
    }

    fn coinbase(&self) -> Address {
        let extra_data = self.blk().extra_data.as_ref();
        let mut sig_array = [0_u8; 65];
        sig_array.copy_from_slice(&extra_data[extra_data.len() - 65..]);
        let msg = self.seal_header();
        let author = Keypair::recover(msg.0, sig_array).unwrap();
        author
    }

    fn difficulty(&self) -> U256 {
        self.blk().difficulty
    }

    fn gas_limit(&self) -> U256 {
        self.blk().gas_limit.to()
    }

    fn number(&self) -> u64 {
        self.blk().number.to()
    }

    fn old_state_root(&self) -> B256 {
        self.pob.data.prev_state_root
    }

    fn prevrandao(&self) -> Option<B256> {
        Some(self.blk().mix_hash)
    }

    fn state_root(&self) -> B256 {
        self.pob.data.linea_zkroot
    }

    fn timestamp(&self) -> U256 {
        self.blk().timestamp.to()
    }

    fn withdrawal_root(&self) -> B256 {
        B256::default()
    }

    fn transactions(&self) -> impl Iterator<Item = TxEnvelope> {
        self.txs.clone().into_iter()
    }

    fn verify_execution_result(&self, _: usize, _: Self::ExecutionResult) {}

    fn tx_env(&self, tx_idx: usize, _: Vec<u8>) -> TxEnv {
        let tx = &self.txs[tx_idx];
        let caller = tx.recover_signer().unwrap();

        TxEnv {
            caller,
            gas_limit: tx.gas_limit() as _,
            gas_price: self._gas_price(tx).unwrap(),
            transact_to: tx.to(),
            value: tx.value(),
            data: tx.input().to_vec().into(),
            nonce: Some(tx.nonce()),
            chain_id: Some(self.pob.data.chain_id),
            access_list: self._access_list(tx).cloned().unwrap_or_default().into(),
            gas_priority_fee: self._max_priority_fee_per_gas(tx),
            blob_hashes: Vec::new(),
            max_fee_per_blob_gas: self._max_fee_per_blob_gas(tx),
            authorization_list: None,
        }
    }

    fn commit_changes(
        &self,
        mut db: CacheDB<Self::DB>,
    ) -> Result<Self::CommitState, ExecutionError> {
        let old_root = self.old_state_root();
        db.db.commit_changes(old_root, &db.accounts)
    }
}

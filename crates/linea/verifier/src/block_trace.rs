use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::{Arc, Mutex},
};

use alloy::{
    consensus::TxEnvelope,
    eips::BlockId,
    primitives::{keccak256, Address, Bytes, B256, U256},
    rlp::{encode_list, Encodable},
    rpc::types::{eth::Block, BlockTransactionsKind, TransactionReceipt},
};
use base::eth::{Keypair, PrimitivesConvert, Eth, EthError};
use linea_executor::{CommitState, Context, ExecutionError, SpecId, TxEnv};
use linea_revm::db::CacheDB;
use linea_shomei::{Client, MerkleAccountProof};
use linea_zktrie::{MemStore, Trace};
use prover_types::{Pob, PobBlock, PobData};
use serde::{Deserialize, Serialize};

use crate::{build_mem_db, ContextDB, DBError};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockTrace {
    pub chain_id: u64,
    pub block: Block,
    pub zk_parent_state_root_hash: B256,
    pub zk_end_state_root_hash: B256,
    pub zk_state_manager_version: String,
    pub traces: Vec<Trace>,
    pub state_proof: Vec<MerkleAccountProof>,
    pub codes: Vec<Bytes>,
    pub receipts: Vec<TransactionReceipt>,
    #[serde(default)]
    pub block_hashes: BTreeMap<u64, B256>,
}

impl BlockTrace {
    pub async fn build(
        eth: &Eth,
        shomei: &Client,
        block_number: u64,
    ) -> Result<BlockTrace, BlockTraceError> {
        let chain_id = eth.provider().get_chain_id().await.map_err(EthError::Rpc)?;

        let block_id = BlockId::Number(block_number.into());

        let block = eth
            .provider()
            .get_block(block_id, BlockTransactionsKind::Full)
            .await
            .map_err(EthError::Rpc)
            .map_err(BlockTraceError::FetchBlock(&block_number))?
            .ok_or(BlockTraceError::BlockNotFound(block_number))?;

        let receipts = eth
            .provider()
            .get_block_receipts(block_number.into())
            .await
            .map_err(EthError::Rpc)?
            .ok_or(BlockTraceError::BlockReceiptsNotFound(block_number))?;

        let prestate_block_number = block_number - 1;
        let prestate_block_id = BlockId::Number(prestate_block_number.into());

        let mut result = shomei
            .fetch_proof(block_number, block_number)
            .await
            .map_err(BlockTraceError::FetchBlockProof(&block_number))?;

        let block_traces = &result.zk_state_merkle_proof[0];

        let acc_proofs = shomei
            .fetch_proof_by_traces(block_traces, prestate_block_id)
            .await
            .map_err(BlockTraceError::FetchAccountProof(&prestate_block_number))?;

        let mut contract_addrs = BTreeSet::new();
        for t in block_traces {
            if t.location().len() == 0 {
                let value = t.read_value();
                if value.len() > 0 {}
                let mut addr = Address::default();
                addr.0.copy_from_slice(t.key());
                contract_addrs.insert(addr);
            } else {
                let mut addr = Address::default();
                addr.copy_from_slice(t.location());
                contract_addrs.insert(addr);
            }
        }

        let contract_addrs = contract_addrs
            .into_iter()
            .map(|n| (n, prestate_block_id))
            .collect::<Vec<_>>();
        let contract_codes = eth
            .batch_request::<_, Bytes>("eth_getCode", &contract_addrs)
            .await
            .map_err(BlockTraceError::FetchContractCodes(&prestate_block_number))?;

        let contract_codes: HashSet<_> = contract_codes.into_iter().collect();
        let contract_codes: Vec<_> = contract_codes.into_iter().collect();

        Ok(BlockTrace {
            chain_id,
            block,
            traces: result.zk_state_merkle_proof.remove(0),
            zk_end_state_root_hash: result.zk_end_state_root_hash,
            zk_parent_state_root_hash: result.zk_parent_state_root_hash,
            zk_state_manager_version: result.zk_state_manager_version,
            state_proof: acc_proofs,
            codes: contract_codes,
            receipts,
            block_hashes: BTreeMap::new(),
        })
    }

    pub fn build_db(self) -> Result<MemStore, DBError> {
        build_mem_db(&self.traces, self.codes, &self.state_proof)
    }
}

pub struct BlockTraceContext {
    bc: BlockTrace,
    db: Arc<Mutex<MemStore>>,
}

impl BlockTraceContext {
    pub fn new(bc: BlockTrace) -> Self {
        let db = bc.clone().build_db().unwrap();
        let db = Arc::new(Mutex::new(db));

        Self { bc, db }
    }

    pub fn seal_header(&self) -> B256 {
        let header = &self.bc.block.header;

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
            &header.number.as_ref().unwrap(),
            &header.gas_limit,
            &header.gas_used,
            &header.timestamp,
            &extra_data,
            header.mix_hash.as_ref().unwrap(),
            header.nonce.as_ref().unwrap(),
            header.base_fee_per_gas.as_ref().unwrap(),
        ];

        encode_list::<_, dyn Encodable>(&enc, &mut buf);

        keccak256(&buf)
    }
}

impl Context for BlockTraceContext {
    type ExecutionResult = linea_revm::primitives::ExecutionResult;
    type CommitState = linea_executor::CommitState;
    type DB = ContextDB;

    fn db(&self) -> Self::DB {
        ContextDB::new(
            self.bc.zk_parent_state_root_hash,
            self.db.clone(),
            self.bc.block_hashes.clone(),
        )
    }

    fn spec_id(&self) -> SpecId {
        SpecId::LONDON
    }

    fn base_fee_per_gas(&self) -> Option<U256> {
        self.bc
            .block
            .header
            .base_fee_per_gas
            .map(|n| U256::from_be_slice(&n.to_be_bytes()))
    }

    fn chain_id(&self) -> u64 {
        self.bc.chain_id
    }

    fn block_hash(&self) -> B256 {
        self.bc.block.header.hash.unwrap()
    }

    fn coinbase(&self) -> Address {
        let extra_data = self.bc.block.header.extra_data.as_ref();
        let mut sig_array = [0_u8; 65];
        sig_array.copy_from_slice(&extra_data[extra_data.len() - 65..]);
        let msg = self.seal_header();
        let author = Keypair::recover(msg.0, sig_array).unwrap();

        author
    }

    fn difficulty(&self) -> U256 {
        self.bc.block.header.difficulty
    }

    fn gas_limit(&self) -> U256 {
        U256::from_be_slice(&self.bc.block.header.gas_limit.to_be_bytes())
    }

    fn prevrandao(&self) -> Option<B256> {
        self.bc.block.header.mix_hash
    }

    fn timestamp(&self) -> U256 {
        U256::from_limbs_slice(&[self.bc.block.header.timestamp])
    }

    fn old_state_root(&self) -> B256 {
        self.bc.zk_parent_state_root_hash
    }

    fn state_root(&self) -> B256 {
        self.bc.zk_end_state_root_hash
    }

    fn number(&self) -> u64 {
        self.bc.block.header.number.unwrap()
    }

    fn transactions(&self) -> impl Iterator<Item = TxEnvelope> {
        let mut txs = vec![];
        for tx in self.bc.block.transactions.as_transactions().unwrap() {
            let tx: TxEnvelope = tx.clone().try_into().unwrap();
            txs.push(tx);
        }
        txs.into_iter()
    }

    fn withdrawal_root(&self) -> B256 {
        self.bc.block.header.withdrawals_root.unwrap()
    }

    fn tx_env(&self, tx_idx: usize, _: Vec<u8>) -> TxEnv {
        let tx = &self.bc.block.transactions.as_transactions().unwrap()[tx_idx];
        let signed_tx: TxEnvelope = tx.clone().try_into().unwrap();
        let caller = signed_tx.recover_signer().unwrap();
        let access_list = tx.access_list.clone().unwrap_or_default().into();
        let authorization_list = tx.authorization_list.clone().map(|n| n.into());

        TxEnv {
            caller,
            gas_limit: tx.gas as _,
            gas_price: U256::from_be_slice(&tx.gas_price.unwrap().to_be_bytes()),
            transact_to: tx.to.into(),
            value: tx.value,
            data: tx.input.clone(),
            nonce: Some(tx.nonce),
            chain_id: Some(self.bc.chain_id),
            access_list,
            gas_priority_fee: tx
                .max_priority_fee_per_gas
                .map(|n| U256::from_be_slice(&n.to_be_bytes())),
            blob_hashes: Vec::new(),
            max_fee_per_blob_gas: tx
                .max_fee_per_blob_gas
                .map(|n| U256::from_be_slice(&n.to_be_bytes())),
            authorization_list,
        }
    }

    fn verify_execution_result(&self, idx: usize, result: Self::ExecutionResult) {
        let receipt = &self.bc.receipts[idx];
        if result.gas_used() != receipt.gas_used as u64 {
            log::warn!(
                "gas used mismatch: remote={}, local={}",
                receipt.gas_used,
                result.gas_used()
            );
        }
    }

    fn commit_changes(&self, mut db: CacheDB<Self::DB>) -> Result<CommitState, ExecutionError> {
        db.db.commit_changes(self.old_state_root(), &db.accounts)
    }
}

base::stack_error! {
    #[derive(Debug)]
    name: BlockTraceError,
    stack_name: BlockTraceErrorStack,
    error: {
        BlockNotFound(u64),
        BlockReceiptsNotFound(u64),
    },
    wrap: {
        Eth(EthError),
        Zktrie(linea_zktrie::Error),
    },
    stack: {
        BuildMemStore(),
        FetchBlock(block_number: u64),
        FetchBlockProof(block_number: u64),
        FetchAccountProof(block_number: u64),
        SendContractCodeRequest(block_number: u64),
        FetchContractCodes(block_number: u64),

        BuildAccNonInclusionProof(),
        BuildAccInclusionProof(),
        BuildSlotInclusionProof(),
        BuildSlotNonInclusionProof(),
    }
}

pub fn block_trace_to_pob(trace: BlockTrace) -> Option<Pob<Bytes>> {
    let header = trace.block.header;
    let mut txs = Vec::new();
    for tx in trace.block.transactions.into_transactions() {
        let tx = TxEnvelope::try_from(tx).unwrap();
        let tx_bytes = alloy::rlp::encode(&tx);
        txs.push(tx_bytes.to());
    }
    let block = PobBlock {
        miner: header.miner,
        state_root: header.state_root,
        difficulty: header.difficulty.to(),
        number: header.number.unwrap().to(),
        gas_limit: (header.gas_limit as u64).to(),
        timestamp: header.timestamp.to(),
        mix_hash: header.mix_hash.unwrap(),
        base_fee_per_gas: header.base_fee_per_gas.map(|n| n.to()),
        block_hash: header.hash,
        transactions: txs,
        extra_data: header.extra_data,
        logs_bloom: header.logs_bloom,
        nonce: header.nonce.unwrap(),
        parent_hash: header.parent_hash,
        receipts_root: header.receipts_root,
        transactions_root: header.transactions_root,
        uncles_hash: header.uncles_hash,
        gas_used: header.gas_used.to(),
    };

    let mut linea_traces = vec![];
    for item in trace.traces {
        linea_traces.push(serde_json::to_vec(&item).unwrap().into());
    }
    let mut linea_proofs = vec![];
    for item in trace.state_proof {
        linea_proofs.push(serde_json::to_vec(&item).unwrap().into());
    }

    let data = PobData {
        chain_id: trace.chain_id,
        coinbase: None,
        prev_state_root: trace.zk_parent_state_root_hash,
        block_hashes: trace.block_hashes,
        mpt_nodes: vec![],
        codes: trace.codes,

        // scroll
        start_l1_queue_index: 0,
        withdrawal_root: B256::default(),

        // linea
        linea_traces,
        linea_proofs,
        linea_zkroot: trace.zk_end_state_root_hash,
    };
    Some(Pob::new(block, data))
}

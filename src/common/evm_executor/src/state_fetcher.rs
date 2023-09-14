use std::prelude::v1::*;

use base::format::debug;
use base::trace::AvgCounter;
use crypto::keccak_hash;
use eth_client::ExecutionClient;
use eth_types::{
    BlockSelector, FetchState, HexBytes, TransactionAccessTuple, H160, H256,
    SH160, SH256, SU256,
};
use statedb::Error;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use scroll_types::FetchStateResult;

#[derive(Clone, Debug)]
pub struct TraceBlockStateFetcher {
    pub fetcher: BlockStateFetcher,
    block_hashes: Arc<Mutex<BTreeMap<u64, SH256>>>,
    mpt_nodes: Arc<Mutex<BTreeMap<SH256, HexBytes>>>,
    codes: Arc<Mutex<BTreeMap<SH256, HexBytes>>>,
}

impl TraceBlockStateFetcher {
    pub fn new(client: Arc<ExecutionClient>, blk: BlockSelector) -> Self {
        Self {
            fetcher: BlockStateFetcher::new(client, blk),
            block_hashes: Default::default(),
            mpt_nodes: Default::default(),
            codes: Default::default(),
        }
    }

    fn add_code(&self, node: &HexBytes) {
        let mut codes = self.codes.lock().unwrap();
        let mut hash = SH256::default();
        hash.0 = keccak_hash(&node);
        codes.entry(hash).or_insert_with(|| node.clone());
    }

    fn add_nodes(&self, nodes: &[HexBytes]) {
        let mut mpt_nodes = self.mpt_nodes.lock().unwrap();
        for node in nodes {
            let mut hash = SH256::default();
            hash.0 = keccak_hash(&node);
            mpt_nodes.entry(hash).or_insert_with(|| node.clone());
        }
    }

    pub fn block_hashes(&self) -> BTreeMap<u64, SH256> {
        self.block_hashes.lock().unwrap().clone()
    }

    pub fn mpt_nodes(&self) -> Vec<HexBytes> {
        let mpt_nodes = self.mpt_nodes.lock().unwrap();
        let mut nodes = Vec::with_capacity(mpt_nodes.len());
        for (_, mpt_node) in mpt_nodes.iter() {
            nodes.push(mpt_node.clone())
        }
        nodes
    }

    pub fn codes(&self) -> Vec<HexBytes> {
        let codes = self.codes.lock().unwrap();
        let mut result = Vec::with_capacity(codes.len());
        for (_, code) in codes.iter() {
            result.push(code.clone());
        }
        result
    }
}

impl statedb::StateFetcher for TraceBlockStateFetcher {
    type FetchStateResult = FetchStateResult;
    fn fork(&self) -> Self {
        Self {
            fetcher: self.fetcher.fork(),
            block_hashes: self.block_hashes.clone(),
            mpt_nodes: self.mpt_nodes.clone(),
            codes: self.codes.clone(),
        }
    }

    fn with_acc(&self, address: &SH160) -> Self {
        Self {
            fetcher: self.fetcher.with_acc(address),
            mpt_nodes: self.mpt_nodes.clone(),
            block_hashes: self.block_hashes.clone(),
            codes: self.codes.clone(),
        }
    }

    fn get_account(&self, address: &SH160) -> Result<(SU256, u64, HexBytes), Error> {
        // it will call fetch_states
        self.fetcher.get_account(address)
    }

    fn get_block_hash(&self, number: u64) -> Result<SH256, Error> {
        let hash = self.fetcher.get_block_hash(number)?;
        let mut hashes = self.block_hashes.lock().unwrap();
        hashes.insert(number, hash);
        Ok(hash)
    }

    fn get_code(&self, address: &SH160) -> Result<HexBytes, Error> {
        let code = self.fetcher.get_code(address)?;
        self.add_code(&code);
        Ok(code)
    }

    fn get_miss_usage(&self) -> base::trace::AvgCounterResult {
        self.fetcher.get_miss_usage()
    }

    fn get_storage(&self, address: &SH160, key: &SH256) -> Result<SH256, Error> {
        self.fetcher.get_storage(address, key)
    }

    fn prefetch_states(
        &self,
        list: &[FetchState],
        with_proof: bool,
    ) -> Result<Vec<FetchStateResult>, Error> {
        let result = self.fetcher.prefetch_states(list, with_proof)?;
        for item in &result {
            if let Some(acc) = &item.acc {
                self.add_nodes(&acc.account_proof);
            }
            if let Some(code) = &item.code {
                self.add_code(code);
            }
        }
        Ok(result)
    }
}

impl statedb::ProofFetcher for TraceBlockStateFetcher {
    fn fetch_proofs(&self, key: &[u8]) -> Result<Vec<HexBytes>, String> {
        let proofs = self.fetcher.fetch_proofs(key)?;
        self.add_nodes(&proofs);
        Ok(proofs)
    }

    fn get_nodes(&self, node: &[SH256]) -> Result<Vec<HexBytes>, String> {
        let nodes = self.fetcher.get_nodes(node)?;
        self.add_nodes(&nodes);
        Ok(nodes)
    }
}

#[derive(Clone, Debug)]
pub struct BlockStateFetcher {
    client: Arc<ExecutionClient>,
    blk: BlockSelector,
    acc: Option<SH160>,
    counter: AvgCounter,
    block_hashes: Arc<Mutex<BTreeMap<u64, SH256>>>,
}

impl BlockStateFetcher {
    pub fn new(client: Arc<ExecutionClient>, blk: BlockSelector) -> BlockStateFetcher {
        Self {
            client,
            acc: None,
            blk,
            counter: AvgCounter::new(),
            block_hashes: Default::default(),
        }
    }

    pub fn select_blk(&mut self, blk: BlockSelector) {
        self.blk = blk;
    }

    pub fn add_block_hashes_cache(&self, blk_number: u64, hash: SH256) {
        let mut block_hashes = self.block_hashes.lock().unwrap();
        block_hashes.insert(blk_number, hash);
    }
}

impl statedb::StateFetcher for BlockStateFetcher {
    type FetchStateResult = FetchStateResult;
    fn with_acc(&self, address: &SH160) -> Self {
        Self {
            client: self.client.clone(),
            blk: self.blk.clone(),
            acc: Some(address.clone()),
            counter: self.counter.clone(),
            block_hashes: self.block_hashes.clone(),
        }
    }

    fn fork(&self) -> Self {
        self.clone()
    }

    fn get_block_hash(&self, number: u64) -> Result<SH256, statedb::Error> {
        {
            let block_hashes = self.block_hashes.lock().unwrap();
            if let Some(hash) = block_hashes.get(&number) {
                return Ok(*hash);
            }
        }
        let _counter = self.counter.place();

        let header = self
            .client
            .get_block_header(number.into())
            .map_err(|err| statedb::Error::CallRemoteFail(format!("[get_block_hash] {:?}", err)))?;
        Ok(header.hash())
    }

    fn get_account(&self, address: &SH160) -> Result<(SU256, u64, HexBytes), statedb::Error> {
        let _counter = self.counter.place();

        let fetch_state = FetchState {
            access_list: Some(Cow::Owned(TransactionAccessTuple {
                address: address.clone(),
                storage_keys: Vec::new(),
            })),
            code: Some(address.clone()),
        };
        let result = self
            .client
            .fetch_states(&[fetch_state], self.blk, false)
            .map_err(|err| statedb::Error::CallRemoteFail(format!("{:?}", err)))?
            .pop()
            .unwrap();
        let acc = result.acc.unwrap();
        Ok((acc.balance, acc.nonce.as_u64(), result.code.unwrap()))
    }

    fn get_storage(&self, address: &SH160, key: &SH256) -> Result<SH256, statedb::Error> {
        let _counter = self.counter.place();

        Ok(self
            .client
            .get_storage(address, key, self.blk)
            .map_err(|err| statedb::Error::CallRemoteFail(format!("{:?}", err)))?)
    }

    fn get_code(&self, address: &SH160) -> Result<HexBytes, statedb::Error> {
        let _counter = self.counter.place();

        let code = self
            .client
            .get_code(address, self.blk)
            .map_err(|err| statedb::Error::CallRemoteFail(format!("[get_block_hash] {:?}", err)))?;
        Ok(code)
    }

    fn prefetch_states(
        &self,
        list: &[FetchState],
        with_proof: bool,
    ) -> Result<Vec<FetchStateResult>, statedb::Error> {
        self.client
            .fetch_states(list, self.blk, with_proof)
            .map_err(|err| statedb::Error::CallRemoteFail(format!("[get_block_hash] {:?}", err)))
    }

    fn get_miss_usage(&self) -> base::trace::AvgCounterResult {
        self.counter.take()
    }
}

impl statedb::ProofFetcher for BlockStateFetcher {
    fn fetch_proofs(&self, key: &[u8]) -> Result<Vec<HexBytes>, String> {
        let _counter = self.counter.place();
        glog::debug!(exclude: "dry_run", target: "state_fetch", "fetch proof: acc[{:?}] {}", self.acc, HexBytes::from(key));
        match &self.acc {
            Some(acc) => {
                assert_eq!(key.len(), 32);
                let key = H256::from_slice(key).into();
                let result = self
                    .client
                    .get_proof(acc, &[key], self.blk)
                    .map_err(debug)?;
                let storage = result.storage_proof.into_iter().next().unwrap();
                Ok(storage.proof)
            }
            None => {
                assert_eq!(key.len(), 20);
                let account = H160::from_slice(key).into();
                let result = self
                    .client
                    .get_proof(&account, &[], self.blk)
                    .map_err(debug)?;
                Ok(result.account_proof)
            }
        }
    }

    fn get_nodes(&self, node: &[SH256]) -> Result<Vec<HexBytes>, String> {
        let _counter = self.counter.place();

        self.client
            .get_dbnodes(node)
            .map_err(|err| format!("{:?}", err))
    }
}

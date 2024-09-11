use alloy::{eips::BlockId, primitives::{Address, BlockNumber, B256, U256}};
use clients::{Eth, EthError};
use linea_zktrie::Trace;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    MerkleAccountProof, RollupGetZkEVMStateMerkleProofV0Req, RollupGetZkEVMStateMerkleProofV0Resp,
};

#[derive(Clone)]
pub struct Client {
    version: String,
    client: Eth,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ShomeiConfig {
    pub endpoint: String,
    pub version: String,
}

impl Client {
    pub fn new(cfg: ShomeiConfig) -> Result<Client, EthError> {
        let client = Eth::dial(&cfg.endpoint, None)?;
        Ok(Client {
            client,
            version: cfg.version,
        })
    }

    pub async fn fetch_proof_by_traces(
        &self,
        traces: &[Trace],
        blk: BlockId,
    ) -> Result<Vec<MerkleAccountProof>, EthError> {
        let mut acc_list = BTreeMap::new();
        for t in traces {
            let location = t.location();
            let key = t.key();
            if location.len() == 0 {
                // account key
                acc_list.entry(key).or_insert_with(|| BTreeSet::new());
            } else {
                let slot_keys = acc_list.entry(location).or_insert_with(|| BTreeSet::new());
                slot_keys.insert(key);
            };
        }
        let acc_list = acc_list
            .into_iter()
            .map(|n| (n.0, n.1, blk))
            .collect::<Vec<_>>();

        let mut out = <Vec<MerkleAccountProof>>::new();
        for (acc, slots, blk) in acc_list {
            let result = self
                .client
                .client()
                .request("linea_getProof", (acc, slots, blk))
                .await?;
            out.push(result);
        }
        Ok(out)
    }

    pub async fn fetch_account(
        &self,
        acc: &Address,
        slots: &[B256],
        blk: BlockNumber,
    ) -> Result<MerkleAccountProof, EthError> {
        let result = self
            .client
            .client()
            .request("linea_getProof", (acc, slots, blk))
            .await?;
        Ok(result)
    }

    pub async fn fetch_proof(
        &self,
        start: u64,
        end: u64,
    ) -> Result<RollupGetZkEVMStateMerkleProofV0Resp, EthError> {
        let params = RollupGetZkEVMStateMerkleProofV0Req {
            start_block_number: U256::from_limbs_slice(&[start]),
            end_block_number: U256::from_limbs_slice(&[end]),
            zk_state_manager_version: self.version.clone(),
        };
        let result = self
            .client
            .client()
            .request("rollup_getZkEVMStateMerkleProofV0", (params,))
            .await?;
        Ok(result)
    }
}

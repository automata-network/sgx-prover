use std::prelude::v1::*;

use base::trace::Alive;
use eth_types::{BlockSelector, HexBytes, SH160, SH256, SU256};
use jsonrpc::{JsonrpcClient, MixRpcClient, RpcError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zktrie::Trace;

pub struct Client {
    version: String,
    client: JsonrpcClient<MixRpcClient>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ShomeiConfig {
    pub endpoint: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RollupgetZkEVMStateMerkleProofV0Req {
    pub start_block_number: SU256,
    pub end_block_number: SU256,
    pub zk_state_manager_version: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RollupgetZkEVMStateMerkleProofV0Resp {
    pub zk_parent_state_root_hash: SH256,
    pub zk_state_merkle_proof: Vec<Vec<zktrie::Trace>>,
    pub zk_state_manager_version: String,
    pub zk_end_state_root_hash: SH256,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct MerkleAccountProof {
    pub account_proof: MerkleProof,
    pub storage_proofs: Vec<MerkleProof>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct MerkleProof {
    pub key: HexBytes,
    #[serde(flatten)]
    pub inclusion: Option<MerkleInclusionProof>,
    #[serde(flatten)]
    pub non_inclusion: Option<MerkleNonInclusionProof>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct MerkleInclusionProof {
    pub leaf_index: u64,
    pub proof: Proof,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct MerkleNonInclusionProof {
    pub left_proof: Proof,
    pub right_proof: Proof,
    pub left_leaf_index: u64,
    pub right_leaf_index: u64,
}

impl MerkleProof {
    pub fn proof(&self) -> Result<&MerkleInclusionProof, &MerkleNonInclusionProof> {
        if let Some(proof) = &self.inclusion {
            return Ok(proof);
        }
        if let Some(proof) = &self.non_inclusion {
            return Err(proof);
        }
        unreachable!()
    }
    // pub fn inclusion(&self) -> Option<(u64, &Proof)> {
    //     let proof = self.proof.as_ref()?;
    //     let leaf_index = self.leaf_index?;
    //     Some((leaf_index, proof))
    // }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub value: Option<HexBytes>,
    pub proof_related_nodes: Vec<HexBytes>,
}

impl Client {
    pub fn new(alive: &Alive, cfg: ShomeiConfig) -> Client {
        let mut conn = MixRpcClient::new(None);
        conn.add_endpoint(alive, &[cfg.endpoint]).unwrap();
        let client = JsonrpcClient::new(conn);
        Client {
            client,
            version: cfg.version,
        }
    }

    pub fn fetch_proof_by_traces(
        &self,
        traces: &[Trace],
        blk: BlockSelector,
    ) -> Result<Vec<MerkleAccountProof>, RpcError> {
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
        glog::info!("fetch proof: {:?}", acc_list);
        // let data = serde_json::to_string(&acc_list).unwrap();
        let mut out = <Vec<MerkleAccountProof>>::new();
        for (acc, slots, blk) in acc_list {
            let result = self.client.rpc("rollup_getProof", (acc, slots, blk))?;
            out.push(result);
        }
        Ok(out)
    }

    pub fn fetch_account(
        &self,
        acc: &SH160,
        slots: &[SH256],
        blk: BlockSelector,
    ) -> Result<MerkleAccountProof, RpcError> {
        self.client.rpc("rollup_getProof", (acc, slots, blk))
    }

    pub fn fetch_proof(
        &self,
        start: u64,
        end: u64,
    ) -> Result<RollupgetZkEVMStateMerkleProofV0Resp, RpcError> {
        let params = RollupgetZkEVMStateMerkleProofV0Req {
            start_block_number: start.into(),
            end_block_number: end.into(),
            zk_state_manager_version: self.version.clone(),
        };
        let result = self
            .client
            .rpc("rollup_getZkEVMStateMerkleProofV0", (params,))?;
        // glog::info!("result: {:?}", result);
        Ok(result)
    }
}

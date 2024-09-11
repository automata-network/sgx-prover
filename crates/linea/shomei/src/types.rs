use alloy::primitives::{Bytes, B256, U256};
use linea_zktrie::Trace;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RollupGetZkEVMStateMerkleProofV0Req {
    pub start_block_number: U256,
    pub end_block_number: U256,
    pub zk_state_manager_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RollupGetZkEVMStateMerkleProofV0Resp {
    pub zk_parent_state_root_hash: B256,
    pub zk_state_merkle_proof: Vec<Vec<Trace>>,
    pub zk_state_manager_version: String,
    pub zk_end_state_root_hash: B256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct MerkleAccountProof {
    pub account_proof: MerkleProof,
    pub storage_proofs: Vec<MerkleProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct MerkleProof {
    pub key: Bytes,
    #[serde(flatten)]
    pub inclusion: Option<MerkleInclusionProof>,
    #[serde(flatten)]
    pub non_inclusion: Option<MerkleNonInclusionProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct MerkleInclusionProof {
    pub leaf_index: u64,
    pub proof: Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub value: Option<Bytes>,
    pub proof_related_nodes: Vec<Bytes>,
}

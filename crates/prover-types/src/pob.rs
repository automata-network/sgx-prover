use std::collections::BTreeMap;

use alloy_primitives::{Address, Bytes, Keccak256, B256, U256, U64};
use serde::{Deserialize, Serialize};

use crate::{StringInterning, StringInterningReader};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Pob<T = Bytes> {
    pub block: PobBlock,
    pub data: PobData<T>,
    pub hash: B256,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct PobBlock {
    pub miner: Address,
    pub state_root: B256,
    // pub transactions_root: SH256,
    // pub receipts_root: SH256,
    // pub logs_bloom: HexBytes,
    pub difficulty: U256,
    pub number: U64,
    pub gas_limit: U64,
    // pub gas_used: SU64,
    pub timestamp: U64,
    // pub extra_data: HexBytes,
    pub mix_hash: B256,
    // pub nonce: BlockNonce,
    // // BaseFee was added by EIP-1559 and is ignored in legacy headers.
    pub base_fee_per_gas: Option<U256>,
    // // WithdrawalsHash was added by EIP-4895 and is ignored in legacy headers.
    // pub withdrawals_root: Nilable<SH256>,
    pub block_hash: Option<B256>,
    pub transactions: Vec<Bytes>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SuccinctPobList {
    pub pob: Vec<Pob<usize>>,
    pub interning: Bytes,
    pub hash: B256,
}

#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct PobData<T> {
    pub chain_id: u64,
    pub coinbase: Option<Address>,
    pub prev_state_root: B256,
    pub block_hashes: BTreeMap<u64, B256>,
    pub mpt_nodes: Vec<T>,
    pub codes: Vec<T>,
    pub start_l1_queue_index: u64,
    pub withdrawal_root: B256,
}

impl PobData<Bytes> {
    pub fn hash(&self) -> B256 {
        keccak_encode(|hash| {
            hash(&self.chain_id.to_be_bytes());
            hash(self.prev_state_root.as_slice());
            hash(&self.block_hashes.len().to_be_bytes());
            for (blk, block_hash) in &self.block_hashes {
                hash(&blk.to_be_bytes());
                hash(block_hash.as_slice());
            }
            hash(&self.mpt_nodes.len().to_be_bytes());
            for item in &self.mpt_nodes {
                hash(&item);
            }
            hash(&self.codes.len().to_be_bytes());
            for code in &self.codes {
                hash(code);
            }
            hash(&self.start_l1_queue_index.to_be_bytes());
            hash(self.withdrawal_root.as_slice());
        })
        .into()
    }

    pub fn intern(&self, si: &mut StringInterning) -> PobData<usize> {
        PobData {
            chain_id: self.chain_id,
            coinbase: self.coinbase,
            prev_state_root: self.prev_state_root,
            block_hashes: self.block_hashes.clone(),
            mpt_nodes: si.offsets(&self.mpt_nodes),
            codes: si.offsets(&self.codes),
            start_l1_queue_index: self.start_l1_queue_index,
            withdrawal_root: self.withdrawal_root,
        }
    }
}

impl PobData<usize> {
    pub fn unintern(&self, si: &StringInterningReader) -> PobData<Bytes> {
        PobData {
            chain_id: self.chain_id,
            prev_state_root: self.prev_state_root,
            coinbase: self.coinbase,
            block_hashes: self.block_hashes.clone(),
            mpt_nodes: si.read(&self.mpt_nodes),
            codes: si.read(&self.codes),
            start_l1_queue_index: self.start_l1_queue_index,
            withdrawal_root: self.withdrawal_root,
        }
    }
}

impl Pob<Bytes> {
    pub fn new(block: PobBlock, mut data: PobData<Bytes>) -> Self {
        data.mpt_nodes.sort_unstable();
        let hash = B256::default();
        let mut pob = Pob { block, data, hash };
        pob.hash = pob.pob_hash();
        return pob;
    }

    pub fn state_hash(&self) -> B256 {
        // the mpt_nodes should be in order
        keccak_encode(|hash| {
            for item in &self.data.mpt_nodes {
                hash(&item);
            }
        })
        .into()
    }

    pub fn pob_hash(&self) -> B256 {
        keccak_encode(|hash| {
            hash(self.block.block_hash.unwrap_or_default().as_slice());
            hash(self.data.hash().as_slice());
        })
        .into()
    }
}

impl SuccinctPobList {
    pub fn unwrap(self) -> Vec<Pob> {
        let mut out = Vec::new();
        let reader = StringInterningReader::new(&self.interning);
        for pob in self.pob {
            let mut new_pob = Pob {
                block: pob.block,
                data: pob.data.unintern(&reader),
                hash: B256::default(),
            };
            new_pob.hash = new_pob.pob_hash();
            out.push(new_pob);
        }
        out
    }

    pub fn compress(list: &[Pob<Bytes>]) -> SuccinctPobList {
        let mut si = StringInterning::new();
        let hash = keccak_encode(|hash| {
            for item in list {
                hash(item.hash.as_slice());
            }
        });
        let mut pob_list = Vec::with_capacity(list.len());
        for item in list {
            for item in &item.data.mpt_nodes {
                si.collect(item.clone().into());
            }
            for item in &item.data.codes {
                si.collect(item.clone().into());
            }
        }
        si.build();
        for pob in list {
            pob_list.push(Pob {
                block: pob.block.clone(),
                data: pob.data.intern(&mut si),
                hash: pob.hash,
            });
        }

        SuccinctPobList {
            pob: pob_list,
            interning: si.to_compress_bytes().into(),
            hash: hash.into(),
        }
    }
}

pub fn keccak_encode<F>(f: F) -> B256
where
    F: FnOnce(&mut dyn FnMut(&[u8])),
{
    let mut keccak = Keccak256::new();
    f(&mut |data: &[u8]| keccak.update(data));
    keccak.finalize()
}

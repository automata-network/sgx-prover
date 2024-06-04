use std::prelude::v1::*;

use crypto::keccak_encode;
use eth_types::{HexBytes, SH256};
use scroll_types::{Block, BlockHeader, Withdrawal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub struct ProveResult {
    pub new_state_root: SH256,
    pub withdrawal_root: SH256,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Pob<T = HexBytes> {
    pub block: PobBlock,
    pub data: PobData<T>,
    pub hash: SH256,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SuccinctPobList {
    pub pob: Vec<Pob<usize>>,
    pub interning: HexBytes,
    pub hash: SH256,
}

impl SuccinctPobList {
    pub fn unwrap(self) -> Vec<Pob> {
        let mut out = Vec::new();
        let reader = StringInterningReader::new(&self.interning);
        for pob in self.pob {
            let mut new_pob = Pob {
                block: pob.block,
                data: pob.data.unintern(&reader),
                hash: SH256::default(),
            };
            new_pob.hash = new_pob.pob_hash();
            out.push(new_pob);
        }
        out
    }

    pub fn compress(mut list: &[Pob<HexBytes>]) -> SuccinctPobList {
        let mut si = StringInterning::new();
        let hash = keccak_encode(|hash| {
            for item in list {
                hash(item.hash.as_bytes());
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

fn compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    let mut out = Vec::new();
    let mut encoder = libflate::gzip::Encoder::new(&mut out).unwrap();
    encoder.write(&data).unwrap();
    encoder.finish().unwrap();
    out
}

fn uncompress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut decoder = libflate::gzip::Decoder::new(data).unwrap();
    std::io::copy(&mut decoder, &mut out).unwrap();
    out
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PobBlock {
    #[serde(flatten)]
    pub header: BlockHeader,
    pub transactions: Vec<HexBytes>,
    pub withdrawals: Option<Vec<Withdrawal>>, // rlp: optional
}

impl From<Block> for PobBlock {
    fn from(blk: Block) -> Self {
        PobBlock {
            header: blk.header,
            transactions: blk
                .transactions
                .into_iter()
                .map(|n| n.inner().unwrap().to_bytes().into())
                .collect(),
            withdrawals: blk.withdrawals,
        }
    }
}

impl<T: core::cmp::Ord> Pob<T> {
    pub fn block_hash(&self) -> SH256 {
        self.block.header.hash()
    }
}

impl Pob<HexBytes> {
    pub fn new(block: Block, mut data: PobData<HexBytes>) -> Self {
        data.mpt_nodes.sort_unstable();
        let hash = SH256::default();
        let mut pob = Pob {
            block: block.into(),
            data,
            hash,
        };
        pob.hash = pob.pob_hash();
        return pob;
    }

    pub fn state_hash(&self) -> SH256 {
        // the mpt_nodes should be in order
        crypto::keccak_encode(|hash| {
            for item in &self.data.mpt_nodes {
                hash(&item);
            }
        })
        .into()
    }

    pub fn pob_hash(&self) -> SH256 {
        crypto::keccak_encode(|hash| {
            hash(self.block.header.hash().as_bytes());
            hash(self.data.hash().as_bytes());
        })
        .into()
    }
}

#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct PobData<T> {
    pub chain_id: u64,
    pub prev_state_root: SH256,
    pub block_hashes: BTreeMap<u64, SH256>,
    pub mpt_nodes: Vec<T>,
    pub codes: Vec<T>,
    pub start_l1_queue_index: u64,
    pub withdrawal_root: SH256,
}

impl PobData<HexBytes> {
    pub fn hash(&self) -> SH256 {
        crypto::keccak_encode(|hash| {
            hash(&self.chain_id.to_be_bytes());
            hash(self.prev_state_root.as_bytes());
            hash(&self.block_hashes.len().to_be_bytes());
            for (blk, block_hash) in &self.block_hashes {
                hash(&blk.to_be_bytes());
                hash(block_hash.as_bytes());
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
            hash(self.withdrawal_root.as_bytes());
        })
        .into()
    }

    pub fn intern(&self, si: &mut StringInterning) -> PobData<usize> {
        PobData {
            chain_id: self.chain_id,
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
    pub fn unintern(&self, si: &StringInterningReader) -> PobData<HexBytes> {
        PobData {
            chain_id: self.chain_id,
            prev_state_root: self.prev_state_root,
            block_hashes: self.block_hashes.clone(),
            mpt_nodes: si.read(&self.mpt_nodes),
            codes: si.read(&self.codes),
            start_l1_queue_index: self.start_l1_queue_index,
            withdrawal_root: self.withdrawal_root,
        }
    }
}

pub struct StringInterningReader(Vec<u8>);

impl StringInterningReader {
    pub fn new(data: &[u8]) -> Self {
        Self(uncompress(data))
    }

    pub fn read(&self, offs: &[usize]) -> Vec<HexBytes> {
        let mut out = Vec::with_capacity(offs.len());
        let mut len_bytes = [0_u8; 4];
        for off in offs {
            let off = *off;
            len_bytes.copy_from_slice(&self.0[off..off + 4]);
            let len = u32::from_be_bytes(len_bytes) as usize;
            let data = (&self.0[off + 4..off + 4 + len]).to_owned();
            out.push(data.into());
        }
        out
    }
}

pub struct StringInterning {
    data: Vec<u8>,
    total: usize,
    unique: BTreeMap<Vec<u8>, Option<usize>>,
}

impl StringInterning {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            total: 0,
            unique: BTreeMap::new(),
        }
    }

    pub fn collect(&mut self, data: Vec<u8>) {
        self.total += 4 + data.len();
        self.unique.insert(data, None);
    }

    pub fn build(&mut self) {
        let mut data = Vec::with_capacity(self.total);
        for (val, idx) in &mut self.unique {
            *idx = Some(data.len());
            data.extend((val.len() as u32).to_be_bytes());
            data.extend(val);
        }
        self.data = data;
    }

    pub fn offset(&self, lib: &[u8]) -> usize {
        self.unique.get(lib).unwrap().unwrap()
    }

    pub fn offsets(&self, lib: &[HexBytes]) -> Vec<usize> {
        let mut out = Vec::with_capacity(lib.len());
        for item in lib {
            out.push(self.offset(item));
        }
        out
    }

    pub fn to_compress_bytes(&self) -> Vec<u8> {
        compress(&self.data)
    }
}

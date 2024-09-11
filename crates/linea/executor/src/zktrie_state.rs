use std::sync::Arc;

use alloy::primitives::{keccak256, B256, U256};
use base::{BufferBeEncode, BufferVec, BufferWriteBytes, PrimitivesConvert};
use linea_zktrie::{mimc_safe_code_hash, Database};
use serde::{Deserialize, Serialize};

pub fn account_key(acc: &[u8]) -> B256 {
    linea_zktrie::hash(acc)
}

pub fn storage_slot(slot: &[u8]) -> B256 {
    linea_zktrie::mimc_safe(slot).unwrap()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZkStateAccount {
    pub nonce: u64,
    pub balance: U256,
    pub root: B256,
    pub mimc_code_hash: B256,
    pub keccak_code_hash: B256,
    pub code_size: U256,
}

impl Default for ZkStateAccount {
    fn default() -> Self {
        ZkStateAccount {
            nonce: 0,
            balance: U256::default(),
            root: linea_zktrie::EMPTY_TRIE_NODE_HASH.clone(),
            mimc_code_hash: *linea_zktrie::EMPTY_MIMC_CODE_HASH,
            keccak_code_hash: *linea_zktrie::EMPTY_KECCAK_CODE_HASH,
            code_size: U256::default(),
        }
    }
}

impl ZkStateAccount {
    pub fn is_exist(&self) -> bool {
        self != &Self::default()
    }

    pub fn set_code<D: Database>(&mut self, dirty: &mut bool, code: Vec<u8>, db: &mut D) {
        let hash = keccak256(&code);
        if self.keccak_code_hash != hash {
            self.keccak_code_hash = hash;
            self.mimc_code_hash = mimc_safe_code_hash(&code);
            self.code_size = code.len().to();
            db.set_code(hash, Arc::new(code.into()));
            *dirty = true;
        }
    }

    pub fn set_nonce(&mut self, dirty: &mut bool, val: u64) {
        if self.nonce != val {
            self.nonce = val;
            *dirty = true;
        }
    }

    pub fn set_root(&mut self, dirty: &mut bool, root_hash: B256) {
        if self.root != root_hash {
            self.root = root_hash;
            *dirty = true;
        }
    }

    pub fn set_balance(&mut self, dirty: &mut bool, val: U256) -> U256 {
        if self.balance != val {
            self.balance = val;
            *dirty = true;
        }
        self.balance
    }

    pub fn suicide(&mut self, dirty: &mut bool) {
        if self.is_exist() {
            *self = Self::default();
            *dirty = true;
        }
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() == 0 {
            return Some(Self::default());
        }
        let mut buf = BufferVec::from_slice(buf, buf.len());
        let nonce = buf.read_be()?.to();
        let balance = buf.read_be()?;
        let root = buf.read_bytes()?;
        let mimc_code_hash = buf.read_bytes()?;
        let keccak_code_hash = buf.read_bytes()?;
        let code_size = buf.read_be()?;
        let acc = Self {
            nonce,
            balance,
            root,
            mimc_code_hash,
            keccak_code_hash,
            code_size,
        };

        Some(acc)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BufferVec::new(192);
        buf.write_be(&U256::from(self.nonce))
            .write_be(&self.balance)
            .write_bytes(&self.root)
            .write_bytes(&self.mimc_code_hash)
            .write_bytes(&self.keccak_code_hash)
            .write_be(&self.code_size);
        buf.to_vec()
    }

    pub fn encode_mimc_safe(&self) -> Vec<u8> {
        if self == &Self::default() {
            return Vec::new();
        }

        let mut buf = BufferVec::new(224);
        buf.write_be(&U256::from(self.nonce))
            .write_be(&self.balance)
            .write_bytes(&self.root)
            .write_bytes(&self.mimc_code_hash);

        buf.advance(16);
        buf.copy_from(&self.keccak_code_hash.as_slice()[16..]);
        buf.advance(16);
        buf.copy_from(&self.keccak_code_hash.as_slice()[..16]);

        buf.write_be(&self.code_size);
        buf.to_vec()
    }
}

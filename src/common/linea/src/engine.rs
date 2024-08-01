use std::prelude::v1::*;

use bytes::{BufferVec, WriteBuffer};
use crypto::keccak_hash;
use eth_types::{
    Block, BlockHeader, HexBytes, Receipt, Signer, StateAccountTrait, TransactionInner, Withdrawal,
    SH160, SH256, SU256,
};
use evm_executor::BlockHashGetter;
use evm_executor::{ExecuteResult, PrecompileSet, TxContext};
use serde::{Deserialize, Serialize};
use statedb::StateDB;
use std::sync::Arc;
use zktrie::{mimc_safe, mimc_safe_encode, Database, EMPTY_MIMC_CODE_HASH, mimc_safe_code_hash};

use crate::{CacheValueEnc, ZkTrieValue};

#[derive(Debug, Clone)]
pub struct Linea {
    chain_id: SU256,
}

impl Linea {
    pub fn new(chain_id: SU256) -> Self {
        Self { chain_id }
    }

    fn seal_hash(header: &BlockHeader) -> [u8; 32] {
        // Remove the last 65 bytes of extra_data
        let extra_data: HexBytes = header.extra_data[..header.extra_data.len() - 65].into();
        // May need to handle the case where base_fee_per_gas is nil
        // https://github.com/ethereum/go-ethereum/blob/81fd1b3cf9c4c4c9f0e06f8bdcbaa8b29c81b052/consensus/clique/clique.go#L763
        let mut s = rlp::RlpStream::new_list(16);
        s.append(&header.parent_hash);
        s.append(&header.sha3_uncles);
        s.append(&header.miner);
        s.append(&header.state_root);
        s.append(&header.transactions_root);
        s.append(&header.receipts_root);
        s.append(&header.logs_bloom);
        s.append(&header.difficulty);
        s.append(&header.number);
        s.append(&header.gas_limit);
        s.append(&header.gas_used);
        s.append(&header.timestamp);
        s.append(&extra_data);
        s.append(&header.mix_hash);
        s.append(&header.nonce);
        s.append(&header.base_fee_per_gas);

        let data = s.out().to_vec();
        return crypto::keccak_hash(&data);
    }
}

impl evm_executor::Engine for Linea {
    type Block = Block;
    type BlockHeader = BlockHeader;
    type Receipt = Receipt;
    type Transaction = TransactionInner;
    type Withdrawal = Withdrawal;
    type NewBlockContext = ();

    fn new_block_header(
        &self,
        prev_header: &Self::BlockHeader,
        _ctx: Self::NewBlockContext,
    ) -> Self::BlockHeader {
        Self::BlockHeader {
            ..prev_header.clone()
        }
    }

    fn build_receipt(
        &self,
        cumulative_gas_used: u64,
        result: &ExecuteResult,
        tx_idx: usize,
        tx: &Self::Transaction,
        _header: &Self::BlockHeader,
    ) -> Self::Receipt {
        let tx_hash = tx.hash();
        let mut receipt = Receipt {
            status: (result.success as u64).into(),
            transaction_hash: tx_hash,
            transaction_index: (tx_idx as u64).into(),
            r#type: Some(tx.ty().into()),
            gas_used: result.used_gas.into(),
            cumulative_gas_used: (cumulative_gas_used + result.used_gas).into(),
            logs: result
                .logs
                .clone()
                .into_iter()
                .map(|mut n| {
                    n.transaction_hash = tx_hash;
                    n
                })
                .collect::<Vec<_>>(),
            logs_bloom: HexBytes::new(),

            // not affect the rlp encoding
            contract_address: None,
            root: None,
            block_hash: None,
            block_number: None,
        };
        receipt.logs_bloom = eth_types::create_bloom([&receipt].into_iter()).to_hex();
        receipt
    }

    fn evm_config(&self) -> evm::Config {
        evm::Config::london()
    }

    fn precompile(&self) -> PrecompileSet {
        PrecompileSet::berlin()
    }

    fn signer(&self) -> Signer {
        Signer::new(self.chain_id)
    }

    fn process_withdrawals<D: StateDB>(
        &mut self,
        _statedb: &mut D,
        _withdrawals: &[Self::Withdrawal],
    ) -> Result<(), statedb::Error> {
        Ok(())
    }

    fn author(&self, header: &Self::BlockHeader) -> Result<Option<SH160>, String> {
        let extra_data = header.extra_data.as_bytes();
        let mut sig_array = [0_u8; 65];
        sig_array.copy_from_slice(&extra_data[extra_data.len() - 65..]);
        let msg = Self::seal_hash(header);
        let pub_key_array =
            crypto::secp256k1_ecdsa_recover(&sig_array, &msg).ok_or("fail to ecrecover")?;
        let pub_key = crypto::Secp256k1PublicKey::from_raw_bytes(&pub_key_array);
        let author = pub_key.eth_accountid().into();

        Ok(Some(author))
    }

    fn tx_context<'a, H: BlockHashGetter>(
        &self,
        ctx: &mut TxContext<'a, Self::Transaction, Self::BlockHeader, H>,
    ) {
        ctx.block_base_fee = ctx.header.base_fee_per_gas;
        ctx.difficulty = ctx.header.difficulty;
    }

    fn finalize_block<D: StateDB>(
        &mut self,
        _statedb: &mut D,
        header: Self::BlockHeader,
        txs: Vec<Arc<Self::Transaction>>,
        receipts: Vec<Self::Receipt>,
        withdrawals: Option<Vec<Self::Withdrawal>>,
    ) -> Result<Self::Block, String> {
        Ok(Block::new(header, txs, &receipts, withdrawals))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ZkStateAccount {
    pub nonce: u64,
    pub balance: SU256,
    pub root: SH256,
    pub mimc_code_hash: SH256,
    pub keccak_code_hash: SH256,
    pub code_size: SU256,
}

impl Default for ZkStateAccount {
    fn default() -> Self {
        ZkStateAccount {
            nonce: 0,
            balance: 0.into(),
            root: zktrie::EMPTY_TRIE_NODE_HASH.clone(),
            mimc_code_hash: *zktrie::EMPTY_MIMC_CODE_HASH,
            keccak_code_hash: *zktrie::EMPTY_KECCAK_CODE_HASH,
            code_size: 0.into(),
        }
    }
}

impl ZkStateAccount {
    pub fn is_exist(&self) -> bool {
        self != &Self::default()
    }

    pub fn set_code<D: Database>(&mut self, dirty: &mut bool, code: Vec<u8>, db: &mut D) {
        let hash = keccak_hash(&code).into();
        if self.keccak_code_hash != hash {
            self.keccak_code_hash = hash;
            self.mimc_code_hash = mimc_safe_code_hash(&code);
            self.code_size = code.len().into();
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

    pub fn set_root(&mut self, dirty: &mut bool, root_hash: SH256) {
        if self.root != root_hash {
            self.root = root_hash;
            *dirty = true;
        }
    }

    pub fn set_balance(&mut self, dirty: &mut bool, val: SU256) -> SU256 {
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

    pub fn to_mimc_safe_bytes(&self) -> Vec<u8> {
        if self == &Self::default() {
            return Vec::new();
        }
        let mut buf = vec![0_u8; 224];
        let nonce: SU256 = self.nonce.into();
        nonce.to_big_endian(&mut buf[..32]);
        let mut off = 32;
        self.balance.to_big_endian(&mut buf[off..off + 32]);
        off += 32;
        &mut buf[off..off + 32].copy_from_slice(self.root.as_bytes());
        off += 32;
        &mut buf[off..off + 32].copy_from_slice(self.mimc_code_hash.as_bytes());
        off += 32;
        &mut buf[off + 16..off + 32].copy_from_slice(&self.keccak_code_hash.as_bytes()[..16]);
        off += 32;
        &mut buf[off + 16..off + 32].copy_from_slice(&self.keccak_code_hash.as_bytes()[16..]);
        off += 32;
        self.code_size.to_big_endian(&mut buf[off..off + 32]);
        buf
    }
}

// impl CacheValueEnc for ZkStateAccount {
//     fn decode(buf: &[u8]) -> Result<Self, String> {
//         Ok(ZkStateAccount::from_bytes(buf))
//     }
// }

impl ZkTrieValue for ZkStateAccount {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    fn decode(mut buf: &[u8]) -> Result<Self, String> {
        if buf.len() == 0 {
            return Ok(Self::default());
        }
        let mut read_buf = || {
            let tmp = &buf[..32];
            buf = &buf[32..];
            tmp
        };
        let nonce = SU256::from_big_endian(read_buf()).as_u64();
        let balance = SU256::from_big_endian(read_buf());
        let root = SH256::from_slice(read_buf());
        let mimc_code_hash = SH256::from_slice(read_buf());
        let keccak_code_hash = SH256::from_slice(read_buf());
        let code_size = SU256::from_big_endian(read_buf());
        let acc = Self {
            nonce,
            balance,
            root,
            mimc_code_hash,
            keccak_code_hash,
            code_size,
        };

        glog::info!("acc: {:?}", acc);
        Ok(acc)
    }

    fn encode(&self) -> Vec<u8> {
        let mut buf = BufferVec::new(192);

        SU256::from(self.nonce).to_big_endian(buf.must_write(32));
        self.balance.to_big_endian(buf.must_write(32));
        buf.copy_from(self.root.as_bytes());
        buf.copy_from(self.mimc_code_hash.as_bytes());
        buf.copy_from(self.keccak_code_hash.as_bytes());
        self.code_size.to_big_endian(buf.must_write(32));
        buf.to_vec()
    }

    fn encode_mimc_safe(&self) -> Vec<u8> {
        let mut buf = BufferVec::new(224);

        SU256::from(self.nonce).to_big_endian(buf.must_write(32));
        self.balance.to_big_endian(&mut buf.must_write(32));
        buf.copy_from(self.root.as_bytes());
        buf.copy_from(self.mimc_code_hash.as_bytes());
        buf.advance(16);
        buf.copy_from(&self.keccak_code_hash.as_bytes()[16..]);
        buf.advance(16);
        buf.copy_from(&self.keccak_code_hash.as_bytes()[..16]);
        self.code_size.to_big_endian(buf.must_write(32));
        buf.to_vec()
    }
}

#[derive(Debug, Default, Clone)]
pub struct StorageValue(pub SH256);

impl StorageValue {
    pub fn set_val(&mut self, dirty: &mut bool, val: SH256) {
        if self.0 != val {
            self.0 = val;
            *dirty = true;
        }
    }
}

impl ZkTrieValue for StorageValue {
    fn is_empty(&self) -> bool {
        self.0 == SH256::default()
    }

    fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() == 0 {
            return Ok(Self::default());
        }
        assert!(data.len() <= 32);
        let mut out = SH256::default();
        out.0[32 - data.len()..].copy_from_slice(&data);
        Ok(Self(out))
    }

    fn encode(&self) -> Vec<u8> {
        self.0 .0.to_vec()
    }

    fn encode_mimc_safe(&self) -> Vec<u8> {
        mimc_safe_encode(self.0.as_bytes()).to_vec()
    }
}

impl std::ops::Deref for StorageValue {
    type Target = SH256;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl rlp::Encodable for StorageValue {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        let idx = self.0.as_bytes().iter().position(|n| *n != 0);
        if let Some(idx) = idx {
            s.append(&&self.0.as_bytes()[idx..]);
        }
    }
}

impl rlp::Decodable for StorageValue {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        if rlp.is_null() {
            return Ok(StorageValue::default());
        }
        let data = rlp.as_raw();
        assert!(data.len() <= 32);
        let mut out = SH256::default();
        out.0[32 - data.len()..].copy_from_slice(&data);
        Ok(Self(out))
    }
}

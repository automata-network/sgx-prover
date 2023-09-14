use std::prelude::v1::*;

use super::{Transaction, TransactionInner};
use crypto::keccak_hash;
use eth_types::{
    BlockNonce, Bloom, HexBytes, KeccakHasher, Nilable, Receipt, SH160, SH256, SU256, SU64,
};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};
use std::iter::Iterator;
use std::sync::Arc;

#[derive(
    Default, Clone, Debug, Deserialize, Serialize, RlpEncodable, RlpDecodable, PartialEq, Eq,
)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub parent_hash: SH256,
    pub sha3_uncles: SH256,
    pub miner: SH160,
    pub state_root: SH256,
    pub transactions_root: SH256,
    pub receipts_root: SH256,
    pub logs_bloom: HexBytes,
    pub difficulty: SU256,
    pub number: SU64,
    pub gas_limit: SU64,
    pub gas_used: SU64,
    pub timestamp: SU64,
    pub extra_data: HexBytes,
    pub mix_hash: SH256,
    pub nonce: BlockNonce,
    // BaseFee was added by EIP-1559 and is ignored in legacy headers.
    pub base_fee_per_gas: Option<SU256>,
    // WithdrawalsHash was added by EIP-4895 and is ignored in legacy headers.
    pub withdrawals_root: Nilable<SH256>,
}

impl BlockHeader {
    pub fn hash(&self) -> SH256 {
        let data = rlp::encode(self).to_vec();
        let mut hash = SH256::default();
        hash.as_bytes_mut().copy_from_slice(&keccak_hash(&data));
        return hash;
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    #[serde(flatten)]
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub withdrawals: Option<Vec<Withdrawal>>, // rlp: optional
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    pub index: SU64,
    pub validator_index: SU64,
    pub address: SH160,
    pub amount: SU64,
}

impl rlp::Encodable for Withdrawal {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_unbounded_list();
        s.append(&self.index);
        s.append(&self.validator_index);
        s.append(&self.address.as_bytes());
        s.append(&self.amount);
        s.finalize_unbounded_list();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockSimple {
    #[serde(flatten)]
    pub header: BlockHeader,
    pub transactions: Vec<SH256>,
    pub withdrawals: Option<Vec<Withdrawal>>, // rlp: optional
}

impl Block {
    pub fn new(
        mut header: BlockHeader,
        txs: Vec<Arc<TransactionInner>>,
        receipts: &[Receipt],
        withdrawals: Option<Vec<Withdrawal>>,
    ) -> Self {
        assert_eq!(txs.len(), receipts.len());
        let empty_root_hash: SH256 =
            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".into();
        if txs.len() == 0 {
            header.transactions_root = empty_root_hash.clone();
        } else {
            let txs: Vec<_> = txs.iter().map(|tx| tx.to_bytes()).collect();
            header.transactions_root = triehash::ordered_trie_root::<KeccakHasher, _>(txs).into();
        }
        if receipts.len() == 0 {
            header.receipts_root = empty_root_hash.clone();
        } else {
            header.logs_bloom = create_bloom(receipts.iter()).to_hex();
            let rs: Vec<_> = receipts.iter().map(|r| r.rlp_bytes()).collect();
            header.receipts_root = triehash::ordered_trie_root::<KeccakHasher, _>(rs).into();
        }
        header.sha3_uncles =
            "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".into();
        let transactions = txs
            .iter()
            .map(|tx| tx.as_ref().clone().to_transaction(Some(&header)))
            .collect();

        if let Some(withdrawals) = &withdrawals {
            header.withdrawals_root = Some(withdrawal_root(&withdrawals)).into();
        }

        Block {
            header,
            transactions,
            withdrawals,
        }
    }
}

pub fn withdrawal_root(withdrawals: &[Withdrawal]) -> SH256 {
    if withdrawals.len() == 0 {
        "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".into()
    } else {
        let wd: Vec<Vec<u8>> = withdrawals.iter().map(|r| rlp::encode(r).into()).collect();
        triehash::ordered_trie_root::<KeccakHasher, _>(wd).into()
    }
}

pub fn create_bloom<'a>(receipts: impl Iterator<Item = &'a Receipt>) -> Bloom {
    let mut buf = [0_u8; 6];
    let mut bin = Bloom::new();
    for receipt in receipts {
        for log in &receipt.logs {
            bin.add(&log.address.raw().0[..], &mut buf);
            for b in &log.topics {
                bin.add(&b.raw().0[..], &mut buf);
            }
        }
    }
    return bin;
}

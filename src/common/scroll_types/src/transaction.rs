use std::prelude::v1::*;

use super::{BlockHeader, Signer};
use crypto::{
    keccak_hash, secp256k1_rec_sign_bytes, Secp256k1PrivateKey, Secp256k1RecoverableSignature,
};
use eth_types::{
    AccessListTx, DynamicFeeTx, Hasher, HexBytes, LegacyTx, Nilable, TransactionAccessTuple, SH160,
    SH256, SU256, SU64,
};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::sync::Arc;

pub const L1_MESSAGE_TX_TYPE: u8 = 0x7E;
pub const L1_MESSAGE_TX_TYPE_U64: u64 = L1_MESSAGE_TX_TYPE as _;

lazy_static::lazy_static! {
    pub static ref ZERO: SU256 = SU256::default();
}

#[derive(
    Default, Clone, Debug, Deserialize, Serialize, RlpEncodable, RlpDecodable, PartialEq, Eq,
)]
#[serde(rename_all = "camelCase")]
pub struct L1MessageTx {
    pub queue_index: SU64,
    pub gas: SU64,          // gas limit
    pub to: Nilable<SH160>, // can not be nil, we do not allow contract creation from L1
    pub value: SU256,
    pub data: HexBytes,
    pub sender: SH160,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub block_hash: Option<SH256>,
    pub block_number: Option<SU64>,
    pub from: Option<SH160>,
    pub gas: SU64,
    pub gas_price: Option<SU256>,
    pub max_fee_per_gas: Option<SU256>,
    pub max_priority_fee_per_gas: Option<SU256>,
    pub hash: SH256,
    pub input: HexBytes,
    pub nonce: SU64,
    pub to: Option<SH160>,
    pub transaction_index: Option<SU64>,
    pub value: SU256,
    pub r#type: SU64,
    pub access_list: Option<Vec<TransactionAccessTuple>>,
    pub chain_id: Option<SU256>,
    pub v: SU256,
    pub r: SU256,
    pub s: SU256,

    // L1 message transaction fields:
    pub sender: Option<SH160>,
    pub queue_index: Option<SU64>,
}

impl rlp::Encodable for TransactionInner {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        match self {
            TransactionInner::Legacy(tx) => tx.rlp_append(s),
            TransactionInner::AccessList(tx) => {
                const PREFIX: [u8; 1] = [1];
                s.append_raw(&PREFIX, 0);
                tx.rlp_append(s);
            }
            TransactionInner::DynamicFee(tx) => {
                const PREFIX: [u8; 1] = [2];
                s.append_raw(&PREFIX, 0);
                tx.rlp_append(s);
            }
            TransactionInner::L1Message(tx) => {
                const PREFIX: [u8; 1] = [L1_MESSAGE_TX_TYPE];
                s.append_raw(&PREFIX, 0);
                tx.rlp_append(s);
            }
        }
    }
}

impl rlp::Decodable for TransactionInner {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        if rlp.is_list() {
            return Ok(Self::Legacy(LegacyTx::decode(rlp)?));
        }
        let n = rlp.as_raw();
        if n.len() < 1 {
            return Err(rlp::DecoderError::RlpIsTooShort);
        }

        match n[0] {
            1 => Ok(Self::AccessList(rlp::decode(&n[1..])?)),
            2 => Ok(Self::DynamicFee(rlp::decode(&n[1..])?)),
            L1_MESSAGE_TX_TYPE => Ok(Self::L1Message(rlp::decode(&n[1..])?)),
            _ => Err(rlp::DecoderError::Custom("unknown tx prefix")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionInner {
    Legacy(LegacyTx),
    AccessList(AccessListTx),
    DynamicFee(DynamicFeeTx),
    L1Message(L1MessageTx),
}

impl Serialize for TransactionInner {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let tx: HexBytes = self.to_bytes().into();
        serializer.serialize_str(&format!("{}", tx))
    }
}

impl<'de> Deserialize<'de> for TransactionInner {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: HexBytes = Deserialize::deserialize(deserializer)?;
        TransactionInner::from_bytes(&s)
            .map_err(|err| serde::de::Error::custom(format!("{:?}", err)))
    }
}

impl core::cmp::PartialOrd for TransactionInner {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl core::cmp::Ord for TransactionInner {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl TransactionInner {
    pub fn extra_fee(&self) -> bool {
        !matches!(self, Self::L1Message(_))
    }

    pub fn can_check_nonce(&self) -> bool {
        !matches!(self, Self::L1Message(_))
    }

    pub fn cost_gas(&self) -> bool {
        !matches!(self, Self::L1Message(_))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        rlp::encode(self).to_vec()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, rlp::DecoderError> {
        rlp::decode(data)
    }

    pub fn to_transaction(self, header: Option<&BlockHeader>) -> Transaction {
        let mut target = Transaction::default();
        target.hash = self.hash();
        match self {
            Self::Legacy(tx) => {
                target.r#type = 0.into();
                target.nonce = tx.nonce;
                target.gas_price = Some(tx.gas_price);
                target.gas = tx.gas;
                target.to = tx.to.into();
                target.value = tx.value;
                target.input = tx.data;
                target.v = tx.v;
                target.r = tx.r;
                target.s = tx.s;
            }
            Self::AccessList(tx) => {
                target.r#type = 1.into();
                target.chain_id = Some(tx.chain_id);
                target.nonce = tx.nonce;
                target.gas_price = Some(tx.gas_price);
                target.gas = tx.gas;
                target.to = tx.to.into();
                target.value = tx.value;
                target.input = tx.data;
                target.access_list = Some(tx.access_list);
                target.v = tx.v;
                target.r = tx.r;
                target.s = tx.s;
            }
            Self::DynamicFee(tx) => {
                target.r#type = 2.into();
                target.chain_id = Some(tx.chain_id);
                target.nonce = tx.nonce;
                target.max_priority_fee_per_gas = Some(tx.max_priority_fee_per_gas);
                target.max_fee_per_gas = Some(tx.max_fee_per_gas.clone());
                target.gas = tx.gas;
                target.gas_price = Some(tx.max_fee_per_gas.clone()); // maybe wrong if we have block info
                if let Some(header) = header {
                    if let Some(base_fee) = header.base_fee_per_gas {
                        let gas_tip_cap = tx.max_priority_fee_per_gas.clone();
                        let gas_fee_cap = tx.max_fee_per_gas.clone();
                        target.gas_price = Some(
                            gas_fee_cap
                                .raw()
                                .clone()
                                .min(base_fee.raw().clone() + gas_tip_cap.raw())
                                .into(),
                        );
                    }
                }
                target.to = tx.to.into();
                target.value = tx.value;
                target.input = tx.data;
                target.access_list = Some(tx.access_list);
                target.v = tx.v;
                target.r = tx.r;
                target.s = tx.s;
            }
            Self::L1Message(tx) => {
                target.r#type = (L1_MESSAGE_TX_TYPE as u64).into();
                target.gas = tx.gas;
                target.input = tx.data;
                target.nonce = tx.queue_index;
                target.to = tx.to.into();
                target.value = tx.value;
                target.sender = Some(tx.sender);
                target.queue_index = Some(tx.queue_index);
                // v, r, s = 0
                // target.gas_price = 0.into();
            }
        }
        if let Some(header) = header {
            target.block_hash = Some(header.hash());
            target.block_number = Some(header.number.as_u64().into());
        }
        target
    }

    pub fn value(&self) -> SU256 {
        match self {
            Self::Legacy(tx) => tx.value.clone(),
            Self::DynamicFee(tx) => tx.value.clone(),
            Self::AccessList(tx) => tx.value.clone(),
            Self::L1Message(tx) => tx.value.clone(),
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            Self::Legacy(tx) => tx.nonce.as_u64(),
            Self::DynamicFee(tx) => tx.nonce.as_u64(),
            Self::AccessList(tx) => tx.nonce.as_u64(),
            Self::L1Message(tx) => tx.queue_index.as_u64(),
        }
    }

    pub fn gas_limit(&self) -> u64 {
        match self {
            Self::Legacy(tx) => tx.gas.as_u64(),
            Self::DynamicFee(tx) => tx.gas.as_u64(),
            Self::AccessList(tx) => tx.gas.as_u64(),
            Self::L1Message(tx) => tx.gas.as_u64(),
        }
    }

    pub fn gas_price(&self, base_fee: Option<SU256>) -> SU256 {
        match self {
            Self::Legacy(tx) => tx.gas_price,
            Self::AccessList(tx) => tx.gas_price,
            Self::DynamicFee(tx) => match base_fee {
                Some(base_fee) => tx
                    .max_fee_per_gas
                    .min(base_fee + &tx.max_priority_fee_per_gas),
                None => tx.max_fee_per_gas,
            },
            Self::L1Message(_) => 0.into(),
        }
    }

    pub fn cost(&self, base_fee: Option<SU256>) -> SU256 {
        let gas: SU256 = self.gas().into();
        let gas_price = self.gas_price(base_fee);
        let value = self.value();
        (gas * gas_price) + value
    }

    pub fn access_list(&self) -> Option<&[TransactionAccessTuple]> {
        match self {
            Self::Legacy(_) => None,
            Self::DynamicFee(tx) => Some(&tx.access_list),
            Self::AccessList(tx) => Some(&tx.access_list),
            Self::L1Message(_) => None,
        }
    }

    pub fn max_fee_per_gas(&self) -> &SU256 {
        match self {
            Self::Legacy(tx) => &tx.gas_price,
            Self::DynamicFee(tx) => &tx.max_fee_per_gas,
            Self::AccessList(tx) => &tx.gas_price,
            Self::L1Message(_) => ZERO.deref(),
        }
    }

    pub fn reward(&self, gas: u64, base_fee: Option<&SU256>) -> Option<SU256> {
        self.effective_gas_tip(base_fee)
            .map(|item| item * SU256::from(gas))
    }

    pub fn effective_gas_tip(&self, base_fee: Option<&SU256>) -> Option<SU256> {
        match base_fee {
            None => Some(self.max_priority_fee_per_gas().clone()),
            Some(base_fee) => {
                let gas_fee_cap = self.max_fee_per_gas();
                if gas_fee_cap < base_fee {
                    None
                } else {
                    Some(
                        self.max_priority_fee_per_gas()
                            .clone()
                            .min(gas_fee_cap - base_fee),
                    )
                }
            }
        }
    }

    pub fn max_priority_fee_per_gas(&self) -> &SU256 {
        match self {
            Self::Legacy(tx) => &tx.gas_price,
            Self::DynamicFee(tx) => &tx.max_priority_fee_per_gas,
            Self::AccessList(tx) => &tx.gas_price,
            Self::L1Message(_) => ZERO.deref(),
        }
    }

    pub fn input(&self) -> &[u8] {
        match self {
            Self::Legacy(tx) => &tx.data,
            Self::DynamicFee(tx) => &tx.data,
            Self::AccessList(tx) => &tx.data,
            Self::L1Message(tx) => &tx.data,
        }
    }

    pub fn gas(&self) -> SU64 {
        match self {
            Self::Legacy(tx) => tx.gas.clone(),
            Self::DynamicFee(tx) => tx.gas.clone(),
            Self::AccessList(tx) => tx.gas.clone(),
            Self::L1Message(tx) => tx.gas.clone(),
        }
    }

    pub fn to(&self) -> Option<SH160> {
        match self {
            Self::Legacy(tx) => tx.to.clone().into(),
            Self::DynamicFee(tx) => tx.to.clone().into(),
            Self::AccessList(tx) => tx.to.clone().into(),
            Self::L1Message(tx) => tx.to.clone().into(),
        }
    }

    pub fn sender(&self, signer: &Signer) -> SH160 {
        signer.sender(self)
    }

    pub fn signature(&self, chain_id: u64) -> Secp256k1RecoverableSignature {
        match self {
            Self::Legacy(tx) => {
                let v = match tx.v.as_u64() {
                    0 | 1 => tx.v.as_u64(),
                    27 | 28 => tx.v.as_u64() - 27,
                    _protected => tx.v.as_u64() - chain_id * 2 - 8 - 27,
                };
                Secp256k1RecoverableSignature {
                    v: v as _,
                    r: tx.r.clone().into(),
                    s: tx.s.clone().into(),
                }
            }
            Self::DynamicFee(tx) => Secp256k1RecoverableSignature {
                v: tx.v.as_u32() as _,
                r: tx.r.clone().into(),
                s: tx.s.clone().into(),
            },
            Self::AccessList(tx) => Secp256k1RecoverableSignature {
                v: tx.v.as_u32() as _,
                r: tx.r.clone().into(),
                s: tx.s.clone().into(),
            },
            Self::L1Message(_) => Secp256k1RecoverableSignature::default(),
        }
    }

    pub fn ty(&self) -> u64 {
        match self {
            Self::Legacy(_) => 0,
            Self::AccessList(_) => 1,
            Self::DynamicFee(_) => 2,
            Self::L1Message(_) => L1_MESSAGE_TX_TYPE as u64,
        }
    }

    pub fn sign(&mut self, prvkey: &Secp256k1PrivateKey, chain_id: u64) {
        match self {
            Self::Legacy(tx) => {
                tx.v = chain_id.into();
                tx.r = 0.into();
                tx.s = 0.into();
            }
            Self::DynamicFee(tx) => {
                tx.v = 0.into();
                tx.r = 0.into();
                tx.s = 0.into();
            }
            Self::AccessList(tx) => {
                tx.v = 0u64.into();
                tx.r = 0u64.into();
                tx.s = 0u64.into();
            }
            Self::L1Message(_) => {}
        }
        let signed_txn_bytes = self.to_bytes();
        let rec_sig = secp256k1_rec_sign_bytes(prvkey, &signed_txn_bytes);
        match self {
            Self::Legacy(tx) => {
                tx.v = (u64::from(rec_sig.v) + chain_id * 2 + 35).into();
                tx.r = rec_sig.r.into();
                tx.s = rec_sig.s.into();
            }
            Self::DynamicFee(tx) => {
                tx.v = u64::from(rec_sig.v).into();
                tx.r = rec_sig.r.into();
                tx.s = rec_sig.s.into();
            }
            Self::AccessList(tx) => {
                tx.v = u64::from(rec_sig.v).into();
                tx.r = rec_sig.r.into();
                tx.s = rec_sig.s.into();
            }
            Self::L1Message(_) => {}
        }
    }

    pub fn hash(&self) -> SH256 {
        Hasher::hash(self)
    }
}

impl Hasher for TransactionInner {
    fn hash(&self) -> SH256 {
        let data = rlp::encode(self).to_vec();
        let mut hash = SH256::default();
        hash.as_bytes_mut().copy_from_slice(&keccak_hash(&data));
        hash
    }
}

impl Transaction {
    pub fn inner(self) -> Option<TransactionInner> {
        Some(match self.r#type.as_u64() {
            0 => TransactionInner::Legacy(LegacyTx {
                nonce: self.nonce,
                gas_price: self.gas_price?,
                gas: self.gas,
                to: self.to.into(),
                value: self.value,
                data: self.input,
                v: self.v,
                r: self.r,
                s: self.s,
            }),
            1 => TransactionInner::AccessList(AccessListTx {
                chain_id: self.chain_id?,
                nonce: self.nonce,
                gas_price: self.gas_price?,
                gas: self.gas,
                to: self.to.into(),
                value: self.value,
                data: self.input,
                access_list: self.access_list?,
                v: self.v,
                r: self.r,
                s: self.s,
            }),
            2 => TransactionInner::DynamicFee(DynamicFeeTx {
                chain_id: self.chain_id?,
                nonce: self.nonce,
                max_priority_fee_per_gas: self.max_priority_fee_per_gas?,
                max_fee_per_gas: self.max_fee_per_gas?,
                access_list: self.access_list?,
                gas: self.gas,
                to: self.to.into(),
                value: self.value,
                data: self.input,
                v: self.v,
                r: self.r,
                s: self.s,
            }),
            L1_MESSAGE_TX_TYPE_U64 => {
                TransactionInner::L1Message(L1MessageTx {
                    queue_index: self.queue_index?,
                    gas: self.gas,
                    to: self.to.into(),
                    value: self.value,
                    data: self.input,
                    sender: self.sender?,
                })
            }
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PoolTx {
    pub caller: SH160,
    pub tx: Arc<TransactionInner>,
    pub access_list: Arc<Vec<TransactionAccessTuple>>,
    pub hash: SH256,
    pub gas: u64,
    pub allow_revert: bool,
    pub block: u64,
    pub result: String,
}

impl PoolTx {
    pub fn with_tx(signer: &Signer, tx: TransactionInner) -> Self {
        Self::with_acl(signer, tx, Vec::new(), 0, 0, "".into(), true)
    }

    pub fn with_acl(
        signer: &Signer,
        tx: TransactionInner,
        acl: Vec<TransactionAccessTuple>,
        gas: u64,
        blk: u64,
        result: String,
        allow_revert: bool,
    ) -> Self {
        let hash = tx.hash();
        let caller = signer.sender(&tx);
        Self {
            caller,
            tx: Arc::new(tx),
            access_list: Arc::new(acl),
            hash,
            gas,
            allow_revert,
            block: blk,
            result,
        }
    }
}

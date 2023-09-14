use std::prelude::v1::*;

use super::TransactionInner;
use crypto::{secp256k1_recover_pubkey, Secp256k1PrivateKey};
use eth_types::{SH160, SU256};

#[derive(Clone, Copy)]
pub struct Signer {
    pub chain_id: SU256,
}

impl Signer {
    pub fn new(chain_id: SU256) -> Self {
        Self { chain_id }
    }

    pub fn sender(&self, inner: &TransactionInner) -> SH160 {
        let sig = inner.signature(self.chain_id.as_u64());
        match inner {
            TransactionInner::DynamicFee(tx) => {
                if tx.chain_id != self.chain_id {
                    panic!(
                        "chain id not match, expect: {}, got: {}",
                        self.chain_id, tx.chain_id
                    );
                }
            }
            TransactionInner::AccessList(tx) => {
                if tx.chain_id != self.chain_id {
                    panic!("chain id not match");
                }
            }
            TransactionInner::Legacy(_) => {}
            TransactionInner::L1Message(tx) => return tx.sender,
        }

        let msg = self.msg(inner);
        let pubkey = secp256k1_recover_pubkey(&sig, &msg[..]);
        pubkey.eth_accountid().into()
    }

    pub fn sign(&self, tx: &mut TransactionInner, key: &Secp256k1PrivateKey) {
        tx.sign(key, self.chain_id.as_u64())
    }

    pub fn msg(&self, tx: &TransactionInner) -> Vec<u8> {
        let data = match tx {
            TransactionInner::DynamicFee(tx) => {
                // stream.append_raw(bytes, item_count)
                let mut s = rlp::RlpStream::new_list(9);
                s.append(&tx.chain_id);
                s.append(&tx.nonce);
                s.append(&tx.max_priority_fee_per_gas);
                s.append(&tx.max_fee_per_gas);
                s.append(&tx.gas);
                s.append(&tx.to);
                s.append(&tx.value);
                s.append(&tx.data);
                s.append_list(&tx.access_list);
                let mut rlp = s.out().to_vec();
                let mut out = vec![2];
                out.append(&mut rlp);
                out
            }
            TransactionInner::AccessList(tx) => {
                // stream.append_raw(bytes, item_count)
                let mut s = rlp::RlpStream::new_list(8);
                s.append(&tx.chain_id);
                s.append(&tx.nonce);
                s.append(&tx.gas_price);
                s.append(&tx.gas);
                s.append(&tx.to);
                s.append(&tx.value);
                s.append(&tx.data);
                s.append_list(&tx.access_list);

                let mut rlp = s.out().to_vec();
                let mut out = vec![1];
                out.append(&mut rlp);
                out
            }
            TransactionInner::Legacy(tx) => {
                let v = tx.v.as_u64();
                let is_protected = v != 27 && v != 28 && v != 1 && v != 0;
                let mut len = 9;
                if !is_protected {
                    len = 6;
                }
                let mut s = rlp::RlpStream::new_list(len);
                s.append(&tx.nonce);
                s.append(&tx.gas_price);
                s.append(&tx.gas);
                s.append(&tx.to);
                s.append(&tx.value);
                s.append(&tx.data);

                if is_protected {
                    s.append(&self.chain_id);
                    s.append(&0usize);
                    s.append(&0usize);
                }

                s.out().into()
            }
            TransactionInner::L1Message(_) => unreachable!(),
        };
        data
    }
}

use std::prelude::v1::*;

use crypto::{Secp256k1PrivateKey, Secp256k1RecoverableSignature};
use eth_types::{HexBytes, SH160, SH256, SU256};
use serde::{Deserialize, Serialize};
use solidity::EncodeArg;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Poe {
    pub batch_hash: SH256,
    pub state_hash: SH256,
    pub prev_state_root: SH256,
    pub new_state_root: SH256,
    pub withdrawal_root: SH256,
    pub signature: HexBytes, // 65bytes
}

impl Poe {
    pub fn merge(batch_hash: SH256, reports: &[Self]) -> Option<Self> {
        if reports.len() < 1 {
            return None;
        }

        let state_hash = crypto::keccak_encode(|hash| {
            for report in reports {
                hash(&report.state_hash.0);
            }
        })
        .into();
        let prev_state_root = reports.first().unwrap().prev_state_root;
        let new_state_root = reports.last().unwrap().new_state_root;
        let withdrawal_root = reports.last().unwrap().withdrawal_root;
        Some(Self {
            batch_hash,
            state_hash,
            prev_state_root,
            new_state_root,
            withdrawal_root,
            signature: vec![0_u8; 65].into(),
        })
    }

    pub fn sign(
        chain_id: &SU256,
        batch_hash: SH256,
        reports: &[Self],
        prvkey: &Secp256k1PrivateKey,
    ) -> Option<Self> {
        let mut report = Self::merge(batch_hash, reports)?;
        let data = report.sign_msg(chain_id);

        let sig = prvkey.sign(&data);
        report.signature = sig.to_array().to_vec().into();
        Some(report)
    }
}

impl Default for Poe {
    fn default() -> Self {
        Self {
            batch_hash: SH256::default(),
            state_hash: SH256::default(),
            prev_state_root: SH256::default(),
            new_state_root: SH256::default(),
            withdrawal_root: SH256::default(),
            signature: vec![0_u8; 65].into(),
        }
    }
}

impl Poe {
    pub fn sign_msg(&self, chain_id: &SU256) -> Vec<u8> {
        let mut encoder = solidity::Encoder::new("");
        encoder.add(chain_id);
        encoder.add(&self.batch_hash);
        encoder.add(&self.state_hash);
        encoder.add(&self.prev_state_root);
        encoder.add(&self.new_state_root);
        encoder.add(&self.withdrawal_root);
        encoder.add(self.signature.as_bytes());
        encoder.encode()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = solidity::Encoder::new("");
        encoder.add(&self.batch_hash);
        encoder.add(&self.state_hash);
        encoder.add(&self.prev_state_root);
        encoder.add(&self.new_state_root);
        encoder.add(&self.withdrawal_root);
        encoder.add(self.signature.as_bytes());
        encoder.encode()
    }

    pub fn recover(&self, chain_id: &SU256) -> SH160 {
        let mut tmp = self.clone();
        tmp.signature = vec![0_u8; 65].into();
        let data = tmp.sign_msg(chain_id);
        let mut sig = [0_u8; 65];
        sig.copy_from_slice(&self.signature);
        let sig = Secp256k1RecoverableSignature::new(sig);
        crypto::secp256k1_recover_pubkey(&sig, &data)
            .eth_accountid()
            .into()
    }
}

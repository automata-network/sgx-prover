use std::sync::{Arc, Mutex};

use alloy::primitives::{keccak256, Address, U256};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    rand::thread_rng,
    Message, PublicKey, SECP256K1,
};

pub use secp256k1::SecretKey;

use crate::debug;

#[derive(Clone, Debug)]
pub struct Keypair {
    key: Arc<Mutex<(Option<U256>, Arc<SecretKey>, Arc<PublicKey>)>>,
}

impl Keypair {
    pub fn new() -> Self {
        let (sk, pk) = secp256k1::generate_keypair(&mut thread_rng());
        Self {
            key: Arc::new(Mutex::new((None, Arc::new(sk), Arc::new(pk)))),
        }
    }

    pub fn address(&self) -> Address {
        Self::public_key_to_address(&self.public_key())
    }

    fn public_key_to_address(pk: &PublicKey) -> Address {
        let hash = keccak256(&pk.serialize_uncompressed()[1..]);
        Address::from_slice(&hash[12..])
    }

    pub fn instance_id(&self) -> Option<U256> {
        self.key.lock().unwrap().0.clone()
    }

    pub fn info(&self) -> Option<(U256, Address, Arc<SecretKey>)> {
        let key = self.key.lock().unwrap();
        let id = key.0?;
        Some((id, Self::public_key_to_address(&key.2), key.1.clone()))
    }

    pub fn secret_key(&self) -> Arc<SecretKey> {
        self.key.lock().unwrap().1.clone()
    }

    pub fn public_key(&self) -> Arc<PublicKey> {
        self.key.lock().unwrap().2.clone()
    }

    pub fn rotate(&self) -> KeypairRotate {
        KeypairRotate {
            kp: Keypair::new(),
            old_key: self,
        }
    }

    pub fn sign_digest_ecdsa(sk: &SecretKey, digest: [u8; 32]) -> [u8; 65] {
        let msg = Message::from_digest(digest);
        let sig = SECP256K1.sign_ecdsa_recoverable(&msg, sk);
        let (v, rs) = sig.serialize_compact();
        let mut sig = [0_u8; 65];
        sig[..64].copy_from_slice(&rs[..]);
        sig[64] = v.to_i32() as u8 + 27;
        sig
    }

    pub fn recover(digest: [u8; 32], sig: [u8; 65]) -> Result<Address, String> {
        let msg = Message::from_digest(digest);
        let recid = RecoveryId::from_i32(sig[64] as _).map_err(debug)?;
        let sig = RecoverableSignature::from_compact(&sig[..64], recid).map_err(debug)?;
        let key = SECP256K1.recover_ecdsa(&msg, &sig).map_err(debug)?;
        Ok(Self::public_key_to_address(&key))
    }
}

pub struct KeypairRotate<'a> {
    kp: Keypair,
    old_key: &'a Keypair,
}

impl<'a> KeypairRotate<'a> {
    pub fn commit(self, instance_id: U256) {
        let mut new_key = self.kp.key.lock().unwrap().clone();
        new_key.0 = Some(instance_id);
        *self.old_key.key.lock().unwrap() = new_key;
    }
}

impl<'a> std::ops::Deref for KeypairRotate<'a> {
    type Target = Keypair;
    fn deref(&self) -> &Self::Target {
        &self.kp
    }
}

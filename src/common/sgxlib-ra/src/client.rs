use std::prelude::v1::*;

use crypto::{
    Aes128EncryptedMsg, Aes128Key, Secp256r1PrivateKey, Secp256r1PublicKey, Secp256r1SignedMsg,
};
use jsonrpc::{JsonrpcClient, JsonrpcErrorObj, RpcClient, RpcEncrypt, RpcError};
use serde::{de::DeserializeOwned, Serialize};
use sgxlib::sgx_types::{sgx_enclave_id_t, sgx_ra_context_t};

use crate::{AttestationClientState, AttestationServerState, AttestationStateError, RaFfi};

pub struct KeyExchangeClient<C: RpcClient> {
    ctx: ExchangeContext,
    client: JsonrpcClient<C>,
}

pub struct ExchangeContext {
    pub enclave_id: sgx_enclave_id_t,
    pub enclave_pubkey: Secp256r1PublicKey,
    pub signed_claim_info: Secp256r1SignedMsg<Secp256r1PublicKey>,
}

#[derive(Clone, Debug)]
pub struct ExchangeResult {
    pub prvkey: Secp256r1PrivateKey,
    pub pubkey: Secp256r1PublicKey,
    pub secret: Aes128Key,
    pub remote_pubkey: Secp256r1PublicKey,
}

impl RpcEncrypt for ExchangeResult {
    type EncKey = Secp256r1PublicKey;
    type EncType = Aes128EncryptedMsg;
    fn encrypt<T: Serialize>(
        &self,
        _: &Self::EncKey,
        data: &T,
    ) -> Result<Self::EncType, JsonrpcErrorObj> {
        let data = serde_json::to_vec(data)
            .map_err(|err| JsonrpcErrorObj::client(format!("serialize fail: {}", err)))?;
        Ok(self.secret.encrypt(&data))
    }

    fn decrypt<T: DeserializeOwned>(
        &self,
        _: &Self::EncKey,
        val: Self::EncType,
    ) -> Result<T, JsonrpcErrorObj> {
        let data = self
            .secret
            .decrypt(&val)
            .map_err(|err| JsonrpcErrorObj::client(format!("decrypt fail: {}", err)))?;
        return serde_json::from_slice(&data).map_err(|err| {
            JsonrpcErrorObj::client(format!(
                "deserialize params({}) fail: {} -> {:?}",
                std::any::type_name::<T>(),
                err,
                String::from_utf8_lossy(&data)
            ))
        });
    }
}

pub fn exchange_key<C: RpcClient>(
    enclave_id: sgx_enclave_id_t,
    c: C,
) -> Result<ExchangeResult, String> {
    let (prvkey, pubkey) = crypto::secp256r1_gen_keypair();
    let signed_claim_info = prvkey.sign(pubkey)?;
    let ctx = ExchangeContext {
        enclave_id,
        enclave_pubkey: pubkey,
        signed_claim_info,
    };
    let client = KeyExchangeClient::new(ctx, JsonrpcClient::new(c));
    let result = client.key_exchange()?;
    Ok(ExchangeResult {
        prvkey,
        pubkey,
        secret: result.key,
        remote_pubkey: result.remote_pubkey,
    })
}

pub struct AttestResult {
    pub key: Aes128Key,
    pub remote_pubkey: Secp256r1PublicKey,
}

impl<C: RpcClient> KeyExchangeClient<C> {
    pub fn new(ctx: ExchangeContext, client: JsonrpcClient<C>) -> Self {
        Self { ctx, client }
    }

    pub fn key_exchange(&self) -> Result<AttestResult, String> {
        let mut state = AttestationClientState::None;
        let mut key = None;
        let epid_gid = RaFfi::get_epid_gpid();
        let mut srv_state = AttestationServerState::Msg0 {
            msg0: epid_gid,
            enclave_pubkey: self.ctx.enclave_pubkey,
        };
        let remote_pubkey = self
            .call_pubkey()
            .map_err(|err| format!("get pubkey fail: {:?}", err))?;
        glog::info!("remote_pubkey: {:?}", remote_pubkey);
        let ctx = RaFfi::init_ra(&remote_pubkey.to_sgx_ec256_public())
            .map_err(|err| format!("init ra fail: {:?}", err))?;

        loop {
            let cli_state = self
                .call(&srv_state)
                .map_err(|err| format!("remote error: {:?}", err))?;
            if matches!(cli_state, AttestationClientState::None) {
                break;
            }
            let new_state = self
                .advance(&mut state, cli_state, ctx)
                .map_err(|err| format!("{:?}", err))?;

            if matches!(&new_state, AttestationServerState::Finalize { .. }) {
                key = Some(RaFfi::get_ra_key(ctx)?);
            }

            if matches!(new_state, AttestationServerState::None) {
                break;
            }
            srv_state = new_state;
        }
        if key.is_none() {
            return Err(format!("fail to key_exchange: no key"));
        }
        glog::info!("attest final state: {:?}", state);
        Ok(AttestResult {
            key: key.unwrap(),
            remote_pubkey,
        })
    }

    fn call_pubkey(&self) -> Result<Secp256r1PublicKey, RpcError> {
        self.client.rpc("sgxra_pubkey", ())
    }

    fn call(&self, srv_state: &AttestationServerState) -> Result<AttestationClientState, RpcError> {
        self.client.rpc("sgxra_attest", (srv_state,))
    }

    fn advance(
        &self,
        state: &mut AttestationClientState,
        new_state: AttestationClientState,
        context: sgx_ra_context_t,
    ) -> Result<AttestationServerState, AttestationStateError> {
        let enclave_pubkey = self.ctx.enclave_pubkey;
        Ok(match &new_state {
            AttestationClientState::None => unreachable!(),
            AttestationClientState::Msg0 { success } => {
                if !matches!(state, AttestationClientState::None) {
                    return Err(AttestationStateError::UnexpectedState);
                }
                if !success {
                    return Err(AttestationStateError::ServerRejectedMsg0);
                }
                let msg1 = match RaFfi::sgx_ra_get_msg1(context, self.ctx.enclave_id) {
                    Ok(v) => v,
                    Err(err) => {
                        return Err(AttestationStateError::GetMsg1Fail(err));
                    }
                };

                *state = new_state;
                AttestationServerState::Msg1 {
                    data: msg1,
                    enclave_pubkey,
                }
            }
            AttestationClientState::Msg2 { msg2_bytes } => {
                if !matches!(state, AttestationClientState::Msg0 { .. }) {
                    return Err(AttestationStateError::UnexpectedState);
                }
                let data = match RaFfi::sgx_ra_proc_msg2(context, self.ctx.enclave_id, &msg2_bytes)
                {
                    Ok(v) => v,
                    Err(err) => {
                        return Err(AttestationStateError::GetMsg2Fail(format!("{:?}", err)));
                    }
                };

                *state = new_state;
                AttestationServerState::Msg3 {
                    data,
                    enclave_pubkey,
                }
            }
            AttestationClientState::Msg3 { is_verified: _ } => {
                if !matches!(state, AttestationClientState::Msg2 { .. }) {
                    return Err(AttestationStateError::UnexpectedState);
                }

                let key = RaFfi::get_ra_key(context).map_err(|err| {
                    AttestationStateError::FinalizeGenMsgFail(format!("get ra key fail: {}", err))
                })?;
                let msg = serde_json::to_vec(&self.ctx.signed_claim_info).map_err(|err| {
                    AttestationStateError::FinalizeGenMsgFail(format!(
                        "serialize signed msg fail: {:?}",
                        err
                    ))
                })?;
                glog::info!("exchange keys: {}", String::from_utf8_lossy(&msg));
                let msg = key.encrypt(&msg);

                *state = new_state;
                AttestationServerState::Finalize {
                    msg,
                    enclave_pubkey,
                }
            }
            AttestationClientState::Finalize {} => {
                if !matches!(state, AttestationClientState::Msg3 { .. }) {
                    return Err(AttestationStateError::UnexpectedState);
                }
                *state = new_state;
                AttestationServerState::None
            }
        })
    }
}

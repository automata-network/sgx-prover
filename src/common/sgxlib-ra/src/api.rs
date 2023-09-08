use std::{prelude::v1::*, sync::Mutex};

use crypto::{
    secp256r1_gen_keypair, Aes128EncryptedMsg, Aes128Key, Secp256r1PrivateKey, Secp256r1PublicKey,
    Secp256r1SignedMsg,
};
use eth_types::HexBytes;
use jsonrpc::{JsonrpcErrorObj, RpcArgs, RpcServer};
use serde::{de::DeserializeOwned, Serialize};
use sgxlib::sgx_types::sgx_ra_msg2_t;
use std::collections::BTreeMap;

use crate::{
    AttestationClientState, AttestationServerState, AttestationStateError, IasReport, IasServer,
    RaMsg1, RaMsg2, SessionKeys, SgxRaMsg3,
};

pub mod __internal {
    pub use crypto::{Aes128EncryptedMsg, Secp256r1PublicKey};
    pub use jsonrpc::{JsonrpcErrorObj, RpcEncrypt};
    pub use serde::{de::DeserializeOwned, Serialize};
}

#[macro_export]
macro_rules! impl_jsonrpc_encrypt {
    ($t:ty, $field:ident) => {
        impl $crate::__internal::RpcEncrypt for $t {
            type EncKey = $crate::__internal::Secp256r1PublicKey;
            type EncType = $crate::__internal::Aes128EncryptedMsg;
            fn encrypt<T: $crate::__internal::Serialize>(
                &self,
                key: &Self::EncKey,
                val: &T,
            ) -> Result<Self::EncType, $crate::__internal::JsonrpcErrorObj> {
                $crate::RaServer::encrypt(&self.$field, key, val)
            }

            fn decrypt<T: $crate::__internal::DeserializeOwned>(
                &self,
                key: &Self::EncKey,
                val: Self::EncType,
            ) -> Result<T, $crate::__internal::JsonrpcErrorObj> {
                $crate::RaServer::decrypt(&self.$field, key, &val)
            }
        }
    };
}

#[derive(Default)]
pub struct RaSession {
    pub keys: SessionKeys,
    pub state: AttestationServerState,
}

pub struct RaServer {
    sessions: Mutex<BTreeMap<Secp256r1PublicKey, RaSession>>,
    pubkey: Secp256r1PublicKey,
    prikey: Secp256r1PrivateKey,
    ias_server: IasServer,
    ias_server_fallback: bool,
    conditional_secure: bool,
    spid: [u8; 16],
}

impl RaServer {
    pub fn new(spid: &[u8], apikey: &str, is_dev: bool) -> Self {
        let ias_server = IasServer::new(apikey, is_dev, None);
        let (prikey, pubkey) = secp256r1_gen_keypair();
        let mut tmp = [0_u8; 16];
        tmp.copy_from_slice(&spid);

        Self {
            sessions: Default::default(),
            prikey,
            pubkey,
            spid: tmp,
            ias_server_fallback: true,
            conditional_secure: true,
            ias_server,
        }
    }

    pub fn get_key(&self, key: &Secp256r1PublicKey) -> Option<Aes128Key> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(key).map(|s| s.keys.sk.clone())
    }

    pub fn decrypt<T>(
        &self,
        key: &Secp256r1PublicKey,
        data: &Aes128EncryptedMsg,
    ) -> Result<T, JsonrpcErrorObj>
    where
        T: DeserializeOwned,
    {
        if let Some(sk) = self.get_key(key) {
            let data = sk
                .decrypt(data)
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
        return Err(self.unauth());
    }

    pub fn encrypt<T: Serialize>(
        &self,
        key: &Secp256r1PublicKey,
        data: &T,
    ) -> Result<Aes128EncryptedMsg, JsonrpcErrorObj> {
        let sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get(key) {
            let data = serde_json::to_vec(data)
                .map_err(|err| JsonrpcErrorObj::client(format!("serialize fail: {}", err)))?;
            return Ok(session.keys.sk.encrypt(&data));
        }
        return Err(self.unauth());
    }

    pub fn unauth(&self) -> JsonrpcErrorObj {
        JsonrpcErrorObj::error(-32403, "need attestation first".into())
    }

    pub fn advance_state(
        &self,
        new_state: AttestationServerState,
    ) -> Result<AttestationClientState, AttestationStateError> {
        glog::info!("recv attest: {:?}", new_state);
        let enclave_id = match new_state.enclave_key() {
            Some(n) => n,
            None => return Err(AttestationStateError::UnexpectedState),
        };
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .entry(enclave_id)
            .or_insert_with(|| RaSession::default());
        let res = self.internal_advance(session, new_state)?;
        Ok(res)
    }

    fn internal_advance(
        &self,
        session: &mut RaSession,
        new_state: AttestationServerState,
    ) -> Result<AttestationClientState, AttestationStateError> {
        let old_state = &session.state;
        Ok(match &new_state {
            AttestationServerState::None => unreachable!(),
            AttestationServerState::Msg0 {
                msg0,
                enclave_pubkey: _,
            } => {
                if !matches!(old_state, AttestationServerState::None) {
                    return Err(AttestationStateError::UnexpectedState);
                }
                let success = match msg0 {
                    0 => true,
                    1 => false,
                    _other => return Err(AttestationStateError::InvalidMsg0),
                };

                session.state = new_state;
                AttestationClientState::Msg0 { success }
            }
            AttestationServerState::Msg1 {
                data,
                enclave_pubkey: _,
            } => {
                if !matches!(old_state, AttestationServerState::Msg0 { .. }) {
                    return Err(AttestationStateError::UnexpectedState);
                }
                let msg2_bytes =
                    RaUtil::proc_msg1(data, &self.ias_server, &self.prikey, self.spid, session)
                        .map_err(|err| AttestationStateError::ApplyMsg1Fail(err))?;

                session.state = new_state;
                AttestationClientState::Msg2 { msg2_bytes }
            }
            AttestationServerState::Msg3 {
                data,
                enclave_pubkey: _,
            } => {
                if !matches!(old_state, AttestationServerState::Msg1 { .. }) {
                    return Err(AttestationStateError::UnexpectedState);
                }
                let is_verified = match RaUtil::proc_msg3(&self.ias_server, session, &data) {
                    Ok(ias) => {
                        let data = match ias.data() {
                            Ok(data) => data,
                            Err(_) => return Err(AttestationStateError::Msg3FailGetQuote),
                        };
                        let _quote = match data.get_isv_enclave_quote_body() {
                            Some(v) => v,
                            None => {
                                return Err(AttestationStateError::Msg3FailGetQuote);
                            }
                        };
                        let is_secure = data.is_enclave_secure(self.conditional_secure);
                        is_secure
                    }
                    Err(err) => {
                        if self.ias_server_fallback {
                            true
                        } else {
                            return Err(err);
                        }
                    }
                };
                session.state = new_state;
                AttestationClientState::Msg3 { is_verified }
            }
            AttestationServerState::Finalize {
                msg,
                enclave_pubkey: _,
            } => {
                if !matches!(old_state, AttestationServerState::Msg3 { .. }) {
                    return Err(AttestationStateError::UnexpectedState);
                }

                let data = session
                    .keys
                    .sk
                    .decrypt(msg)
                    .map_err(|err| AttestationStateError::FinalizeDecryptFail(err))?;

                let msg: Secp256r1SignedMsg<Secp256r1PublicKey> = serde_json::from_slice(&data)
                    .map_err(|err| {
                        AttestationStateError::FinalizeDecryptFail(format!(
                            "decode msg fail: {:?} => {}",
                            err,
                            String::from_utf8_lossy(&data),
                        ))
                    })?;
                glog::info!("final: {:?}", HexBytes::from(&msg.msg.to_raw_bytes()[..]));
                session.state = new_state;
                AttestationClientState::Finalize {}
            }
        })
    }
}

pub struct RaUtil;
impl RaUtil {
    pub fn derive_secret_keys(
        kdk: &Aes128Key,
    ) -> Result<(Aes128Key, Aes128Key, Aes128Key, Aes128Key), String> {
        let smk_data = [0x01, 'S' as u8, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
        let mac = kdk.mac(&smk_data)?;
        let smk = Aes128Key { key: mac.mac };

        let sk_data = [0x01, 'S' as u8, 'K' as u8, 0x00, 0x80, 0x00];
        let mac = kdk.mac(&sk_data)?;
        let sk = Aes128Key { key: mac.mac };

        let mk_data = [0x01, 'M' as u8, 'K' as u8, 0x00, 0x80, 0x00];
        let mac = kdk.mac(&mk_data)?;
        let mk = Aes128Key { key: mac.mac };

        let vk_data = [0x01, 'V' as u8, 'K' as u8, 0x00, 0x80, 0x00];
        let mac = kdk.mac(&vk_data)?;
        let vk = Aes128Key { key: mac.mac };
        Ok((smk, sk, mk, vk))
    }

    pub fn proc_msg1(
        msg1: &HexBytes,
        ias_server: &IasServer,
        aas_prvkey: &Secp256r1PrivateKey,
        spid: [u8; 16],
        session: &mut RaSession,
    ) -> Result<HexBytes, String> {
        let p_msg1 = RaMsg1::to_sgx(&msg1);
        glog::info!("gid: {:?}", p_msg1.gid);

        let (prvkey, pubkey) = secp256r1_gen_keypair();
        let g_b = pubkey;
        let g_a = Secp256r1PublicKey::from_sgx_ec256_public(&p_msg1.g_a);
        session.keys.g_a = g_a;
        session.keys.g_b = g_b;
        let kdk = prvkey.derive_kdk(&g_a)?;
        let (smk, sk, mk, _vk) = Self::derive_secret_keys(&kdk)?;
        session.keys.kdk = kdk;
        session.keys.smk = smk;
        session.keys.sk = sk;
        session.keys.mk = mk;

        // get sign_gb_ga
        let mut gb_ga: [u8; 128] = [0; 128];
        let gb_bytes = g_b.to_raw_bytes();
        let ga_bytes = g_a.to_raw_bytes();
        gb_ga[..64].copy_from_slice(&gb_bytes);
        gb_ga[64..].copy_from_slice(&ga_bytes);

        let sign_gb_ga = aas_prvkey.sign_bytes(&gb_ga)?;

        let mut p_msg2 = sgx_ra_msg2_t::default();
        p_msg2.g_b = g_b.to_sgx_ec256_public();
        p_msg2.spid.id = spid;
        p_msg2.quote_type = 1_u16;
        p_msg2.kdf_id = 1_u16;
        p_msg2.sign_gb_ga = sign_gb_ga.into();
        p_msg2.mac = RaMsg2::mac(&session.keys.smk, &p_msg2)?.mac;

        let sigrl = match ias_server.get_sigrl(&p_msg1.gid) {
            Ok(sigrl) => sigrl,
            Err(err) => {
                return Err(err);
            }
        };
        p_msg2.sig_rl_size = sigrl.len() as u32;

        let msg2_bytes = RaMsg2::to_hex(p_msg2, &sigrl);
        Ok(msg2_bytes)
    }

    pub fn proc_msg3(
        ias_server: &IasServer,
        session: &mut RaSession,
        msg3: &[u8],
    ) -> Result<IasReport, AttestationStateError> {
        let msg3 = match SgxRaMsg3::from_slice(msg3) {
            Ok(v) => v,
            Err(err) => return Err(AttestationStateError::InvalidMsg3(err)),
        };

        // verify sgx_ra_msg3_t using derived smk as described in Intel's manual.
        if msg3.verify(&session.keys.smk) {
            let avr = match ias_server.verify_quote(msg3.quote) {
                Ok(v) => v,
                Err(err) => {
                    glog::error!("verify_quote in sp_proc_ra_msg3 meet error: {:?}", err);
                    return Err(AttestationStateError::Msg3FailVerifyQuote);
                }
            };
            Ok(avr)
        } else {
            Err(AttestationStateError::Msg3FailVerify)
        }
    }
}

pub trait Api: Sized + Send + Sync {
    fn ctx(&self) -> &RaServer;

    fn init_api<E>(&self, srv: &mut RpcServer<Self, E>)
    where
        E: Send + 'static,
    {
        srv.jsonrpc("sgxra_attest", Self::attest);
        srv.jsonrpc("sgxra_pubkey", Self::pubkey);
    }

    fn attest(
        &self,
        arg: RpcArgs<(AttestationServerState,)>,
    ) -> Result<AttestationClientState, JsonrpcErrorObj> {
        let next = self
            .ctx()
            .advance_state(arg.params.0)
            .map_err(|err| JsonrpcErrorObj::client(format!("{:?}", err)))?;
        Ok(next)
    }

    fn pubkey(&self, _arg: RpcArgs) -> Result<Secp256r1PublicKey, JsonrpcErrorObj> {
        Ok(self.ctx().pubkey)
    }

    // #[cfg(feature = "std")]
    // fn transit(
    //     &self,
    //     arg: RpcArgs<(AttestationServerState,)>,
    // ) -> Result<AttestationClientState, JsonrpcErrorObj> {
    //     glog::info!("hello: {:?}", arg.params.0);
    //     Ok(AttestationClientState::None)
    // }
}

use std::prelude::v1::*;

use base::format::debug;
use crypto::Aes128Key;
use eth_types::HexBytes;
use serde::{Deserialize, Serialize};
#[cfg(feature = "tstd")]
use sgxlib::{
    sgx_tkey_exchange::rsgx_ra_get_keys,
    sgx_types::{sgx_create_report, sgx_ra_key_type_t, sgx_report_data_t},
    unsafe_ocall,
};
use std::ptr::{null, null_mut};

use sgxlib::{
    sgx_tkey_exchange::rsgx_ra_init,
    sgx_types::{
        sgx_ec256_public_t, sgx_ecall_get_ga_trusted_t, sgx_enclave_id_t,
        sgx_get_extended_epid_group_id, sgx_get_quote, sgx_get_quote_size, sgx_quote_nonce_t,
        sgx_ra_context_t, sgx_ra_msg1_t, sgx_ra_msg2_t, sgx_ra_msg3_t, sgx_ra_proc_msg2,
        sgx_report_t, sgx_spid_t, sgx_status_t, sgx_target_info_t, size_t, uint32_t,
    },
    to_result,
};

use crate::{SgxReport, SgxTarget};

#[derive(Debug, Serialize, Deserialize)]
pub enum RaFfi {
    GetEpidGid {
        response: Option<u32>,
    },
    GetMsg1 {
        request: Option<(sgx_ra_context_t, sgx_enclave_id_t)>,
        response: Option<HexBytes>,
    },
    ProcMsg2 {
        request: Option<(sgx_ra_context_t, sgx_enclave_id_t, Vec<u8>)>,
        response: Option<HexBytes>,
    },
    GetQuote {
        request: Option<(HexBytes, [u8; 16], HexBytes)>,
        response: Option<HexBytes>,
    },
    InitQuote {
        response: Option<(HexBytes, [u8; 4])>,
    },
}

impl RaFfi {
    #[cfg(feature = "std")]
    pub fn call(self) -> Result<RaFfi, String> {
        Ok(match self {
            Self::GetEpidGid { response: None } => Self::GetEpidGid {
                response: Some(Self::get_epid_gpid()),
            },
            Self::GetMsg1 {
                request: Some((context, eid)),
                response: None,
            } => Self::GetMsg1 {
                request: None,
                response: Some(Self::sgx_ra_get_msg1(context, eid)?),
            },
            Self::ProcMsg2 {
                request: Some((ctx, eid, msg2)),
                response: None,
            } => Self::ProcMsg2 {
                request: None,
                response: Some(Self::sgx_ra_proc_msg2(ctx, eid, &msg2)?),
            },
            Self::GetQuote {
                request: Some((data, spid, sigrl)),
                response: None,
            } => {
                let report = SgxReport::from_bytes(&data);
                Self::GetQuote {
                    request: None,
                    response: Some(Self::get_quote(&report, spid, sigrl)?),
                }
            }
            Self::InitQuote { response: None } => {
                let (target, gid) = Self::init_quote()?;
                Self::InitQuote {
                    response: Some((target.to_bytes(), gid)),
                }
            }
            other => return Err(format!("unexpect enum {:?}", other)),
        })
    }

    #[cfg(feature = "std")]
    pub unsafe fn on_call(
        msg_in: *const u8,
        msg_in_size: size_t,
        msg_out: *mut u8,
        msg_out_size: size_t,
    ) -> sgx_status_t {
        let msg_in = std::slice::from_raw_parts(msg_in, msg_in_size);
        let msg_in: RaFfi = match serde_json::from_slice(msg_in) {
            Ok(n) => n,
            Err(err) => {
                glog::error!("decode msg_in fail: {:?}", err);
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        };
        let sig = format!("{:?}", msg_in);
        match msg_in.call() {
            Ok(result) => {
                let out = serde_json::to_vec(&result).unwrap();
                if out.len() > msg_out_size {
                    glog::error!(
                        "buffer too small [want:{}, got:{}] [{:?}]",
                        out.len(),
                        msg_out_size,
                        String::from_utf8_lossy(&out)
                    );
                    return sgx_status_t::SGX_ERROR_UNEXPECTED;
                }
                let msg_out = std::slice::from_raw_parts_mut(msg_out, out.len());
                msg_out.copy_from_slice(&out);
                sgx_status_t::SGX_SUCCESS
            }
            Err(err) => {
                glog::error!("process fail: on {} {}", sig, err);
                sgx_status_t::SGX_ERROR_UNEXPECTED
            }
        }
    }

    #[cfg(feature = "tstd")]
    pub fn call(self) -> Result<RaFfi, String> {
        let data = serde_json::to_vec(&self).map_err(debug)?;
        let mut out = vec![0_u8; 4096];
        unsafe_ocall!(sgxlib_ra_ocall(
            data.len(),
            data.as_ptr(),
            out.len(),
            out.as_mut_ptr(),
        ))
        .map_err(|err| format!("ocall fail: {:?}", err))?;
        let len = out
            .iter()
            .position(|n| *n == '\0' as u8)
            .ok_or(format!("invalid result"))?;
        let result: RaFfi = serde_json::from_slice(&out[..len]).map_err(debug)?;
        Ok(result)
    }

    #[cfg(feature = "std")]
    pub fn get_epid_gpid() -> u32 {
        let mut extended_epid_gid = 0u32;
        unsafe { to_result(sgx_get_extended_epid_group_id(&mut extended_epid_gid)).unwrap() }
        extended_epid_gid
    }

    #[cfg(feature = "tstd")]
    pub fn get_epid_gpid() -> u32 {
        let result = Self::GetEpidGid { response: None }.call().unwrap();
        if let Self::GetEpidGid { response: Some(id) } = result {
            return id;
        }
        unreachable!()
    }

    #[cfg(feature = "tstd")]
    pub fn init_quote() -> Result<(SgxTarget, [u8; 4]), String> {
        let result = Self::InitQuote { response: None }.call().unwrap();
        if let Self::InitQuote {
            response: Some((quote, gid)),
        } = result
        {
            return Ok((SgxTarget::from_bytes(&quote), gid));
        }
        unreachable!()
    }

    #[cfg(feature = "std")]
    pub fn init_quote() -> Result<(SgxTarget, [u8; 4]), String> {
        use sgxlib::sgx_types::{sgx_epid_group_id_t, sgx_init_quote};

        let mut target = sgx_target_info_t::default();
        let mut epid_gid = sgx_epid_group_id_t::default();
        unsafe {
            to_result(sgx_init_quote(&mut target as _, &mut epid_gid as _)).map_err(debug)?;
        }
        Ok((SgxTarget { raw: target }, epid_gid))
    }

    // #[cfg(feature = "std")]
    // pub fn generate_quote(data: [u8; 64], spid: [u8; 16]) -> Result<HexBytes, String> {
    // target, sgx_create_report
    // let report = Self::create_report(data)?;
    // Self::get_quote(&report, spid)
    // }

    // #[cfg(feature = "tstd")]
    // pub fn generate_quote1(data: [u8; 64], spid: [u8; 16]) -> Result<HexBytes, String> {
    //     let data = data.as_ref().into();
    //     let result = Self::GenerateQuote {
    //         request: Some((data, spid)),
    //         response: None,
    //     }
    //     .call()?;
    //     if let Self::GenerateQuote {
    //         request: None,
    //         response: Some(data),
    //     } = result
    //     {
    //         return Ok(data);
    //     }
    //     unreachable!()
    // }

    #[cfg(feature = "tstd")]
    pub fn create_report(target: sgx_target_info_t, data: [u8; 64]) -> Result<SgxReport, String> {
        let mut report_data = sgx_report_data_t::default();
        report_data.d = data;
        let mut report = SgxReport::default();
        unsafe {
            to_result(sgx_create_report(
                &target as _,
                &report_data as _,
                &mut report.raw as _,
            ))
            .map_err(debug)?;
        }
        Ok(report)
    }

    #[cfg(feature = "tstd")]
    pub fn get_quote(
        report: &SgxReport,
        spid: [u8; 16],
        sigrl: HexBytes,
    ) -> Result<HexBytes, String> {
        let result = RaFfi::GetQuote {
            request: Some((report.to_bytes(), spid, sigrl)),
            response: None,
        }
        .call()?;
        if let Self::GetQuote {
            request: None,
            response: Some(msg),
        } = result
        {
            return Ok(msg);
        }
        unreachable!()
    }

    #[cfg(feature = "std")]
    pub fn get_quote(
        report: &SgxReport,
        spid: [u8; 16],
        sigrl: HexBytes,
    ) -> Result<HexBytes, String> {
        let quote_type = sgxlib::sgx_types::sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
        let mut tspid = sgx_spid_t::default();
        tspid.id = spid;
        let p_sig_rl = if sigrl.len() == 0 {
            null()
        } else {
            sigrl.as_ptr() as _
        };
        let sig_rl_size = sigrl.len() as _;
        let quote_size = unsafe {
            let mut size = 0u32;
            to_result(sgx_get_quote_size(p_sig_rl, &mut size as _))
                .map_err(|err| format!("sgx_get_quote_size fail: {:?}", err))?;
            size
        };

        let mut nonce = sgx_quote_nonce_t::default();
        crypto::read_rand(&mut nonce.rand);

        let mut quote_buf = vec![0_u8; quote_size as usize];

        unsafe {
            to_result(sgx_get_quote(
                &report.raw as _,
                quote_type,
                &tspid as _,
                null(),
                p_sig_rl,
                sig_rl_size,
                null_mut(),
                quote_buf.as_mut_ptr() as _,
                quote_size,
            ))
            .map_err(|err| format!("sgx_get_quote: {:?}", err))?;
        }

        return Ok(quote_buf.into());
    }

    #[cfg(feature = "std")]
    pub fn sgx_ra_get_msg1(
        context: sgx_ra_context_t,
        eid: sgx_enclave_id_t,
    ) -> Result<HexBytes, String> {
        use crate::RaMsg1;
        glog::info!("call sgx_ra_get_msg1 on std");
        let mut msg1 = sgx_ra_msg1_t::default();
        unsafe {
            to_result(sgx_ra_get_msg1(
                context,
                eid,
                sgx_ra_get_ga,
                (&mut msg1) as *mut sgx_ra_msg1_t,
            ))
            .map_err(debug)?;
        }
        Ok(RaMsg1::to_hex(msg1))
    }

    #[cfg(feature = "tstd")]
    pub fn sgx_ra_get_msg1(
        context: sgx_ra_context_t,
        eid: sgx_enclave_id_t,
    ) -> Result<HexBytes, String> {
        let result = Self::GetMsg1 {
            request: Some((context, eid)),
            response: None,
        }
        .call()?;
        if let Self::GetMsg1 {
            request: None,
            response: Some(msg),
        } = result
        {
            return Ok(msg);
        }
        unreachable!()
    }

    #[cfg(feature = "std")]
    pub fn sgx_ra_proc_msg2(
        context: sgx_ra_context_t,
        enclave_id: sgx_enclave_id_t,
        msg2: &[u8],
    ) -> Result<HexBytes, String> {
        let p_msg2 = msg2 as *const _ as *const sgx_ra_msg2_t;
        let msg2_size = msg2.len() as u32;
        let mut msg3_ptr: *mut sgx_ra_msg3_t = 0 as *mut sgx_ra_msg3_t;
        let mut msg3_size = 0_u32;
        unsafe {
            to_result(sgx_ra_proc_msg2(
                context,
                enclave_id,
                sgx_ra_proc_msg2_trusted,
                sgx_ra_get_msg3_trusted,
                p_msg2,
                msg2_size,
                &mut msg3_ptr,
                &mut msg3_size,
            ))
            .map_err(debug)?
        }

        let msg3_slice =
            unsafe { std::slice::from_raw_parts(msg3_ptr as *const u8, msg3_size as usize) };
        Ok(msg3_slice.to_vec().into())
    }

    #[cfg(feature = "tstd")]
    pub fn sgx_ra_proc_msg2(
        context: sgx_ra_context_t,
        enclave_id: sgx_enclave_id_t,
        msg2: &[u8],
    ) -> Result<HexBytes, String> {
        let result = Self::ProcMsg2 {
            request: Some((context, enclave_id, msg2.into())),
            response: None,
        }
        .call()
        .unwrap();
        if let Self::ProcMsg2 {
            request: None,
            response: Some(msg3),
        } = result
        {
            return Ok(msg3);
        }
        unreachable!()
    }

    pub fn init_ra(pubkey: &sgx_ec256_public_t) -> Result<sgx_ra_context_t, sgx_status_t> {
        let ctx = rsgx_ra_init(pubkey, 0)?;
        Ok(ctx)
    }

    // #[cfg(feature = "tstd")]
    // pub fn enclave_ra_finalize(
    //     ra_context: sgx_ra_context_t,
    //     msg: Sr25519SignedMsg<Secp256r1PublicKey>,
    // ) -> Result<Aes128EncryptedMsg, String> {
    //     let finalize_request_bytes = serde_json::to_vec(&msg).unwrap();
    //     let sk: Aes128Key = rsgx_ra_get_keys(ra_context, sgx_ra_key_type_t::SGX_RA_KEY_SK)
    //         .unwrap()
    //         .into();
    //     let msg = sk.encrypt(&finalize_request_bytes);
    //     Ok(msg)
    // }

    #[cfg(feature = "tstd")]
    pub fn get_ra_key(ra_context: sgx_ra_context_t) -> Result<Aes128Key, String> {
        Ok(
            rsgx_ra_get_keys(ra_context, sgx_ra_key_type_t::SGX_RA_KEY_SK)
                .map_err(debug)?
                .into(),
        )
    }

    #[cfg(feature = "std")]
    pub fn get_ra_key(_: sgx_ra_context_t) -> Result<Aes128Key, String> {
        unimplemented!("not support calling get_ra_key on std mode yet")
    }
}

#[cfg(feature = "tstd")]
extern "C" {
    // ocalls

    fn ra_get_epid_group_id(retval: *mut u32);
    fn sgxlib_ra_ocall(
        retval: *mut sgx_status_t,
        msg_in_size: size_t,
        msg_in: *const u8,
        msg_out_size: size_t,
        msg_out: *mut u8,
    );
    fn ra_get_msg1(
        retval: *mut sgx_status_t,
        context: sgx_ra_context_t,
        eid: sgx_enclave_id_t,
        msg1: &mut sgx_ra_msg1_t,
    );
    fn ra_proc_msg2(
        retval: *mut sgx_status_t,
        context: sgx_ra_context_t,
        eid: sgx_enclave_id_t,
        msg2_len: size_t,
        msg2: *const u8,
        msg3: *mut *mut sgx_ra_msg3_t,
        msg3_len: *mut size_t,
    );
}

extern "C" {
    pub fn rsgx_self_identity(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
    pub fn sgx_ra_get_msg1(
        context: sgx_ra_context_t,
        eid: sgx_enclave_id_t,
        p_get_ga: sgx_ecall_get_ga_trusted_t,
        p_msg1: *mut sgx_ra_msg1_t,
    ) -> sgx_status_t;
    pub fn sgx_ra_get_ga(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        context: sgx_ra_context_t,
        g_a: *mut sgx_ec256_public_t,
    ) -> sgx_status_t;
    pub fn sgx_ra_proc_msg2_trusted(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        context: sgx_ra_context_t,
        p_msg2: *const sgx_ra_msg2_t,
        p_qe_target: *const sgx_target_info_t,
        p_report: *mut sgx_report_t,
        nonce: *mut sgx_quote_nonce_t,
    ) -> sgx_status_t;
    pub fn sgx_ra_get_msg3_trusted(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        context: sgx_ra_context_t,
        quote_size: uint32_t,
        qe_report: *mut sgx_report_t,
        p_msg3: *mut sgx_ra_msg3_t,
        msg3_size: uint32_t,
    ) -> sgx_status_t;
}

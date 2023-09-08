use std::prelude::v1::*;

use core::mem::size_of;
use core::mem::transmute;
use crypto::Aes128EncryptedMsg;
use crypto::Aes128Key;
use crypto::Aes128Mac;
use crypto::Secp256r1PublicKey;
use eth_types::HexBytes;
use memoffset::offset_of;
use rustls::internal::pemfile;
use serde::{Deserialize, Serialize};
use sgxlib::sgx_types::sgx_report_t;
use sgxlib::sgx_types::sgx_target_info_t;
use sgxlib::sgx_types::{
    sgx_attributes_t, sgx_isv_svn_t, sgx_mac_t, sgx_prod_id_t, sgx_quote_t, sgx_ra_msg1_t,
    sgx_ra_msg2_t, sgx_ra_msg3_t, sgx_report_body_t, uint32_t, SGX_FLAGS_DEBUG, SGX_FLAGS_INITTED,
};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IasReportRequest {
    pub isv_enclave_quote: String,
    pub nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IasReport {
    pub raw: HexBytes,
    pub sig: HexBytes,
    pub cert: String,
}

#[derive(Debug)]
pub enum VerifyError {
    EnclaveNotSecure,
    InvalidCert,
    InvalidCertChain,
    ParseEndEntityCert(webpki::Error),
    VerifySigFail(webpki::Error),
    InvalidData(serde_json::Error),
    GetQuote,
}

// origin source: https://github.com/integritee-network/pallet-teerex/blob/a8143a18a03abf5d546e3fd9d0042ececb448b30/ias-verify/src/lib.rs#L116C1-L157C1
pub static IAS_SERVER_ROOTS: webpki::TLSServerTrustAnchors = webpki::TLSServerTrustAnchors(&[
	/*
	 * -----BEGIN CERTIFICATE-----
	 * MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
	 * BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
	 * BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
	 * YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy
	 * MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL
	 * U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD
	 * DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G
	 * CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e
	 * LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh
	 * rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT
	 * L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe
	 * NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ
	 * byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H
	 * afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf
	 * 6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM
	 * RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX
	 * MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50
	 * L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW
	 * BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr
	 * NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq
	 * hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir
	 * IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ
	 * sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi
	 * zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra
	 * Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA
	 * 152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB
	 * 3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O
	 * DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv
	 * DaVzWh5aiEx+idkSGMnX
	 * -----END CERTIFICATE-----
	 */
	webpki::TrustAnchor {
		subject: b"1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x0b0\t\x06\x03U\x04\x08\x0c\x02CA1\x140\x12\x06\x03U\x04\x07\x0c\x0bSanta Clara1\x1a0\x18\x06\x03U\x04\n\x0c\x11Intel Corporation100.\x06\x03U\x04\x03\x0c\'Intel SGX Attestation Report Signing CA",
		spki: b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x8f\x000\x82\x01\x8a\x02\x82\x01\x81\x00\x9f<d~\xb5w<\xbbQ-\'2\xc0\xd7A^\xbbU\xa0\xfa\x9e\xde.d\x91\x99\xe6\x82\x1d\xb9\x10\xd51w7\twFjj^G\x86\xcc\xd2\xdd\xeb\xd4\x14\x9dj/c%R\x9d\xd1\x0c\xc9\x877\xb0w\x9c\x1a\x07\xe2\x9cG\xa1\xae\x00IHGlH\x9fE\xa5\xa1]z\xc8\xec\xc6\xac\xc6E\xad\xb4=\x87g\x9d\xf5\x9c\t;\xc5\xa2\xe9ilTxT\x1b\x97\x9euKW9\x14\xbeU\xd3/\xf4\xc0\x9d\xdf\'!\x994\xcd\x99\x05\'\xb3\xf9.\xd7\x8f\xbf)$j\xbe\xcbq$\x0e\xf3\x9c-q\x07\xb4GTZ\x7f\xfb\x10\xeb\x06\nh\xa9\x85\x80!\x9e6\x91\tRh8\x92\xd6\xa5\xe2\xa8\x08\x03\x19>@u1@N6\xb3\x15b7\x99\xaa\x82Pt@\x97T\xa2\xdf\xe8\xf5\xaf\xd5\xfec\x1e\x1f\xc2\xaf8\x08\x90o(\xa7\x90\xd9\xdd\x9f\xe0`\x93\x9b\x12W\x90\xc5\x80]\x03}\xf5j\x99S\x1b\x96\xdei\xde3\xed\"l\xc1 }\x10B\xb5\xc9\xab\x7f@O\xc7\x11\xc0\xfeGi\xfb\x95x\xb1\xdc\x0e\xc4i\xea\x1a%\xe0\xff\x99\x14\x88n\xf2i\x9b#[\xb4\x84}\xd6\xff@\xb6\x06\xe6\x17\x07\x93\xc2\xfb\x98\xb3\x14X\x7f\x9c\xfd%sb\xdf\xea\xb1\x0b;\xd2\xd9vs\xa1\xa4\xbdD\xc4S\xaa\xf4\x7f\xc1\xf2\xd3\xd0\xf3\x84\xf7J\x06\xf8\x9c\x08\x9f\r\xa6\xcd\xb7\xfc\xee\xe8\xc9\x82\x1a\x8eT\xf2\\\x04\x16\xd1\x8cF\x83\x9a_\x80\x12\xfb\xdd=\xc7M%by\xad\xc2\xc0\xd5Z\xffo\x06\"B]\x1b\x02\x03\x01\x00\x01",
		name_constraints: None
	},

]);

impl IasReport {
    pub fn data(&self) -> Result<IasReportData, serde_json::Error> {
        serde_json::from_slice(&self.raw)
    }

    pub fn verify(&self) -> Result<SgxQuote, VerifyError> {
        let certs = {
            let mut buf = self.cert.as_bytes();
            pemfile::certs(&mut buf).map_err(|_| VerifyError::InvalidCert)?
        };

        let now = webpki::Time::from_seconds_since_unix_epoch(base::time::now().as_secs());

        let (cert, chain) = certs.split_first().ok_or(VerifyError::InvalidCertChain)?;
        let chain: Vec<&[u8]> = chain.iter().map(AsRef::as_ref).collect();

        let cert =
            webpki::EndEntityCert::from(cert.as_ref()).map_err(VerifyError::ParseEndEntityCert)?;
        let alg = &webpki::RSA_PKCS1_2048_8192_SHA256;
        cert.verify_signature(alg, &self.raw, &self.sig)
            .map_err(VerifyError::VerifySigFail)?;
        cert.verify_is_valid_tls_server_cert(&[alg], &IAS_SERVER_ROOTS, &chain, now)
            .map_err(VerifyError::VerifySigFail)?;

        let data = self.data().map_err(VerifyError::InvalidData)?;
        if !data.is_enclave_secure(true) {
            glog::error!("{}", data.isv_enclave_quote_status);
            return Err(VerifyError::EnclaveNotSecure);
        }
        let quote = match data.get_isv_enclave_quote_body() {
            Some(v) => v,
            None => {
                return Err(VerifyError::GetQuote);
            }
        };
        Ok(quote)
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IasReportData {
    pub id: String,
    pub timestamp: String,
    pub version: u32,
    pub isv_enclave_quote_status: String,
    pub isv_enclave_quote_body: String,
    pub revocation_reason: Option<String>,
    pub pse_manifest_status: Option<String>,
    pub pse_manifest_hash: Option<String>,
    pub platform_info_blob: Option<String>,
    pub nonce: Option<String>,
    pub epid_pseudonym: Option<String>,
    #[serde(rename(serialize = "advisoryURL"))]
    #[serde(rename(deserialize = "advisoryURL"))]
    pub advisory_url: Option<String>,
    #[serde(rename(serialize = "advisoryIDs"))]
    #[serde(rename(deserialize = "advisoryIDs"))]
    pub advisory_ids: Option<Vec<String>>,
}

impl IasReportData {
    pub fn get_isv_enclave_quote_body(&self) -> Option<SgxQuote> {
        let isv_enclave_quote_body = match base64::decode(&self.isv_enclave_quote_body) {
            Ok(v) => v,
            Err(_) => return None,
        };
        // size of sgx_quote_t is 436 bytes,
        // isv_enclave_quote_body don't have signature and signature len
        SgxQuote::from_isv_bytes(isv_enclave_quote_body)
    }

    pub fn get_isv_enclave_quote_status(&self) -> String {
        self.isv_enclave_quote_status.to_owned()
    }

    pub fn is_enclave_secure(&self, allow_conditional: bool) -> bool {
        // let isv_enclave_quote_status =
        //     EnclaveQuoteStatus::from_str(&self.isv_enclave_quote_status).unwrap();
        let is_secure = match self.isv_enclave_quote_status.as_str() {
            "OK" => true,
            "SIGNATURE_INVALID" => false,
            "GROUP_REVOKED" => false,
            "SIGNATURE_REVOKED" => false,
            "KEY_REVOKED" => false,
            "SIGRL_VERSION_MISMATCH" => false,
            // the following items are conditionally "secure"
            "GROUP_OUT_OF_DATE" => allow_conditional,
            "CONFIGURATION_NEEDED" => allow_conditional,
            "SW_HARDENING_NEEDED" => allow_conditional,
            "CONFIGURATION_AND_SW_HARDENING_NEEDED" => allow_conditional,
            _ => false,
        };
        is_secure
    }
}

#[derive(Default, Clone)]
pub struct SgxRaMsg3 {
    pub raw_ra_msg3: sgx_ra_msg3_t,
    pub quote: SgxQuote,
}

#[derive(Default, Clone)]
pub struct SgxReport {
    pub raw: sgx_report_t,
}

impl SgxReport {
    pub fn to_bytes(&self) -> HexBytes {
        let bytes: [u8; size_of::<sgx_report_t>()] = unsafe { std::mem::transmute_copy(&self.raw) };
        bytes.to_vec().into()
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let mut buf = [0_u8; size_of::<sgx_report_t>()];
        buf.copy_from_slice(data);
        let raw: sgx_report_t = unsafe { std::mem::transmute_copy(&buf) };
        Self { raw }
    }
}

#[derive(Default, Clone)]
pub struct SgxQuote {
    pub raw_quote: sgx_quote_t,
    pub signature: Vec<u8>,
}

impl SgxQuote {
    pub fn get_report_body(&self) -> sgx_report_body_t {
        self.raw_quote.report_body
    }

    pub fn get_mr_enclave(&self) -> [u8; 32] {
        self.raw_quote.report_body.mr_enclave.m
    }

    pub fn get_mr_signer(&self) -> [u8; 32] {
        self.raw_quote.report_body.mr_signer.m
    }

    pub fn get_attributes(&self) -> sgx_attributes_t {
        self.raw_quote.report_body.attributes
    }

    pub fn get_isv_prod_id(&self) -> sgx_prod_id_t {
        self.raw_quote.report_body.isv_prod_id
    }

    pub fn get_isv_svn(&self) -> sgx_isv_svn_t {
        self.raw_quote.report_body.isv_svn
    }

    pub fn is_enclave_debug(&self) -> bool {
        self.raw_quote.report_body.attributes.flags & SGX_FLAGS_DEBUG != 0
    }

    pub fn is_enclave_init(&self) -> bool {
        self.raw_quote.report_body.attributes.flags & SGX_FLAGS_INITTED != 0
    }

    #[allow(unaligned_references)]
    pub fn from_isv_bytes(quote_bytes: Vec<u8>) -> Option<SgxQuote> {
        // Check that quote_bytes is sgx_quote_t up till report_body
        if offset_of!(sgx_quote_t, signature_len) != quote_bytes.len() {
            return None;
        }
        let mut raw_quote_buf = [0_u8; size_of::<sgx_quote_t>()];
        raw_quote_buf[..offset_of!(sgx_quote_t, signature_len)].copy_from_slice(&quote_bytes);
        let quote = SgxQuote {
            raw_quote: unsafe {
                transmute::<[u8; size_of::<sgx_quote_t>()], sgx_quote_t>(raw_quote_buf)
            },
            signature: Vec::new(),
        };
        Some(quote)
    }

    pub fn from_bytes(quote_bytes: Vec<u8>) -> Option<SgxQuote> {
        // Check that quote_bytes is at least sgx_quote_t large
        let actual_sig_size: i32 = quote_bytes.len() as i32 - size_of::<sgx_quote_t>() as i32;
        if actual_sig_size < 0 {
            return None;
        }

        let raw_quote = unsafe { *(quote_bytes.as_ptr() as *const sgx_quote_t) };
        if actual_sig_size as usize != raw_quote.signature_len as usize {
            return None;
        }

        let mut signature: Vec<u8> = vec![0; raw_quote.signature_len as usize];
        signature.copy_from_slice(&quote_bytes[size_of::<sgx_quote_t>()..]);

        let quote = SgxQuote {
            raw_quote: raw_quote,
            signature: signature,
        };
        Some(quote)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let quote_size = size_of::<sgx_quote_t>() + self.signature.len();
        let mut quote_bytes = vec![0_u8; quote_size];
        let quote_bytes_ptr = (&self.raw_quote as *const sgx_quote_t) as *const u8;
        let quote_bytes_slice =
            unsafe { core::slice::from_raw_parts(quote_bytes_ptr, size_of::<sgx_quote_t>()) };
        quote_bytes[..size_of::<sgx_quote_t>()].copy_from_slice(quote_bytes_slice);
        quote_bytes[size_of::<sgx_quote_t>()..].copy_from_slice(self.signature.as_slice());
        quote_bytes
    }
}

impl SgxRaMsg3 {
    pub fn verify(&self, smk: &Aes128Key) -> bool {
        let msg3_bytes = self.as_bytes();
        let msg3_content = match msg3_bytes.get(size_of::<sgx_mac_t>()..) {
            Some(v) => v,
            None => return false,
        };
        let msg3_mac = Aes128Mac {
            mac: self.raw_ra_msg3.mac,
        };
        match smk.verify(msg3_content, &msg3_mac) {
            Ok(v) => v,
            Err(err) => {
                glog::error!("aes128cmac_verify meet error: {:?}", err);
                return false;
            }
        }
    }

    pub fn from_slice(msg3_bytes: &[u8]) -> Result<SgxRaMsg3, String> {
        // We take in a vector of bytes representing the entire msg3.
        // As long as we work within the size of the vec, we're safe.

        // Ensure that the length of vec is at least sgx_ra_msg3_t + sgx_quote_t
        if msg3_bytes.len() < size_of::<sgx_ra_msg3_t>() {
            return Err(format!("msg3 msg is too small"));
        }
        let quote_size = msg3_bytes.len() - size_of::<sgx_ra_msg3_t>();
        if quote_size < size_of::<sgx_quote_t>() {
            return Err(format!("invalid quote size"));
        }

        // TODO: Do some sanity check on the structure of sgx_ra_msg3_t
        // sanity_check(msg3);

        // Create a buffer for safety and copy quote object into it
        let mut quote_bytes: Vec<u8> = vec![0; quote_size];
        let msg3_bytes_ptr = msg3_bytes.as_ptr();
        let quote_bytes_ptr = unsafe { msg3_bytes_ptr.offset(size_of::<sgx_ra_msg3_t>() as isize) };
        let quote_slice = unsafe { core::slice::from_raw_parts(quote_bytes_ptr, quote_size) };
        quote_bytes.copy_from_slice(quote_slice);

        // Try to instantiate SgxQuote object
        if let Some(quote) = SgxQuote::from_bytes(quote_bytes) {
            let msg3 = SgxRaMsg3 {
                raw_ra_msg3: unsafe { *(msg3_bytes_ptr as *const sgx_ra_msg3_t) },
                quote: quote,
            };
            Ok(msg3)
        } else {
            return Err(format!("invalid quote"));
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let msg3_size = size_of::<sgx_ra_msg3_t>() + self.quote.as_bytes().len();
        let mut msg3_bytes = vec![0_u8; msg3_size];
        let msg3_bytes_ptr = (&self.raw_ra_msg3 as *const sgx_ra_msg3_t) as *const u8;
        let msg3_bytes_slice =
            unsafe { core::slice::from_raw_parts(msg3_bytes_ptr, size_of::<sgx_ra_msg3_t>()) };
        msg3_bytes[..size_of::<sgx_ra_msg3_t>()].copy_from_slice(msg3_bytes_slice);
        msg3_bytes[size_of::<sgx_ra_msg3_t>()..].copy_from_slice(self.quote.as_bytes().as_slice());
        msg3_bytes
    }
}

#[derive(Debug)]
pub struct AttestationServerInfo {
    pub conditional_secure: bool,
}

#[derive(Clone, Default)]
pub struct SessionKeys {
    pub g_a: Secp256r1PublicKey,
    pub g_b: Secp256r1PublicKey,
    pub kdk: Aes128Key,
    pub smk: Aes128Key,
    pub sk: Aes128Key,
    pub mk: Aes128Key,
}

pub struct RaMsg1;

impl RaMsg1 {
    pub fn to_hex(msg1: sgx_ra_msg1_t) -> HexBytes {
        let buf = unsafe {
            let slice = std::slice::from_raw_parts(
                (&msg1) as *const _ as *const u8,
                std::mem::size_of_val(&msg1),
            );
            slice.to_vec()
        };
        buf.into()
    }

    pub fn to_sgx(buf: &[u8]) -> sgx_ra_msg1_t {
        let mut p_msg1_buf = [0_u8; std::mem::size_of::<sgx_ra_msg1_t>()];
        p_msg1_buf.copy_from_slice(buf);
        let p_msg1: sgx_ra_msg1_t =
            unsafe { transmute::<[u8; size_of::<sgx_ra_msg1_t>()], sgx_ra_msg1_t>(p_msg1_buf) };
        p_msg1
    }
}

pub struct RaMsg2;
impl RaMsg2 {
    pub fn mac(smk: &Aes128Key, p_msg2: &sgx_ra_msg2_t) -> Result<Aes128Mac, String> {
        let p_msg2_slice_size =
            size_of::<sgx_ra_msg2_t>() - (size_of::<sgx_mac_t>() + size_of::<uint32_t>());
        let p_msg2_bytes_slice = unsafe {
            core::slice::from_raw_parts(
                p_msg2 as *const sgx_ra_msg2_t as *const u8,
                p_msg2_slice_size,
            )
        };
        smk.mac(p_msg2_bytes_slice)
    }

    pub fn to_hex(mut p_msg2: sgx_ra_msg2_t, sigrl: &[u8]) -> HexBytes {
        p_msg2.sig_rl_size = sigrl.len() as u32;
        let full_msg2_size = size_of::<sgx_ra_msg2_t>() + p_msg2.sig_rl_size as usize;
        let mut msg2_buf = vec![0; full_msg2_size];
        let msg2_slice = unsafe {
            core::slice::from_raw_parts(
                &p_msg2 as *const sgx_ra_msg2_t as *const u8,
                size_of::<sgx_ra_msg2_t>(),
            )
        };
        msg2_buf[..size_of::<sgx_ra_msg2_t>()].copy_from_slice(msg2_slice);
        msg2_buf[size_of::<sgx_ra_msg2_t>()..].copy_from_slice(sigrl);
        msg2_buf.into()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AttestationServerState {
    None,
    Msg0 {
        msg0: u32, // maybe should use u8?
        enclave_pubkey: Secp256r1PublicKey,
    },
    Msg1 {
        data: HexBytes,
        enclave_pubkey: Secp256r1PublicKey,
    },
    Msg3 {
        data: HexBytes,
        enclave_pubkey: Secp256r1PublicKey,
    },
    Finalize {
        msg: Aes128EncryptedMsg,
        enclave_pubkey: Secp256r1PublicKey,
    },
}

impl Default for AttestationServerState {
    fn default() -> Self {
        Self::None
    }
}

impl AttestationServerState {
    pub fn enclave_key(&self) -> Option<Secp256r1PublicKey> {
        Some(match self {
            Self::None => return None,
            Self::Msg0 { enclave_pubkey, .. } => *enclave_pubkey,
            Self::Msg1 { enclave_pubkey, .. } => *enclave_pubkey,
            Self::Msg3 { enclave_pubkey, .. } => *enclave_pubkey,
            Self::Finalize { enclave_pubkey, .. } => *enclave_pubkey,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AttestationClientState {
    None,
    Msg0 { success: bool },
    Msg2 { msg2_bytes: HexBytes },
    Msg3 { is_verified: bool },
    Finalize {},
}

#[derive(Debug)]
pub enum AttestationStateError {
    UnexpectedState,
    InvalidMsg0,
    InvalidMsg1,
    InvalidMsg3(String),
    ApplyMsg1Fail(String),
    GetMsg1Fail(String),
    GetMsg2Fail(String),
    Msg3FailGetQuote,
    Msg3FailVerifyQuote,
    Msg3FailVerify,
    ServerRejectedMsg0,
    ServerRejectedMsg3,
    ServerRejectedFinalize,
    FinalizeDecryptFail(String),
    FinalizeGenMsgFail(String),
}

#[derive(Default, Clone)]
pub struct SgxTarget {
    pub raw: sgx_target_info_t,
}

impl SgxTarget {
    pub fn to_bytes(&self) -> HexBytes {
        let bytes: [u8; size_of::<sgx_target_info_t>()] =
            unsafe { std::mem::transmute_copy(&self.raw) };
        bytes.to_vec().into()
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        let mut buf = [0_u8; size_of::<sgx_target_info_t>()];
        buf.copy_from_slice(data);
        let raw: sgx_target_info_t = unsafe { std::mem::transmute_copy(&buf) };
        Self { raw }
    }
}

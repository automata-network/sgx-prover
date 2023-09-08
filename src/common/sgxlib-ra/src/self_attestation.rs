use std::prelude::v1::*;

#[cfg(feature = "tstd")]
use sgxlib::{
    sgx_types::{sgx_epid_group_id_t, sgx_init_quote, sgx_status_t, sgx_target_info_t},
    to_result,
};

#[cfg(feature = "tstd")]
use crate::{
    AttestationStateError, IasReport, IasServer, RaFfi, RaSession, RaUtil, SgxQuote, VerifyError,
};

pub enum SelfAttestation {
    Init,
}

#[derive(Debug)]
pub enum AttestationError {
    InitQuoteFail(String),
    GetSigrlFail(String),
    CreateReportFail(String),
    GetQuoteFail(String),
    VerifyQuoteFail(String),
}

#[cfg(feature = "tstd")]
pub fn self_attestation(
    ias_server: &IasServer,
    data: [u8; 64],
    spid: [u8; 16],
    eid: u64,
) -> Result<IasReport, AttestationError> {
    let (target, gid) = RaFfi::init_quote().map_err(AttestationError::InitQuoteFail)?;
    let sigrl = ias_server
        .get_sigrl(&gid)
        .map_err(AttestationError::GetSigrlFail)?;

    let report =
        RaFfi::create_report(target.raw, data).map_err(AttestationError::CreateReportFail)?;
    let quote =
        RaFfi::get_quote(&report, spid, sigrl.into()).map_err(AttestationError::GetQuoteFail)?;
    let quote = SgxQuote::from_bytes(quote.into())
        .ok_or(AttestationError::GetQuoteFail("invalid quote".into()))?;
    let ias_report = ias_server
        .verify_quote(quote)
        .map_err(AttestationError::VerifyQuoteFail)?;
    Ok(ias_report)
}

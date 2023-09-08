use std::prelude::v1::*;

use jsonrpc::{JsonrpcClient, MixRpcClient};
use sgxlib::sgx_types::sgx_enclave_id_t;

pub fn attestation(id: sgx_enclave_id_t, client: MixRpcClient) {
    let result = sgxlib_ra::exchange_key(id, client);
    glog::info!("exchange_key: {:?}", result);
}
// mod enclave_interface;

use sgxlib_enclave::sgx_types::sgx_status_t;
use sgxlib_enclave::unsafe_ecall;
use sgxlib_enclave::Enclave;

use sgxlib_enclave::sgx_types;
include!(concat!(env!("OUT_DIR"), "/ecall.rs"));

use serde_json;
use std::ffi::CString;

fn main() {
    glog::init();

    let enclave = Enclave::new("sgx_attestor_enclave");

    let args: Vec<String> = std::env::args().collect();
    let args = serde_json::to_string(&args).unwrap();
    let args_ptr = CString::new(args.as_str()).unwrap();
    apps::set_ctrlc({
        let enclave = enclave.clone();
        move || {
            unsafe_ecall!(enclave.eid(), enclave_terminate()).unwrap();
        }
    });
    unsafe_ecall!(
        enclave.eid(),
        enclave_entrypoint(enclave.eid(), args_ptr.as_ptr())
    )
    .unwrap();
}

#[no_mangle]
pub unsafe extern "C" fn sgxlib_ra_ocall(
    msg_in_size: size_t,
    msg_in: *const u8,
    msg_out_size: size_t,
    msg_out: *mut u8,
) -> sgx_status_t {
    sgxlib_ra::RaFfi::on_call(msg_in, msg_in_size, msg_out, msg_out_size)
}

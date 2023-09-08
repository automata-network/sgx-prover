// docker image versioning: 0

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
// #![feature(map_first_last)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgxlib as std;

use app_attestor::App;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::prelude::v1::*;
use std::sgx_trts;
use std::sgx_types::sgx_status_t;

lazy_static::lazy_static! {
    static ref APP: App = App::default();
}

#[no_mangle]
pub unsafe extern "C" fn enclave_entrypoint(eid: u64, args: *const c_char) -> sgx_status_t {
    glog::init();
    glog::info!("Initialize Enclave!");
    match apps::run_enclave(&APP, eid, args) {
        Ok(()) => sgx_status_t::SGX_SUCCESS,
        Err(err) => err,
    }
}

#[no_mangle]
pub unsafe extern "C" fn enclave_terminate() -> sgx_status_t {
    apps::terminate(&APP);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn __assert_fail(
    __assertion: *const u8,
    __file: *const u8,
    __line: u32,
    __function: *const u8,
) -> ! {
    let assertion = unsafe { CStr::from_ptr(__assertion as *const c_char).to_str() }
        .expect("__assertion is not a valid c-string!");
    let file = unsafe { CStr::from_ptr(__file as *const c_char).to_str() }
        .expect("__file is not a valid c-string!");
    let line = unsafe { CStr::from_ptr(__line as *const c_char).to_str() }
        .expect("__line is not a valid c-string!");
    let function = unsafe { CStr::from_ptr(__function as *const c_char).to_str() }
        .expect("__function is not a valid c-string!");
    println!("{}:{}:{}:{}", file, line, function, assertion);

    use sgx_trts::trts::rsgx_abort;
    rsgx_abort()
}

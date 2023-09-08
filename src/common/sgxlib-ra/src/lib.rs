#![cfg_attr(feature = "tstd", no_std)]

#[cfg(feature = "tstd")]
#[macro_use]
extern crate sgxlib as std;

mod ias_server;
pub use ias_server::*;

mod types;
pub use types::*;

mod api;
pub use api::*;

mod client;
pub use client::*;

mod ffi;
pub use ffi::*;

mod self_attestation;
pub use self_attestation::*;
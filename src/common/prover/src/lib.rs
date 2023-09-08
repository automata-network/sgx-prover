#![cfg_attr(feature = "tstd", no_std)]

#[cfg(feature = "tstd")]
#[macro_use]
extern crate sgxlib as std;

mod prover;
pub use prover::*;
mod types;
pub use types::*;
mod executor;
pub use executor::*;

#[cfg(feature = "sgx")]
mod attestation;
#[cfg(feature = "sgx")]
pub use attestation::*;
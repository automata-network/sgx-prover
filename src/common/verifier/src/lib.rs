#![cfg_attr(feature = "tstd", no_std)]

#[cfg(feature = "tstd")]
#[macro_use]
extern crate sgxlib as std;

mod client;
pub use client::*;
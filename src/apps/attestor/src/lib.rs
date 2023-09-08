#![feature(map_first_last)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "tstd")]
#[macro_use]
extern crate sgxlib as std;

pub use apps;

mod app;
pub use app::*;
mod types;
pub use types::*;

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "tstd")]
#[macro_use]
extern crate sgxlib as std;

mod precompile;
pub use precompile::*;
mod state_proxy;
pub use state_proxy::*;
mod context;
pub use context::*;
mod executor;
pub use executor::*;
mod state_fetcher;
pub use state_fetcher::*;

pub use evm::Config;
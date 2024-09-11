use lazy_static::lazy_static;
use tiny_keccak::{Hasher, Keccak};

use crate::{fr::BYTES, Fr};

pub(crate) const MIMC_NB_ROUNDS: usize = 62;
const SEED: &str = "seed";
pub const BLOCK_SIZE: usize = BYTES;

lazy_static! {
    pub(crate) static ref MIMC_CONSTANTS: [Fr; MIMC_NB_ROUNDS] = init_constants();
}

fn init_constants() -> [Fr; MIMC_NB_ROUNDS] {
    let mut mimc = [Fr::default(); MIMC_NB_ROUNDS];

    let mut rnd = keccak_hash(SEED.as_bytes());
    rnd = keccak_hash(&rnd);
    for item in mimc.iter_mut() {
        *item = Fr::from_be(&rnd).unwrap();
        rnd = keccak_hash(&rnd);
    }

    mimc
}

pub fn keccak_hash(data: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    keccak.update(data);
    let mut out = [0_u8; 32];
    keccak.finalize(&mut out);
    out
}

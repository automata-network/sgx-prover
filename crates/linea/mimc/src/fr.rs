use std::prelude::v1::*;

use ff::*;

pub const BYTES: usize = 32;

#[derive(PrimeField)]
#[PrimeFieldModulus = "8444461749428370424248824938781546531375899335154063827935233455917409239041"]
#[PrimeFieldGenerator = "4"]
pub struct Fr(FrRepr);

lazy_static! {
    pub static ref R_SQUARE: Fr = Fr::from_raw_repr(FrRepr([
        2726216793283724667,
        14712177743343147295,
        12091039717619697043,
        81024008013859129,
    ]))
    .unwrap();
}

use ff::PrimeField;
use lazy_static::lazy_static;

impl Fr {
    pub fn from_be(data: &[u8]) -> Result<Self, String> {
        let mut repr = FrRepr::default();
        repr.read_be(data).unwrap();
        let mut tmpfr = Fr(repr);
        tmpfr.mul_assign(&R_SQUARE);

        // check again
        Fr::from_raw_repr(tmpfr.into_raw_repr()).map_err(|err| format!("{:?}", err))
    }

    pub fn bytes(&self) -> [u8; 32] {
        let mut buf = [0_u8; 32];
        self.into_repr().write_be(&mut buf[..]).unwrap();
        buf
    }
}

pub struct ByteOrder {}
impl ByteOrder {
    pub fn element(&self, data: &[u8]) -> Result<Fr, String> {
        Fr::from_be(data)
    }
}

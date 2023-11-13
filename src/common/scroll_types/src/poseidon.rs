use std::prelude::v1::*;

use eth_types::{SH256, SU256};
use zktrie::{Fr, POSEIDON};

const DEFAULT_POSEIDON_CHUNK: usize = 3;
const NBYTES_TO_FIELD_ELEMENT: usize = 31;

lazy_static::lazy_static! {
    pub static ref POSEIDON_EMPTY_CODE: SH256 = poseidon_code_hash(&[]);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoseidonHash;
impl zktrie::HashScheme for PoseidonHash {
    fn hash_scheme(arr: &[Fr], domain: &Fr) -> Fr {
        match POSEIDON.hash_fixed_with_domain(arr, *domain) {
            Ok(output) => output,
            Err(err) => {
                panic!("inp: {:?}, domain: {:?}, err: {:?}", arr, domain, err);
            }
        }
    }
}

pub fn copy_truncated(dst: &mut [u8], src: &[u8]) {
    if dst.len() >= src.len() {
        dst[..src.len()].copy_from_slice(src);
    } else {
        dst.copy_from_slice(&src[..dst.len()])
    }
}

pub fn poseidon_code_hash(code: &[u8]) -> SH256 {
    let length = (code.len() + NBYTES_TO_FIELD_ELEMENT - 1) / NBYTES_TO_FIELD_ELEMENT;

    let mut frs = Vec::with_capacity(length);
    let mut ii = 0;

    while length > 1 && ii < length - 1 {
        let val = match Fr::from_big_endian(
            &code[ii * NBYTES_TO_FIELD_ELEMENT..(ii + 1) * NBYTES_TO_FIELD_ELEMENT],
        ) {
            Ok(val) => val,
            Err(_) => return SH256::default(),
        };
        frs.push(val);
        ii += 1;
    }

    if length > 0 {
        let mut buf = vec![0_u8; NBYTES_TO_FIELD_ELEMENT];
        copy_truncated(&mut buf, &code[ii * NBYTES_TO_FIELD_ELEMENT..]);
        let val = match Fr::from_big_endian(&buf) {
            Ok(val) => val,
            Err(_) => return SH256::default(),
        };
        frs.push(val);
    }

    match POSEIDON.hash_with_cap(&frs, DEFAULT_POSEIDON_CHUNK, code.len()) {
        Ok(val) => {
            let hash: SU256 = val.into();
            hash.into()
        }
        Err(_) => SH256::default(),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_code_hash() {
        glog::init_test();
        let got = poseidon_code_hash(&[]);
        let want: SH256 =
            "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864".into();
        assert_eq!(got, want);

        let got = poseidon_code_hash(&[0]);
        let want: SH256 =
            "0x29f94b67ee4e78b2bb08da025f9943c1201a7af025a27600c2dd0a2e71c7cf8b".into();
        assert_eq!(got, want);

        let got = poseidon_code_hash(&[1]);
        let want: SH256 =
            "0x246d3c06960643350a3e2d587fa16315c381635eb5ac1ac4501e195423dbf78e".into();
        assert_eq!(got, want);

        let got = poseidon_code_hash(&vec![1_u8; 32]);
        let want: SH256 =
            "0x0b46d156183dffdbed8e6c6b0af139b95c058e735878ca7f4dca334e0ea8bd20".into();
        assert_eq!(got, want);
    }
}

use std::prelude::v1::*;

use eth_types::{SH256, SU256};
use poseidon_rs::{Fr, Poseidon};

const DEFAULT_POSEIDON_CHUNK: usize = 3;
const NBYTES_TO_FIELD_ELEMENT: usize = 31;

lazy_static::lazy_static! {
    pub static ref POSEIDON: Poseidon = Poseidon::new();
    pub static ref POSEIDON_EMPTY_CODE: SH256 = poseidon_code_hash(&[]);
}

#[derive(Clone, Debug)]
pub struct PoseidonHash;
impl zktrie::HashScheme for PoseidonHash {
    fn hash_scheme(list: &[SU256], val: &SU256) -> SU256 {
        let inp = list.iter().map(|v| v.clone().into()).collect();
        match POSEIDON.hash_fixed_with_domain(inp, (*val).into()) {
            Ok(output) => output.into(),
            Err(err) => {
                panic!("inp: {:?}, domain: {:?}, err: {:?}", list, val, err);
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

    let mut frs: Vec<SU256> = Vec::with_capacity(length);
    let mut ii = 0;

    while length > 1 && ii < length - 1 {
        let val = SU256::from_big_endian(
            &code[ii * NBYTES_TO_FIELD_ELEMENT..(ii + 1) * NBYTES_TO_FIELD_ELEMENT],
        );
        frs.push(val);
        ii += 1;
    }

    if length > 0 {
        let mut buf = vec![0_u8; NBYTES_TO_FIELD_ELEMENT];
        copy_truncated(&mut buf, &code[ii * NBYTES_TO_FIELD_ELEMENT..]);
        let val = SU256::from_big_endian(&buf);
        frs.push(val);
    }

    let frs: Vec<Fr> = frs.into_iter().map(|n| n.into()).collect();
    match POSEIDON.hash_with_cap(frs, DEFAULT_POSEIDON_CHUNK, code.len()) {
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

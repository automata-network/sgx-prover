use std::borrow::Cow;

use crate::{ByteOrder, Fr, BLOCK_SIZE, MIMC_CONSTANTS};
use ff::Field;

pub fn sum(msg: &[u8]) -> Result<[u8; 32], String> {
    let mut digest = Digest {
        data: vec![],
        byte_order: ByteOrder {},
    };
    digest.write(msg)?;
    let h = digest.checksum();

    Ok(h.bytes())
}

pub struct Digest {
    data: Vec<Fr>,
    byte_order: ByteOrder,
}

impl Digest {
    pub fn write(&mut self, p: &[u8]) -> Result<usize, String> {
        let mut p = Cow::Borrowed(p);
        if p.len() > 0 && p.len() < BLOCK_SIZE {
            let mut pp = vec![0_u8; BLOCK_SIZE];
            pp[BLOCK_SIZE - p.len()..].copy_from_slice(&p);
            p = Cow::Owned(pp);
        }

        let mut start = 0;
        for i in (0..p.len()).step_by(BLOCK_SIZE) {
            start = i;
            let block = &p[start..start + BLOCK_SIZE];
            self.data.push(self.byte_order.element(block)?);
        }
        start += BLOCK_SIZE;
        if start != p.len() {
            return Err("invalid input length: must represent a list of field elements, expects a []byte of len m*BlockSize".into());
        }

        Ok(p.len())
    }

    fn encrypt(&self, hash: &Fr, mut m: Fr) -> Fr {
        for c in MIMC_CONSTANTS.iter() {
            let mut tmp = hash.clone();
            tmp.add_assign(&m);
            tmp.add_assign(c);

            m = tmp;
            m.square();
            m.square();
            m.square();
            m.square();
            m.mul_assign(&tmp);
        }
        m.add_assign(hash);
        m
    }

    pub fn checksum(&self) -> Fr {
        let mut hash = Fr::default();
        for item in &self.data {
            let r = self.encrypt(&hash, item.clone());
            hash.add_assign(&r);
            hash.add_assign(item);
        }
        hash
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mimc_hash() {
        let output = sum(b"hello").unwrap();
        assert_eq!("0f60063a2af76ea29310721ea6b1856c129e66bed7951fa77307e498ab553e66", hex::encode(&output));

        let data = hex::decode("000000000000000000000000000000000000000000000000000000000000002b0000000000000000000000000000000000000000000000001bb72bb8ec449a0007977874126658098c066972282d4c85f230520af3847e297fe7524f976873e50134373b65f439c874734ff51ea349327c140cde2e47a933146e6f9f2ad8eb17c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4700000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let output = sum(&data).unwrap();
        assert_eq!("0c64f7b1d19a07e9908200ac325a6f9ad76fcd1ffb87f458571364f0c8585e66", hex::encode(&output));
    }
}

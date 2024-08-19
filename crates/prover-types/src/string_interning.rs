use std::collections::BTreeMap;

use alloy_primitives::Bytes;

pub struct StringInterningReader(Vec<u8>);

impl StringInterningReader {
    pub fn new(data: &[u8]) -> Self {
        Self(uncompress(data))
    }

    pub fn read(&self, offs: &[usize]) -> Vec<Bytes> {
        let mut out = Vec::with_capacity(offs.len());
        let mut len_bytes = [0_u8; 4];
        for off in offs {
            let off = *off;
            len_bytes.copy_from_slice(&self.0[off..off + 4]);
            let len = u32::from_be_bytes(len_bytes) as usize;
            let data = (&self.0[off + 4..off + 4 + len]).to_owned();
            out.push(data.into());
        }
        out
    }
}

pub struct StringInterning {
    data: Vec<u8>,
    total: usize,
    unique: BTreeMap<Vec<u8>, Option<usize>>,
}

impl StringInterning {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            total: 0,
            unique: BTreeMap::new(),
        }
    }

    pub fn collect(&mut self, data: Vec<u8>) {
        self.total += 4 + data.len();
        self.unique.insert(data, None);
    }

    pub fn build(&mut self) {
        let mut data = Vec::with_capacity(self.total);
        for (val, idx) in &mut self.unique {
            *idx = Some(data.len());
            data.extend((val.len() as u32).to_be_bytes());
            data.extend(val);
        }
        self.data = data;
    }

    pub fn offset(&self, lib: &[u8]) -> usize {
        self.unique.get(lib).unwrap().unwrap()
    }

    pub fn offsets(&self, lib: &[Bytes]) -> Vec<usize> {
        let mut out = Vec::with_capacity(lib.len());
        for item in lib {
            out.push(self.offset(item));
        }
        out
    }

    pub fn to_compress_bytes(&self) -> Vec<u8> {
        compress(&self.data)
    }
}

fn compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    let mut out = Vec::new();
    let mut encoder = libflate::gzip::Encoder::new(&mut out).unwrap();
    encoder.write(&data).unwrap();
    encoder.finish().unwrap();
    out
}

fn uncompress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut decoder = libflate::gzip::Decoder::new(data).unwrap();
    std::io::copy(&mut decoder, &mut out).unwrap();
    out
}

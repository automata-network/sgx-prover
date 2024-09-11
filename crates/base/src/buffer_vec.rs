use std::io::{Error, ErrorKind, Write};

use alloy::primitives::{B256, U256};

#[derive(Debug)]
pub struct BufferVec {
    pub raw: Vec<u8>,
    size: usize,
}

pub trait BufferWriteBytes<T> {
    fn write_bytes(&mut self, n: &T) -> &mut Self;
    fn read_bytes(&mut self) -> Option<T>;
}

impl BufferWriteBytes<B256> for BufferVec {
    fn write_bytes(&mut self, n: &B256) -> &mut Self {
        self.copy_from(n.as_ref());
        self
    }
    fn read_bytes(&mut self) -> Option<B256> {
        let buf = self.read_n(32)?;
        let val = B256::from_slice(buf);
        self.rotate_left(32);
        Some(val)
    }
}

pub trait BufferBeEncode<T> {
    fn write_be(&mut self, n: &T) -> &mut Self;
    fn read_be(&mut self) -> Option<T>;
}

impl BufferBeEncode<U256> for BufferVec {
    fn write_be(&mut self, n: &U256) -> &mut Self {
        let n = n.to_be_bytes::<32>();
        self.must_write(n.len()).copy_from_slice(&n);
        self
    }

    fn read_be(&mut self) -> Option<U256> {
        let buf = self.read_n(32)?;
        let val = U256::from_be_slice(buf);
        self.rotate_left(32);
        Some(val)
    }
}

impl From<Vec<BufferVec>> for BufferVec {
    fn from(list: Vec<BufferVec>) -> Self {
        let cap = list.iter().map(|b| b.cap()).sum();
        let mut buf = Self::new(cap);
        for mut item in list {
            buf.copy_from(item.read());
            item.clear();
        }
        buf
    }
}

impl BufferVec {
    pub fn new(size: usize) -> Self {
        Self {
            raw: vec![0_u8; size],
            size: 0,
        }
    }

    pub fn move_to(&mut self, target: &mut Self) {
        target.copy_from(self.read());
        self.clear();
    }

    pub fn from_slice(slice: &[u8], cap: usize) -> Self {
        let mut buf = Self::new(cap);
        buf.copy_from(slice);
        buf
    }

    pub fn from_vec(mut vec: Vec<u8>, mut cap: usize) -> Self {
        if cap < vec.len() {
            cap = vec.len();
        }
        let size = vec.len();
        vec.resize(cap, 0);
        Self { raw: vec, size }
    }

    pub fn to_vec(mut self) -> Vec<u8> {
        self.raw.truncate(self.size);
        self.raw
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn ends_with(&self, needle: &[u8]) -> bool {
        self.read().ends_with(needle)
    }

    pub fn resize_cap(&mut self, size: usize) {
        self.raw.resize(size, 0);
        if self.size > self.raw.len() {
            self.size = self.raw.len();
        }
    }

    pub fn is_full(&self) -> bool {
        self.raw[self.size..].len() == 0
    }

    pub fn cap(&self) -> usize {
        self.raw.len()
    }

    pub fn read_n(&self, n: usize) -> Option<&[u8]> {
        if self.size >= n {
            return Some(&self.read()[..n]);
        }
        None
    }

    pub fn read(&self) -> &[u8] {
        &self.raw[..self.size]
    }

    pub fn write(&mut self) -> &mut [u8] {
        &mut self.raw[self.size..]
    }

    pub fn must_write(&mut self, n: usize) -> &mut [u8] {
        let buf = &mut self.raw[self.size..self.size + n];
        self.size += n;
        buf
    }

    pub fn advance(&mut self, n: usize) {
        self.size += n;
    }

    pub fn rotate_left(&mut self, n: usize) {
        self.raw.rotate_left(n);
        self.size -= n;
    }

    pub fn clear(&mut self) {
        self.size = 0;
    }

    /// try to read from `reader` until it's fulled.
    pub fn fill_all_with<R>(&mut self, reader: &mut R) -> Result<(), Error>
    where
        R: std::io::Read,
    {
        while !self.is_full() {
            match reader.read(self.write()) {
                Ok(0) => return Err(Error::new(ErrorKind::UnexpectedEof, "unexpected EOF")),
                Ok(incoming_bytes) => {
                    self.advance(incoming_bytes);
                    if self.is_full() {
                        break;
                    }
                }
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    pub fn fill_with<R>(&mut self, reader: &mut R) -> Result<usize, Error>
    where
        R: std::io::Read,
    {
        match reader.read(self.write()) {
            Ok(0) => Err(Error::new(ErrorKind::UnexpectedEof, "unexpected EOF")),
            Ok(incoming_bytes) => {
                self.advance(incoming_bytes);
                Ok(incoming_bytes)
            }
            Err(err) => Err(err),
        }
    }

    pub fn copy_from(&mut self, mut buf: &[u8]) -> usize {
        if self.write().len() < buf.len() {
            buf = &buf[..self.write().len()];
        }
        self.write().write_all(buf).unwrap();
        self.advance(buf.len());
        buf.len()
    }
}

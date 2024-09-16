use core::hash::{Hash, Hasher};
use scroll_executor::{B256, U256};
use scroll_zstd_encoder::{init_zstd_encoder, zstd::zstd_safe::WriteBuf, N_BLOCK_SIZE_TARGET};

pub(crate) fn solidity_parse_bytes(offset: usize, slice: &[u8]) -> Vec<u8> {
    let mut data: Vec<u8> = vec![];
    let data_offset: usize = U256::from_be_slice(&slice[offset..offset + 32]).to();
    let data_len: usize = U256::from_be_slice(&slice[data_offset..data_offset + 32]).to();
    let content_offset = data_offset + 32;
    data.extend_from_slice(&slice[content_offset..content_offset + data_len]);
    data
}

pub(crate) fn solidity_parse_array_bytes(offset: usize, slice: &[u8]) -> Vec<Vec<u8>> {
    let len_offset: usize = U256::from_be_slice(&slice[offset..offset + 32]).to();
    let len: usize = U256::from_be_slice(&slice[len_offset..len_offset + 32]).to();

    let tail_offset = len_offset + 32;
    let tail = &slice[tail_offset..];

    let mut vs = vec![];
    for i in 0..len {
        let data = solidity_parse_bytes(i * 32, tail);
        vs.push(data);
    }
    vs
}

pub(crate) fn decode_block_numbers(mut data: &[u8]) -> Option<Vec<u64>> {
    if data.len() < 1 {
        return None;
    }
    let num_blocks = data[0] as usize;
    data = &data[1..];
    if data.len() < num_blocks * 60 {
        return None;
    }

    let mut numbers = Vec::new();
    let mut tmp = [0_u8; 8];
    for i in 0..num_blocks {
        tmp.copy_from_slice(&data[i * 60..i * 60 + 8]);
        let block_number = u64::from_be_bytes(tmp);
        numbers.push(block_number);
    }
    Some(numbers)
}

pub fn compress_scroll_batch_bytes(src: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let mut encoder = init_zstd_encoder(N_BLOCK_SIZE_TARGET);
    encoder.set_pledged_src_size(Some(src.len() as u64)).expect(
        "compress_scroll_batch_bytes: failed to set pledged src size, should be infallible",
    );

    let ret = encoder
        .write_all(src)
        .and_then(|_| encoder.finish())
        .map_err(|err| format!("{:?}", err))?;
    Ok(ret)
}

pub(crate) fn sha256(buf: &[u8]) -> B256 {
    let mut out = B256::default();
    unsafe { blst::blst_sha256(out.0.as_mut_ptr(), buf.as_ptr(), buf.len()) };
    out
}

pub(crate) fn calc_blob_hash<H: Hash>(version: u8, h: &H) -> B256 {
    pub struct H {
        version: u8,
        hash: B256,
    }
    impl Hasher for H {
        fn write(&mut self, bytes: &[u8]) {
            self.hash = sha256(bytes);
            self.hash.0[0] = self.version;
        }

        fn finish(&self) -> u64 {
            0
        }
    }
    let mut def_hasher = H {
        version,
        hash: B256::default(),
    };
    h.hash(&mut def_hasher);
    def_hasher.hash
}

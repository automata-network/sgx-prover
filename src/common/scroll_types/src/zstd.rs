use std::prelude::v1::*;

use std::io::Write;
use base::format::debug;
use zstd::{
    zstd_safe::{CParameter, ParamSwitch},
    Encoder,
};

// we use offset window no more than = 17
// TODO: use for multi-block zstd.
#[allow(dead_code)]
pub const CL_WINDOW_LIMIT: usize = 17;

/// zstd block size target.
pub const N_BLOCK_SIZE_TARGET: u32 = 124 * 1024;

/// Maximum number of blocks that we can expect in the encoded data.
pub const N_MAX_BLOCKS: u64 = 10;

pub fn init_zstd_encoder(target_block_size: u32) -> Encoder<'static, Vec<u8>> {
    let mut encoder = Encoder::new(Vec::new(), 0).expect("infallible");

    // disable compression of literals, i.e. literals will be raw bytes.
    encoder
        .set_parameter(CParameter::LiteralCompressionMode(ParamSwitch::Disable))
        .expect("infallible");
    // with a hack in zstd we can set window log <= 17 with single segment kept
    encoder
        .set_parameter(CParameter::WindowLog(17))
        .expect("infallible");
    // set target block size to fit within a single block.
    encoder
        .set_parameter(CParameter::TargetCBlockSize(target_block_size))
        .expect("infallible");
    // do not include the checksum at the end of the encoded data.
    encoder.include_checksum(false).expect("infallible");
    // do not include magic bytes at the start of the frame since we will have a single
    // frame.
    encoder.include_magicbytes(false).expect("infallible");
    // do not include dictionary id so we have more simple content
    encoder.include_dictid(false).expect("infallible");
    // include the content size to know at decode time the expected size of decoded
    // data.
    encoder.include_contentsize(true).expect("infallible");

    encoder
}

pub fn compress_scroll_batch_bytes(src: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = init_zstd_encoder(N_BLOCK_SIZE_TARGET);
    encoder.set_pledged_src_size(Some(src.len() as u64)).expect(
        "compress_scroll_batch_bytes: failed to set pledged src size, should be infallible",
    );

    let ret = encoder.write_all(src).and_then(|_| encoder.finish()).map_err(debug)?;
    Ok(ret)
}

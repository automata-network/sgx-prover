use scroll_executor::{Bytes, B256};

base::stack_error! {
    name: BatchError,
    stack_name: BatchErrorStack,
    error: {
        UnknownBatchVersion(u8),
        InvalidBlockNumbers(Bytes),
        InvalidBlockBytes(Bytes),
        InvalidNumBlock(usize),
        InvalidL1Nonce{ expect: u64, current: u64, batch_id: u64, chunk_id: usize, block_id: usize, tx_hash: B256 },
        NumL1TxTooLarge,
        NumTxTooLarge,
        OversizedBatchPayload,
        ZstdEncode(String),
        KzgError(String),
    },
    stack: {
        ParseBatchTaskFromCalldata(),
        EncodeBatchChunk(),
    }
}

impl From<c_kzg::Error> for BatchError {
    fn from(err: c_kzg::Error) -> Self {
        Self::KzgError(format!("{:?}", err))
    }
}

use scroll_executor::{Bytes, B256};

base::stack_error! {
    name: BatchError,
    stack_name: BatchErrorStack,
    error: {
        UnknownBatchVersion(u8),
        InvalidDABatchData{ version: u8, want_at_least: usize, got: usize },

        InvalidBlockNumbers(Bytes),
        InvalidBlockBytes(Bytes),
        InvalidNumBlock(usize),
        InvalidL1Nonce{ expect: u64, current: u64, batch_id: u64, chunk_id: usize, block_id: usize, tx_hash: B256 },
        MismatchBatchVersionAndBlock{ block_batch_version: u8, parent_batch_version: u8 },
        TooManyChunks { max: usize },
        MissingChunks,
        TooFewBlocksInLastChunk,
        NumL1TxTooLarge,
        NumTxTooLarge,
        OversizedBatchPayload{ size: usize },
        ZstdEncode(String),
        KzgError(String),

        UnexpectedBlock { want: (usize, usize), got: (usize, usize) },
        UnknownBlock,
    },
    stack: {
        ParseBatchTaskFromCalldata(),
        EncodeBatchChunk(),
        BuildChunkHash(),
    }
}

impl From<c_kzg::Error> for BatchError {
    fn from(err: c_kzg::Error) -> Self {
        Self::KzgError(format!("{:?}", err))
    }
}

#[cfg(test)]
base::stack_error! {
    name: BatchTestError,
    stack_name: BatchTestErrorStack,
    error: {
        TestEncode { want: String, got: String },
        MismatchHash { want: B256, got: B256 },
    },
    wrap: {
        Hex(hex::FromHexError),
        Batch(BatchError),
    },
    stack: {}
}

use std::marker::PhantomData;

use scroll_executor::{Context, Transaction};

use crate::HardforkConfig;

use super::{
    v0::CodecV0, v1::CodecV1, v2::CodecV2, v3::CodecV3, BatchError, BatchTrait, BatchVersionedType,
    BlockTrait, ChunkTrait, DABatch, TxTrait,
};

pub type BatchBuilderV0 = VersionedBatchBuilder<CodecV0>;
pub type BatchBuilderV1 = VersionedBatchBuilder<CodecV1>;
pub type BatchBuilderV2 = VersionedBatchBuilder<CodecV2>;
pub type BatchBuilderV3 = VersionedBatchBuilder<CodecV3>;

pub enum BatchBuilder {
    V0(BatchBuilderV0),
    V1(BatchBuilderV1),
    V2(BatchBuilderV2),
    V3(BatchBuilderV3),
}

impl BatchBuilder {
    pub fn new(
        fork: HardforkConfig,
        parent: DABatch,
        chunks: Vec<Vec<u64>>,
    ) -> Result<Self, BatchError> {
        let batch_version = fork.batch_version(*chunks.last().unwrap().last().unwrap());
        Ok(match (batch_version, parent.version()) {
            (0, 0) => Self::V0(BatchBuilderV0::new(chunks)),
            (1, 0) => Self::V1(BatchBuilderV1::new(chunks)),
            (1, 1) => Self::V1(BatchBuilderV1::new(chunks)),
            (1, 2) => Self::V2(BatchBuilderV2::new(chunks)),
            (2, 2) => Self::V2(BatchBuilderV2::new(chunks)),
            (2, 3) => Self::V3(BatchBuilderV3::new(chunks)),
            (3, 3) => Self::V3(BatchBuilderV3::new(chunks)),

            (batch_version, pv) => {
                return Err(BatchError::MismatchBatchVersionAndBlock {
                    block_batch_version: batch_version,
                    parent_batch_version: pv,
                })
            }
        })
    }

    pub fn add<C: BatchContext>(&mut self, c: &C) -> Result<(), BatchError> {
        match self {
            Self::V0(b) => b.add(c),
            Self::V1(b) => b.add(c),
            Self::V2(b) => b.add(c),
            Self::V3(b) => b.add(c),
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            Self::V0(_) => 0,
            Self::V1(_) => 1,
            Self::V2(_) => 2,
            Self::V3(_) => 3,
        }
    }

    pub fn build(self, parent: DABatch) -> Result<DABatch, BatchError> {
        Ok(match (self, parent) {
            (Self::V0(b), DABatch::V0(parent)) => DABatch::V0(b.build(parent)?),
            (Self::V1(b), DABatch::V0(parent)) => DABatch::V1(b.build(parent)?),
            (Self::V1(b), DABatch::V1(parent)) => DABatch::V1(b.build(parent)?),
            (Self::V2(b), DABatch::V1(parent)) => DABatch::V2(b.build(parent)?),
            (Self::V2(b), DABatch::V2(parent)) => DABatch::V2(b.build(parent)?),
            (Self::V3(b), DABatch::V2(parent)) => DABatch::V3(b.build(parent)?),
            (Self::V3(b), DABatch::V3(parent)) => DABatch::V3(b.build(parent)?),
            (b, parent) => {
                return Err(BatchError::MismatchBatchVersionAndBlock {
                    block_batch_version: b.version(),
                    parent_batch_version: parent.version(),
                })
            }
        })
    }
}

pub struct VersionedBatchBuilder<T: BatchVersionedType> {
    numbers: Vec<Vec<u64>>,
    _marker: PhantomData<T>,

    current_chunk_id: usize,
    current_block_id: usize,

    pub chunks: Vec<T::Chunk>,
}

pub trait BatchContext: Context {
    fn txs(&self) -> &[Transaction];
    fn tx_rlp(&self, idx: usize) -> Vec<u8>;
}

impl<T: BatchVersionedType> VersionedBatchBuilder<T> {
    pub fn new(numbers: Vec<Vec<u64>>) -> Self {
        Self {
            chunks: Vec::with_capacity(numbers.len()),
            numbers,
            _marker: PhantomData,
            current_block_id: 0,
            current_chunk_id: 0,
        }
    }

    pub fn add<C: BatchContext>(&mut self, ctx: &C) -> Result<(), BatchError> {
        // let batch_id = self.parent_batch_header.batch_index() + 1;
        let mut txs = Vec::new();
        for (tx_idx, tx) in ctx.txs().iter().enumerate() {
            txs.push(T::Tx::new(tx, ctx.tx_rlp(tx_idx)));
        }
        let block = T::Block::new(ctx, txs);

        for (chunk_id, chunk) in self.numbers.iter().enumerate() {
            for (block_id, blkno) in chunk.iter().enumerate() {
                if blkno == &block.number() {
                    let mut expect_chunk_id = self.current_chunk_id;
                    let mut expect_block_id = self.current_block_id;
                    if expect_block_id == self.numbers[self.current_chunk_id].len() {
                        expect_chunk_id += 1;
                        expect_block_id = 0;
                    }
                    if expect_block_id != block_id || expect_chunk_id != chunk_id {
                        return Err(BatchError::UnexpectedBlock {
                            want: (expect_block_id, expect_chunk_id),
                            got: (block_id, chunk_id),
                        });
                    }
                    if block_id == 0 {
                        self.chunks.push(T::Chunk::default());
                    }
                    let chunk = self.chunks.get_mut(chunk_id).unwrap();
                    chunk.add_block(block);

                    self.current_chunk_id = chunk_id;
                    self.current_block_id = block_id + 1;
                    return Ok(());
                }
            }
        }

        Err(BatchError::UnknownBlock)
    }

    pub fn build<B: BatchTrait>(self, parent: B) -> Result<T::Batch, BatchError> {
        T::Batch::new(parent, self.chunks)
    }
}

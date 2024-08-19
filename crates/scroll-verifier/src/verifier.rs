use base::{parallel, Alive};
use prover_types::Poe;
use scroll_executor::{Context, ScrollEvmExecutor};

use crate::{
    BatchChunkBlock, BatchChunkBlockTx, BatchChunkBuilder, BatchTask, HardforkConfig, PobContext,
};

pub struct ScrollBatchVerifier {}

impl ScrollBatchVerifier {
    pub async fn verify(batch: &BatchTask, ctx_list: Vec<PobContext>) -> Result<Poe, String> {
        let alive = Alive::new();
        let hardfork = HardforkConfig::default_from_chain_id(ctx_list.first().unwrap().chain_id());
        let mut batch_chunk = BatchChunkBuilder::new(batch.chunks.clone());
        for ctx in &ctx_list {
            let mut txs = Vec::new();
            for (tx_idx, tx) in ctx.txs().iter().enumerate() {
                txs.push(BatchChunkBlockTx {
                    l1_msg: tx.transaction_type.map(|n| n.as_u64()) == Some(0x7E),
                    nonce: tx.nonce.as_u64(),
                    tx_hash: tx.hash().0.into(),
                    encode: ctx.pob.block.transactions[tx_idx].to_vec(),
                });
            }
            batch_chunk.add_block(BatchChunkBlock {
                number: ctx.number(),
                timestamp: ctx.timestamp().to(),
                base_fee: ctx.base_fee_per_gas(),
                gas_limit: ctx.gas_limit().to(),
                hash: ctx.pob.block.block_hash,
                txs,
            })?;
        }

        let result = parallel(&alive, (), ctx_list, 4, |ctx, _| async move {
            let memdb = ctx.memdb();
            let db = ctx.db(memdb.clone());
            let spec_id = ctx.spec_id();
            let new_root = ScrollEvmExecutor::new(&db, memdb, spec_id).handle_block(&ctx);
            Ok(new_root)
        })
        .await?;

        let new_batch = batch.build_header(hardfork, &batch_chunk.chunks).unwrap();
        let mut poe = Poe::default();
        poe.batch_hash = new_batch.hash();
        poe.new_state_root = result.last().unwrap().0.into();
        Ok(poe)
    }
}

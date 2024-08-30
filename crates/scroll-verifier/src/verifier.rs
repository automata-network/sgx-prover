use std::time::Instant;

use base::{parallel, Alive};
use prover_types::{Poe, B256};
use scroll_executor::{Context, ExecutionError, ExecutionResult, ScrollEvmExecutor};

use crate::{BatchError, BatchTask, HardforkConfig, PobContext};

pub struct ScrollBatchVerifier {}

impl ScrollBatchVerifier {
    pub async fn verify(
        batch: &BatchTask,
        ctx_list: Vec<PobContext>,
    ) -> Result<Poe, ValidateError> {
        let alive = Alive::new();
        let hardfork = HardforkConfig::default_from_chain_id(ctx_list.first().unwrap().chain_id());

        let new_batch = batch.build_batch(hardfork, &ctx_list)?;

        let result = parallel(&alive, (), ctx_list, 4, |ctx, _| async move {
            let memdb = ctx.memdb();
            let db = ctx.db(memdb.clone());
            let spec_id = ctx.spec_id();
            let now = Instant::now();
            let result = ScrollEvmExecutor::new(&db, memdb, spec_id).handle_block(&ctx);
            log::info!(
                "[scroll] generate poe: {} -> {:?}",
                ctx.number(),
                now.elapsed()
            );
            match result {
                Ok(result) => {
                    let result = Self::verify_result(result, &ctx)
                        .map_err(ValidateError::Block(&ctx.number()))?;
                    let mut poe = Poe::default();
                    poe.prev_state_root = ctx.pob.data.prev_state_root;
                    poe.new_state_root = result.new_state_root;
                    poe.withdrawal_root = result.new_withdrawal_root;
                    Ok::<Poe, ValidateError>(poe)
                }
                Err(err) => Err(err.into()),
            }
        })
        .await?;

        let poe = Poe::merge(new_batch.hash(), &result).unwrap();

        Ok(poe)
    }

    fn verify_result<C: Context>(
        result: ExecutionResult,
        ctx: &C,
    ) -> Result<ExecutionResult, ValidateError> {
        if result.new_state_root != ctx.state_root() {
            return Err(ValidateError::StateRootMismatch {
                local: result.new_state_root,
                remote: ctx.state_root(),
            });
        }
        if result.new_withdrawal_root != ctx.withdrawal_root() {
            return Err(ValidateError::WithdrawalRootMismatch {
                local: result.new_withdrawal_root,
                remote: ctx.withdrawal_root(),
            });
        }
        Ok(result)
    }
}

base::stack_error! {
    name: ValidateError,
    stack_name: ValidateErrorStack,
    error: {
        StateRootMismatch { local: B256, remote: B256 },
        WithdrawalRootMismatch { local: B256, remote: B256 },
    },
    wrap: {
        Execution(ExecutionError),
        Batch(BatchError),
    },
    stack: {
        Block(number: u64),
    }
}

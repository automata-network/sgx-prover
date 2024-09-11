use std::time::Instant;

use base::{parallel, Alive};
use clients::EthError;
use prover_types::{Pob, Poe, ProveTaskParams, B256};
use scroll_executor::{Context, ExecutionError, ExecutionResult, ScrollEvmExecutor};

use crate::{
    block_trace_to_pob, BatchError, BatchTask, HardforkConfig, PobContext, ScrollExecutionNode,
};

#[derive(Clone)]
pub struct ScrollBatchVerifier {
    alive: Alive,
    el: Option<ScrollExecutionNode>,
}

impl ScrollBatchVerifier {
    pub fn new(el: Option<&str>) -> Result<Self, ValidateError> {
        let el = match el {
            Some(url) => Some(ScrollExecutionNode::dial(url)?),
            None => None,
        };
        let alive = Alive::new();
        Ok(Self { alive, el })
    }

    pub fn with_context(&self) -> bool {
        self.el.is_none()
    }

    pub async fn generate_context(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<Vec<Pob>, ValidateError> {
        let el = match &self.el {
            Some(el) => el.clone(),
            None => return Err(ValidateError::RequireExecutionEndpoint),
        };
        let blocks = (start_block..=end_block).collect::<Vec<_>>();
        let result = parallel(&self.alive, el, blocks, 4, |blk, el| async move {
            let now = Instant::now();
            let block_trace = el
                .trace_block(blk)
                .await
                .map_err(ValidateError::FailGenBlockTrace(&blk))?;
            let pob = block_trace_to_pob(block_trace).ok_or(ValidateError::FailGenPob)?;
            log::info!("[scroll] generate pob: {} -> {:?}", blk, now.elapsed());
            Ok::<_, ValidateError>(pob)
        })
        .await?;

        Ok(result)
    }

    pub fn cache_key(
        &self,
        params: &ProveTaskParams,
    ) -> Result<(u64, u64, u64, B256), ValidateError> {
        let batch_data = params.batch.as_ref().ok_or(ValidateError::MissingBatch)?;
        let batch = BatchTask::from_calldata(batch_data)?;
        let start_block = batch.start().unwrap();
        let end_block = batch.end().unwrap();
        let key = (batch.id(), start_block, end_block, params.pob_hash);
        Ok(key)
    }

    pub async fn prove(
        &self,
        pob_list: &[Pob],
        params: ProveTaskParams,
    ) -> Result<Poe, ValidateError> {
        let batch_data = params.batch.as_ref().ok_or(ValidateError::MissingBatch)?;
        let batch = BatchTask::from_calldata(batch_data)?;
        let ctx_list = pob_list
            .iter()
            .map(|pob| PobContext::new(pob.clone()))
            .collect();
        let poe = Self::verify(&batch, ctx_list).await?;
        Ok(poe)
    }

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
        RequireExecutionEndpoint,
        FailGenPob,
        MissingBatch,
    },
    wrap: {
        Execution(ExecutionError),
        Batch(BatchError),
        Eth(EthError),
    },
    stack: {
        Block(number: u64),
        FailGenBlockTrace(number: u64),
    }
}

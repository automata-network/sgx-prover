use base::{thread::parallel, trace::Alive};
use clients::{Eth, EthError};
use linea_executor::{CommitState, Context, ExecutionError, LineaEvmExecutor};
use linea_revm::primitives::ExecutionResult;
use linea_shomei::ShomeiConfig;
use prover_types::{Pob, Poe, ProveTaskParams, B256};

use crate::{block_trace_to_pob, BlockTrace, BlockTraceError, DBError, PobContext};

#[derive(Clone)]
pub struct LineaBatchVerifier {
    alive: Alive,
    el: Option<Eth>,
    shomei: Option<linea_shomei::Client>,
}

impl LineaBatchVerifier {
    pub fn new(el: Option<&str>, shomei: Option<ShomeiConfig>) -> Result<Self, ValidateError> {
        let el = match el {
            Some(el) => Some(Eth::dial(el, None)?),
            None => None,
        };
        let shomei = match shomei {
            Some(cfg) => Some(linea_shomei::Client::new(cfg)?),
            None => None,
        };
        let alive = Alive::new();
        Ok(Self { alive, el, shomei })
    }

    pub fn cache_key(
        &self,
        params: &ProveTaskParams,
    ) -> Result<(u64, u64, u64, B256), ValidateError> {
        let start = params.start.unwrap();
        let end = params.end.unwrap();
        let batch_id = end;
        Ok((batch_id, start, end, params.pob_hash))
    }

    pub async fn generate_context(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<Vec<Pob>, ValidateError> {
        let blocks = (start_block..=end_block).collect::<Vec<_>>();
        let el = self
            .el
            .clone()
            .ok_or(ValidateError::ExecutionNodeIsRequired)?;
        let shomei = self.shomei.clone().ok_or(ValidateError::ShomeiIsRequired)?;

        let ctx = (el, shomei);
        let result = parallel(&self.alive, ctx, blocks, 4, Self::generate_single_context).await?;
        Ok(result)
    }

    async fn generate_single_context(
        blk: u64,
        ctx: (Eth, linea_shomei::Client),
    ) -> Result<Pob, ValidateError> {
        let block_trace = BlockTrace::build(&ctx.0, &ctx.1, blk).await?;
        let pob = block_trace_to_pob(block_trace).ok_or(ValidateError::ConvertToPobFailed)?;
        Ok(pob)
    }

    pub async fn prove(
        &self,
        pob_list: &[Pob],
        _params: ProveTaskParams,
    ) -> Result<Poe, ValidateError> {
        let mut ctx_list = Vec::with_capacity(pob_list.len());
        for pob in pob_list {
            ctx_list.push(PobContext::new(pob.clone())?);
        }
        Self::verify(ctx_list).await
    }

    pub async fn verify<C>(ctx_list: Vec<C>) -> Result<Poe, ValidateError>
    where
        C: Context<ExecutionResult = ExecutionResult, CommitState = CommitState> + Send + 'static,
    {
        let alive = Alive::new();
        let result = parallel(&alive, (), ctx_list, 4, |ctx, _| async move {
            let db = ctx.db();
            let spec_id = ctx.spec_id();
            let result = LineaEvmExecutor::new(db, spec_id)
                .handle_block(&ctx)
                .map_err(ValidateError::Block(&ctx.number()))?;
            if result.new_state_root != ctx.state_root() {
                return Err(ValidateError::StateRootMismatch {
                    local: result.new_state_root,
                    remote: ctx.state_root(),
                });
            }
            let mut poe = Poe::default();
            poe.prev_state_root = ctx.old_state_root();
            poe.new_state_root = result.new_state_root;
            Ok::<_, ValidateError>(poe)
        })
        .await?;

        let poe = Poe::merge(B256::default(), &result).unwrap();
        Ok(poe)
    }
}

base::stack_error! {
    #[derive(Debug)]
    name: ValidateError,
    stack_name: ValidateErrorStack,
    error: {
        StateRootMismatch { local: B256, remote: B256 },
        ExecutionNodeIsRequired,
        ShomeiIsRequired,
        ConvertToPobFailed,
    },
    wrap: {
        BlockTrace(BlockTraceError),
        Execution(ExecutionError),
        DB(DBError),
        Eth(EthError),
    },
    stack: {
        Block(number: u64),
    }
}

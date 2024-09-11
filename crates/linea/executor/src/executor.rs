use linea_revm::{
    db::CacheDB,
    primitives::{Env, SpecId},
    Evm,
};

use crate::{CommitState, Context, ExecutionError, ExecutionResult};

pub struct LineaEvmExecutor<C>
where
    C: Context<
        ExecutionResult = linea_revm::primitives::ExecutionResult,
        CommitState = CommitState,
    >,
{
    db: CacheDB<C::DB>,
    spec_id: SpecId,
}

impl<C> LineaEvmExecutor<C>
where
    C: Context<
        ExecutionResult = linea_revm::primitives::ExecutionResult,
        CommitState = CommitState,
    >,
{
    pub fn new(db: C::DB, spec_id: SpecId) -> Self {
        Self {
            db: CacheDB::new(db),
            spec_id,
        }
    }

    pub fn handle_block(mut self, ctx: &C) -> Result<ExecutionResult, ExecutionError> {
        let mut env = Box::<Env>::default();
        env.cfg.chain_id = ctx.chain_id();
        env.block = ctx.block_env();

        for (idx, tx) in ctx.transactions().enumerate() {
            let mut env = env.clone();
            env.tx = ctx.tx_env(idx, Vec::new());

            {
                let mut revm = Evm::builder()
                    .with_spec_id(self.spec_id)
                    .with_db(&mut self.db)
                    .with_env(env.clone())
                    .build();

                let result = revm
                    .transact_commit()
                    .map_err(ExecutionError::CommitTx(&ctx.number(), &tx.tx_hash()))?;
                ctx.verify_execution_result(idx, result);
            }
        }

        let commited_state = ctx.commit_changes(self.db)?;

        Ok(ExecutionResult {
            new_state_root: commited_state.new_state_root,
        })
    }
}

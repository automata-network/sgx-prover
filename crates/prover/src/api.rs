use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use crate::types::{DaApiServer, ProverV1ApiServer, ProverV2ApiServer};
use crate::{
    DaItemLockStatus, DaManager, Metadata, PoeResponse, ProveTaskParams, TaskManager, BUILD_TAG,
};

use alloy::primitives::Bytes;
use async_trait::async_trait;
use base::{parallel, Alive};
use clients::Eth;
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::{ErrorObject, ErrorObjectOwned};
use jsonrpsee::RpcModule;
use prover_types::{keccak_encode, Pob, Poe, SuccinctPobList, TaskType, B256};
use scroll_verifier::{block_trace_to_pob, BatchTask, PobContext, ScrollBatchVerifier};

const POB_EXPIRED_SECS: u64 = 120;

#[derive(Clone)]
pub struct ProverApi {
    pub alive: Alive,
    pub force_with_context: bool,
    pub scroll_el: Option<Eth>,
    pub task_mgr: Arc<TaskManager<BatchTask, Poe, String>>,
    pub pobda_task_mgr: Arc<TaskManager<(u64, u64, B256), Poe, String>>,
    pub pob_da: Arc<DaManager<Vec<Pob>>>,
}

fn jsonrpc_err<E>(code: i32) -> impl Fn(E) -> ErrorObjectOwned
where
    E: std::fmt::Debug,
{
    move |err| ErrorObject::owned(code, format!("{:?}", err), None::<()>)
}

impl ProverApi {
    pub fn rpc(self) -> RpcModule<Self> {
        let mut rpc = ProverV1ApiServer::into_rpc(self.clone());
        rpc.merge(ProverV2ApiServer::into_rpc(self.clone()))
            .unwrap();
        rpc.merge(DaApiServer::into_rpc(self.clone())).unwrap();
        rpc
    }

    pub fn err<M: Into<String>>(&self, code: i32, msg: M) -> ErrorObjectOwned {
        ErrorObject::owned(code, msg, None::<()>)
    }
}

#[async_trait]
impl ProverV1ApiServer for ProverApi {
    async fn generate_attestation_report(&self, req: Bytes) -> RpcResult<Bytes> {
        let mut data = [0_u8; 64];
        if req.len() > 64 {
            return Err(self.err(14002, "invalid report data"));
        }
        data[64 - req.len()..].copy_from_slice(&req);

        let quote = match automata_sgx_builder::dcap::dcap_quote(data) {
            Ok(quote) => quote,
            Err(err) => {
                let msg = format!("generate report failed: {:?}", err);
                return Err(self.err(14003, msg));
            }
        };
        Ok(quote.into())
    }

    async fn get_poe(&self, _arg: B256) -> RpcResult<PoeResponse> {
        unimplemented!()
    }
}

#[async_trait]
impl ProverV2ApiServer for ProverApi {
    async fn prove_task(&self, params: ProveTaskParams) -> RpcResult<PoeResponse> {
        let batch =
            BatchTask::from_calldata(params.batch.as_ref().unwrap()).map_err(jsonrpc_err(14005))?;
        log::info!("batchTask: {:?}, from: {:?}", batch, params.from);
        let batch_id;
        let start_block;
        let end_block;
        let poe = {
            start_block = batch.start().unwrap();
            end_block = batch.end().unwrap();
            batch_id = batch.id();
            let pob_list = self.pob_da.get(&params.pob_hash).unwrap();
            let key = (start_block, end_block, params.pob_hash);
            match self.pobda_task_mgr.process_task(key.clone()).await {
                Some(poe) => poe,
                None => {
                    let ctx_list = pob_list
                        .iter()
                        .map(|n| PobContext::new(n.clone()))
                        .collect();
                    let result = ScrollBatchVerifier::verify(&batch, ctx_list).await;
                    self.pobda_task_mgr.update_task(key, result.clone()).await;
                    result
                }
            }
        }
        .map_err(jsonrpc_err(15001))?;
        Ok(PoeResponse {
            not_ready: true,
            batch_id,
            start_block,
            end_block,
            poe: Some(poe),
        })
    }

    async fn generate_context(
        &self,
        start_block: u64,
        end_block: u64,
        _: u64,
    ) -> RpcResult<SuccinctPobList> {
        let el = match &self.scroll_el {
            Some(scroll_el) => scroll_el.clone(),
            None => return Err(self.err(14005, "server config error: missing config l2")),
        };

        let blocks = (start_block..=end_block).collect::<Vec<_>>();
        let result = parallel(&self.alive, el, blocks, 4, |blk, scroll_el| async move {
            let now = Instant::now();
            let block_trace = scroll_el.trace_block(blk).await;
            let pob = block_trace_to_pob(block_trace).unwrap();

            log::info!("[scroll] generate pob: {} -> {:?}", blk, now.elapsed());
            Ok(pob)
        })
        .await
        .unwrap();
        let pob_list = SuccinctPobList::compress(&result);
        Ok(pob_list)
    }

    async fn metadata(&self) -> RpcResult<Metadata> {
        let mut task_with_context = BTreeMap::new();
        task_with_context.insert(
            TaskType::Scroll.u64(),
            self.force_with_context || self.scroll_el.is_none(),
        );
        task_with_context.insert(TaskType::Linea.u64(), self.force_with_context || true);
        Ok(Metadata {
            with_context: self.force_with_context || self.scroll_el.is_none(),
            task_with_context,
            version: BUILD_TAG.unwrap_or_default(),
        })
    }
}

#[async_trait]
impl DaApiServer for ProverApi {
    async fn da_put_pob(&self, arg: SuccinctPobList) -> RpcResult<()> {
        let pob_list = arg.unwrap();
        let pob_hash = keccak_encode(|hash| {
            for pob in &pob_list {
                hash(pob.hash.as_slice());
            }
        });
        self.pob_da
            .put(pob_hash.into(), Arc::new(pob_list), POB_EXPIRED_SECS);
        Ok(())
    }

    async fn da_try_lock(&self, arg: B256) -> RpcResult<DaItemLockStatus> {
        Ok(self.pob_da.try_lock(&[arg], POB_EXPIRED_SECS).remove(0))
    }
}

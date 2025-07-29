use std::collections::BTreeMap;
use std::future::IntoFuture;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::types::{DaApiServer, ProverV1ApiServer, ProverV2ApiServer};
use crate::{AsyncDcapQuote, Collector, DaItemLockStatus, DaManager, Metadata, TaskManager, BUILD_TAG};

use alloy::primitives::Bytes;
use async_trait::async_trait;
use base::eth::{Eth, Keypair};
use base::format::debug;
use base::thread::wait_timeout;
use base::trace::Alive;
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::{ErrorObject, ErrorObjectOwned};
use jsonrpsee::RpcModule;
use linea_verifier::LineaBatchVerifier;
use prover_types::{
    keccak_encode, poe_digest, Pob, Poe, PoeResponse, ProveTaskParams, SuccinctPobList, TaskType, B256
};
use scroll_da_codec::BatchTask;
use scroll_verifier::ScrollBatchVerifier;

const POB_EXPIRED_SECS: u64 = 120;

#[derive(Clone)]
pub struct ProverApi {
    pub alive: Alive,
    pub sampling: u64,
    pub force_with_context: bool,
    pub l1_el: Option<Eth>,
    pub task_mgr: Arc<TaskManager<BatchTask, Poe, String>>,
    pub pobda_task_mgr: Arc<TaskManager<(u64, u64, u64, B256), Poe, String>>,
    pub pob_da: Arc<DaManager<Vec<Pob>>>,
    pub metrics: Arc<Collector>,
    pub keypair: Keypair,
    pub request_timeout: Option<Duration>,
    pub dcap_quote_generator: Arc<AsyncDcapQuote>,

    pub scroll: ScrollBatchVerifier,
    pub linea: LineaBatchVerifier,
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

    async fn wait<T, F>(&self, f: F) -> RpcResult<T>
    where
        F: IntoFuture<Output = Result<T, ErrorObjectOwned>>,
    {
        match wait_timeout(self.request_timeout, f).await {
            Ok(n) => n,
            Err(_) => Err(ErrorObject::owned(
                14502,
                format!("request timeout"),
                None::<()>,
            )),
        }
    }

    async fn inner_generate_context(
        &self,
        start_block: u64,
        end_block: u64,
        ty: u64,
    ) -> RpcResult<SuccinctPobList> {
        let ty = TaskType::from_u64(ty);

        let start = Instant::now();
        let result = match ty {
            TaskType::Scroll => self
                .scroll
                .generate_context(start_block, end_block)
                .await
                .map_err(jsonrpc_err(14004))?,
            TaskType::Linea => self
                .linea
                .generate_context(start_block, end_block)
                .await
                .map_err(jsonrpc_err(14004))?,
            TaskType::Other(_) => return Err(self.err(14005, format!("unknown task: {:?}", ty))),
        };

        let pob_list = SuccinctPobList::compress(&result);
        let gen_ctx_time = start.elapsed().as_millis() as f64;

        self.pob_da
            .put(pob_list.hash, Arc::new(result), POB_EXPIRED_SECS);

        let data = serde_json::to_vec(&pob_list).unwrap();
        self.metrics
            .pob_size
            .lock()
            .unwrap()
            .set([ty.name()], data.len() as _);
        self.metrics
            .counter_gen_ctx
            .lock()
            .unwrap()
            .inc([ty.name()]);
        self.metrics
            .gauge_gen_ctx_ms
            .lock()
            .unwrap()
            .set([ty.name()], gen_ctx_time);
        Ok(pob_list)
    }

    async fn inner_prove_task(&self, params: ProveTaskParams) -> RpcResult<PoeResponse> {
        let ty = TaskType::from_opu64(params.task_type);

        let pob_list = self
            .pob_da
            .get(&params.pob_hash)
            .ok_or(self.err(14006, format!("pob_hash not found: {:?}", params.pob_hash)))?;

        let cache_key = match ty {
            TaskType::Scroll => self
                .scroll
                .cache_key(params.batch().map_err(jsonrpc_err(14001))?, params.pob_hash)
                .map_err(jsonrpc_err(14001))?,
            TaskType::Linea => self.linea.cache_key(&params).map_err(jsonrpc_err(14001))?,
            TaskType::Other(_) => unreachable!(),
        };

        let poe = match self.pobda_task_mgr.process_task(cache_key.clone()).await {
            Some(poe) => poe,
            None => {
                let start = Instant::now();
                let result = match ty {
                    TaskType::Scroll => self
                        .scroll
                        .prove(
                            pob_list.as_slice(),
                            params.batch().map_err(jsonrpc_err(14001))?,
                        )
                        .await
                        .map_err(debug),
                    TaskType::Linea => self.linea.prove(&pob_list, params).await.map_err(debug),
                    TaskType::Other(_) => unreachable!(),
                };
                self.pobda_task_mgr
                    .update_task(cache_key.clone(), result.clone())
                    .await;
                self.metrics
                    .gauge_prove_ms
                    .lock()
                    .unwrap()
                    .set([ty.name()], start.elapsed().as_millis() as _);
                result
            }
        }
        .map_err(jsonrpc_err(15001))?;
        self.metrics.counter_prove.lock().unwrap().inc([ty.name()]);

        let sig = Keypair::sign_digest_ecdsa(&self.keypair.secret_key(), poe_digest(&poe).into());

        Ok(PoeResponse {
            not_ready: false,
            batch_id: cache_key.0,
            start_block: cache_key.1,
            end_block: cache_key.2,
            poe: Some(poe),
            poe_signature: Some(sig.to_vec().into()),
        })
    }
}

#[async_trait]
impl ProverV1ApiServer for ProverApi {
    async fn generate_attestation_report(&self, mut req: Bytes) -> RpcResult<Bytes> {
        let mut data = [0_u8; 64];
        const ZERO: [u8; 32] = [0_u8; 32];
        if req.len() == 64 {
            if ZERO.eq(&req[0..32]) {
                req = req.slice(32..);
            }
        }

        if req.len() > 32 {
            log::info!("invalid report data: {:?}", Bytes::copy_from_slice(&req));
            return Err(self.err(14002, "invalid report data (too long)"));
        }
        data[64 - req.len()..].copy_from_slice(&req);
        data[12..32].copy_from_slice(self.keypair.address().as_slice());

        
        log::info!("report data: {:?}", Bytes::copy_from_slice(&data));

        let start = Instant::now();

        let result = self.dcap_quote_generator.generate(data).await;

        self.metrics
            .gen_attestation_report_ms
            .lock()
            .unwrap()
            .set([], start.elapsed().as_millis() as f64);

        match result {
            Ok(quote) => Ok(quote.into()),
            Err(err) => {
                let msg = format!("generate report failed: {:?}", err);
                return Err(self.err(14003, msg));
            }
        }
    }

    async fn get_poe(&self, tx_hash: B256) -> RpcResult<PoeResponse> {
        self.wait(self.prove_task_with_sample(tx_hash, None, self.sampling, TaskType::Scroll.u64()))
            .await
    }
}

#[async_trait]
impl ProverV2ApiServer for ProverApi {
    async fn prove_task(&self, params: ProveTaskParams) -> RpcResult<PoeResponse> {
        self.wait(self.inner_prove_task(params)).await
    }

    async fn prove_task_without_context(
        &self,
        task_data: Bytes,
        ty: u64,
    ) -> RpcResult<PoeResponse> {
        self.wait(self.prove_task_with_sample(B256::default(), Some(task_data), 0, ty))
            .await
    }

    async fn generate_context(
        &self,
        start_block: u64,
        end_block: u64,
        ty: u64,
    ) -> RpcResult<SuccinctPobList> {
        self.wait(self.inner_generate_context(start_block, end_block, ty))
            .await
    }

    async fn metadata(&self) -> RpcResult<Metadata> {
        let mut task_with_context = BTreeMap::new();
        task_with_context.insert(
            TaskType::Scroll.u64(),
            self.force_with_context || self.scroll.with_context(),
        );
        task_with_context.insert(TaskType::Linea.u64(), self.force_with_context || true);
        Ok(Metadata {
            with_context: task_with_context
                .get(&TaskType::Scroll.u64())
                .cloned()
                .unwrap_or(true),
            task_with_context,
            version: BUILD_TAG.unwrap_or("v0.1.0"),
        })
    }
}

#[async_trait]
impl DaApiServer for ProverApi {
    async fn da_put_pob(&self, arg: SuccinctPobList) -> RpcResult<()> {
        let pob_list = arg.unwrap();
        let pob_hash = keccak_encode(|hash| {
            for pob in &pob_list {
                hash(pob.pob_hash().as_slice());
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

impl ProverApi {
    async fn prove_task_with_sample(
        &self,
        tx_hash: B256,
        task_data: Option<Bytes>,
        sampling: u64,
        ty: u64,
    ) -> RpcResult<PoeResponse> {
        let ty = TaskType::from_u64(ty);
        if ty != TaskType::Scroll {
            return Err(self.err(14010, format!("unsupported task {:?}", ty)));
        }
        let task_data = match task_data {
            Some(task_data) => task_data,
            None => {
                let Some(l1_el) = &self.l1_el else {
                    return Err(self.err(14011, "missing config for scroll_chain"));
                };

                let tx = l1_el.get_transaction(tx_hash).await.unwrap();
                tx.input
            }
        };
        let task_data: Bytes = task_data[4..].to_owned().into();

        let batch_task = BatchTask::from_calldata(&task_data).unwrap();
        if sampling > 0 {
            if batch_task.id() % sampling != 0 {
                return Err(self.err(14444, "ratelimited, skip this, try next time"));
            }
        }
        println!("task: {:?}", batch_task);

        let pob_list = self
            .inner_generate_context(
                batch_task.start().unwrap(),
                batch_task.end().unwrap(),
                ty.u64(),
            )
            .await?;

        println!(
            "context size: {}",
            serde_json::to_vec(&pob_list).unwrap().len()
        );

        let poe = self
            .inner_prove_task(ProveTaskParams {
                batch: Some(task_data),
                pob_hash: pob_list.hash,
                start: None,
                end: None,
                starting_state_root: None,
                final_state_root: None,
                task_type: Some(ty.u64()),
                from: None,
            })
            .await?;

        Ok(poe)
    }
}

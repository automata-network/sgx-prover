use std::prelude::v1::*;

use apps::Getter;
use base::fs::read_file;
use base::time::Time;
use base::trace::Alive;
use crypto::{keccak_encode, Secp256k1PrivateKey};
use eth_client::ExecutionClient;
use eth_types::{HexBytes, SU256};
use eth_types::{SH256, SU64};
use jsonrpc::{JsonrpcErrorObj, RpcArgs, RpcServer, RpcServerConfig};
use net_http::{HttpRequestReader, HttpResponse, HttpResponseBuilder};
use prover::{Database, Pob, Prover, SuccinctPobList};
use scroll_types::{BatchTask, Poe};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    App, Collector, DaItemLockStatus, DaManager, L1ExecutionClient, PoeResponse, ProveParams,
    ProveTaskParams, TaskManager, BUILD_TAG,
};

const POB_EXPIRED_SECS: u64 = 120;

pub struct PublicApi {
    pub alive: Alive,
    pub prover: Arc<Prover>,
    pub verifier: Option<Arc<verifier::Client>>,
    pub l2_el: Option<Arc<ExecutionClient>>,
    pub l2_chain_id: u64,
    pub l1_el: Option<Arc<L1ExecutionClient>>,
    // pub relay: Option<Secp256k1PrivateKey>,
    pub insecure: bool,
    pub check_report_metadata: bool,
    pub sampling: Option<u64>,
    pub task_mgr: TaskManager<BatchTask, Poe, String>,
    pub pobda_task_mgr: TaskManager<(u64, u64, SH256), Poe, String>,
    pub pob_da: Arc<DaManager<Vec<Pob>>>,
    pub metrics: Arc<Collector>,
    pub force_with_context: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PobResposne {
    pub hash: SH256,
    pub pob: Arc<Pob<HexBytes>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub with_context: bool,
    pub version: &'static str,
}

impl PublicApi {
    fn metric(&self, req: HttpRequestReader) -> HttpResponse {
        HttpResponseBuilder::new(200)
            .body(self.metrics.registry.expose().into_bytes())
            .build()
    }

    // validate a batch of blocks
    // * arg1: start block
    // * arg2: number of blocks to validated
    fn validate(&self, arg: RpcArgs<(SU64, u64)>) -> Result<(), JsonrpcErrorObj> {
        let start_blk = arg.params.0.as_u64();
        for blk_no in start_blk..start_blk + arg.params.1 {
            glog::info!("{}  {}  {}", "=".repeat(20), blk_no, "=".repeat(20));
            let new_arg = arg.map(|_| (blk_no.into(),));
            let report = self.report(new_arg)?;
            glog::info!("prove result: {:?}", report);
        }
        Ok(())
    }

    fn da_put_pob(&self, arg: RpcArgs<(SuccinctPobList,)>) -> Result<(), JsonrpcErrorObj> {
        let pob_list = arg.params.0.unwrap();
        let pob_hash = keccak_encode(|hash| {
            for pob in &pob_list {
                hash(pob.hash.as_bytes());
            }
        });
        self.pob_da
            .put(pob_hash.into(), Arc::new(pob_list), POB_EXPIRED_SECS);
        Ok(())
    }

    // return the pob hash which are miss
    fn da_try_lock(&self, arg: RpcArgs<(SH256,)>) -> Result<DaItemLockStatus, JsonrpcErrorObj> {
        Ok(self
            .pob_da
            .try_lock(&[arg.params.0], POB_EXPIRED_SECS)
            .remove(0))
    }

    fn metadata(&self, arg: RpcArgs<()>) -> Result<Metadata, JsonrpcErrorObj> {
        Ok(Metadata {
            with_context: self.force_with_context || self.l2_el.is_none(),
            version: BUILD_TAG.unwrap_or_default(),
        })
    }

    fn generate_context(
        &self,
        arg: RpcArgs<(u64, u64, u64)>,
    ) -> Result<SuccinctPobList, JsonrpcErrorObj> {
        let block_numbers = (arg.params.0..=arg.params.1).collect();
        let start = Time::now();
        let l2_el = match &self.l2_el {
            Some(l2_el) => l2_el,
            None => {
                return Err(JsonrpcErrorObj::client(format!(
                    "server config error: missing config l2"
                )))
            }
        };
        let pob = App::generate_pob(&self.alive, l2_el, &self.prover, block_numbers)
            .map_err(JsonrpcErrorObj::unknown)?;
        let pob_list = SuccinctPobList::compress(&pob);
        let gen_ctx_time = (Time::now() - start).as_millis() as f64;

        {
            let pob_hash = pob_list.hash;
            self.pob_da
                .put(pob_hash.into(), Arc::new(pob), POB_EXPIRED_SECS);
        }

        let data = serde_json::to_vec(&pob_list).unwrap();
        self.metrics
            .pob_size
            .lock()
            .unwrap()
            .set(["scroll".into()], data.len() as _);
        self.metrics
            .counter_gen_ctx
            .lock()
            .unwrap()
            .inc(["scroll".into()]);
        self.metrics
            .gauge_gen_ctx_ms
            .lock()
            .unwrap()
            .set(["scroll".into()], gen_ctx_time);

        Ok(pob_list)
    }

    fn prove_task_without_context(
        &self,
        arg: RpcArgs<(SH256, u64)>,
    ) -> Result<PoeResponse, JsonrpcErrorObj> {
        let l1_el = match &self.l1_el {
            Some(el) => el,
            None => {
                return Err(JsonrpcErrorObj::client(format!(
                    "missing config for scroll_chain"
                )))
            }
        };

        let tx = l1_el
            .get_transaction(&arg.params.0)
            .map_err(JsonrpcErrorObj::unknown)?;

        let batch_task =
            BatchTask::from_calldata(&tx.input[4..]).map_err(JsonrpcErrorObj::unknown)?;

        let pob_list = self.generate_context(arg.map(|_| {
            (
                batch_task.start().unwrap(),
                batch_task.end().unwrap(),
                arg.params.1,
            )
        }))?;

        let arg = arg.map(|_| {
            (ProveTaskParams {
                batch: tx.input[4..].into(),
                pob_hash: pob_list.hash,
                from: None,
            },)
        });
        self.prove_task(arg)
    }

    fn prove_task(&self, arg: RpcArgs<(ProveTaskParams,)>) -> Result<PoeResponse, JsonrpcErrorObj> {
        let params = arg.params.0;
        let batch = BatchTask::from_calldata(&params.batch).map_err(JsonrpcErrorObj::unknown)?;
        glog::info!("batchTask: {:?}, from: {:?}", batch, params.from);
        let start = batch.start().unwrap();
        let end = batch.end().unwrap();
        let pob_list = self.pob_da.get(&params.pob_hash).unwrap();
        let key = (start, end, params.pob_hash);
        let poe = match self.pobda_task_mgr.process_task(key.clone()) {
            Some(poe) => poe,
            None => {
                let start = Time::now();
                let result = App::generate_poe_by_pob(
                    &self.alive,
                    self.l2_chain_id,
                    &self.prover,
                    &batch,
                    pob_list,
                    4,
                );
                self.pobda_task_mgr.update_task(key, result.clone());
                self.metrics
                    .gauge_prove_ms
                    .lock()
                    .unwrap()
                    .set(["scroll".into()], (Time::now() - start).as_millis() as _);
                result
            }
        }
        .map_err(JsonrpcErrorObj::unknown)?;

        self.metrics
            .counter_prove
            .lock()
            .unwrap()
            .inc(["scroll".into()]);

        let response = PoeResponse {
            not_ready: false,
            batch_id: batch.id(),
            start_block: start,
            end_block: end,
            poe: Some(poe),
        };

        glog::info!(
            "batchTask: {:?}, from: {:?}, response: {:?}",
            batch,
            params.from,
            response
        );

        Ok(response)
    }

    fn get_poe(&self, arg: RpcArgs<(SH256,)>) -> Result<PoeResponse, JsonrpcErrorObj> {
        let l1_el = match &self.l1_el {
            Some(el) => el,
            None => {
                return Err(JsonrpcErrorObj::client(format!(
                    "missing config for scroll_chain"
                )))
            }
        };
        let l2_el = match &self.l2_el {
            Some(l2_el) => l2_el,
            None => {
                return Err(JsonrpcErrorObj::client(format!(
                    "server config error: missing config scroll_endpoint"
                )))
            }
        };

        let tx = l1_el
            .get_transaction(&arg.params.0)
            .map_err(JsonrpcErrorObj::unknown)?;
        let receipt = l1_el
            .get_receipt(&arg.params.0)
            .map_err(JsonrpcErrorObj::unknown)?
            .ok_or_else(|| JsonrpcErrorObj::client("tx missing receipt".into()))?;
        let topic = solidity::encode_eventsig("CommitBatch(uint256,bytes32)");

        let log = receipt
            .logs
            .into_iter()
            .find(|log| log.topics.len() > 0 && log.topics[0] == topic)
            .ok_or_else(|| JsonrpcErrorObj::client("invalid tx".into()))?;

        let batch_id = SU256::from_big_endian(log.topics[1].as_bytes());
        if let Some(sampling) = self.sampling {
            if batch_id.as_u64() % sampling != 0 {
                return Err(JsonrpcErrorObj::client(
                    "ratelimited, skip this, try next time".into(),
                ));
            }
        }
        let batch_hash = log.topics[2];
        let batch_task =
            BatchTask::from_calldata(&tx.input[4..]).map_err(JsonrpcErrorObj::unknown)?;

        if batch_task.chunks.len() == 0 {
            return Err(JsonrpcErrorObj::client("invalid chunk".into()));
        }
        let start_block = *batch_task.chunks[0]
            .first()
            .ok_or(JsonrpcErrorObj::client("invalid chunk".into()))?;
        let end_block = *batch_task.chunks[batch_task.chunks.len() - 1]
            .last()
            .ok_or(JsonrpcErrorObj::client("invalid chunk".into()))?;

        let poe = match self.task_mgr.process_task(batch_task.clone()) {
            Some(poe) => poe,
            None => {
                let result = App::generate_poe(
                    &self.alive,
                    self.l2_chain_id,
                    l2_el,
                    &self.prover,
                    batch_task.clone(),
                );
                self.task_mgr
                    .update_task(batch_task.clone(), result.clone());
                result
            }
        }
        .map_err(JsonrpcErrorObj::unknown)?;

        if poe.batch_hash != batch_hash {
            return Err(JsonrpcErrorObj::client("batch hash mismatch, skip".into()));
        }

        Ok(PoeResponse {
            not_ready: false,
            start_block,
            end_block,
            batch_id: batch_id.as_u64(),
            poe: Some(poe),
        })
    }

    fn generate_attestation_report(
        &self,
        arg: RpcArgs<(HexBytes,)>,
    ) -> Result<HexBytes, JsonrpcErrorObj> {
        if arg.params.0.len() != 64 {
            return Err(JsonrpcErrorObj::unknown("invalid report data"));
        }

        let start = Time::now();

        #[cfg(feature = "tstd")]
        {
            let mut report_data = [0_u8; 64];
            report_data.copy_from_slice(&arg.params.0);
            let quote =
                sgxlib_ra::dcap_generate_quote(report_data).map_err(JsonrpcErrorObj::unknown)?;
            let data = if let Some(verifier) = &self.verifier {
                if self.check_report_metadata {
                    let pass_mrenclave = verifier
                        .verify_mrenclave(quote.get_mr_enclave())
                        .map_err(JsonrpcErrorObj::unknown)?;
                    let pass_mrsigner = verifier
                        .verify_mrsigner(quote.get_mr_signer())
                        .map_err(JsonrpcErrorObj::unknown)?;
                    if !pass_mrenclave || !pass_mrsigner {
                        glog::info!(
                            "mrenclave: {}, mrsigner: {}",
                            HexBytes::from(&quote.get_mr_enclave()[..]),
                            HexBytes::from(&quote.get_mr_signer()[..])
                        );
                        return Err(JsonrpcErrorObj::unknown(format!(
                            "mrenclave[{}] or mr_signer[{}] not trusted",
                            pass_mrenclave, pass_mrsigner
                        )));
                    }
                }

                let data = quote.to_bytes();

                verifier
                    .verify_report_on_chain(&report_data, &data)
                    .map_err(JsonrpcErrorObj::unknown)?;

                data
            } else {
                quote.to_bytes()
            };

            return Ok(data.into());
        }

        let du = Time::now() - start;
        self.metrics
            .gen_attestation_report_ms
            .lock()
            .unwrap()
            .set([], du.as_millis() as _);

        return Err(JsonrpcErrorObj::unknown(
            "generate attestation report is unsupported",
        ));
    }

    // validate a block and generate a execution report
    fn report(&self, arg: RpcArgs<(SU64,)>) -> Result<Poe, JsonrpcErrorObj> {
        let l2_el = match &self.l2_el {
            Some(l2_el) => l2_el,
            None => {
                return Err(JsonrpcErrorObj::client(format!(
                    "server config error: missing config scroll_endpoint"
                )))
            }
        };

        let block_trace = l2_el
            .get_block_trace(arg.params.0.into())
            .map_err(JsonrpcErrorObj::unknown)?;

        let codes = self
            .prover
            .fetch_codes(l2_el, &block_trace)
            .map_err(|err| JsonrpcErrorObj::server("fetch code fail", err))?;
        let new_state_root = block_trace.storage_trace.root_after;
        let withdrawal_root = block_trace.withdraw_trie_root.unwrap_or_default();
        let pob = self.prover.generate_pob(block_trace, codes);

        let params = ProveParams {
            pob,
            withdrawal_root,
            new_state_root,
        };

        let result = self.prove(arg.map(|_| (params,)))?;

        let poe = self
            .prover
            .sign_poe(SH256::default(), &[result])
            .ok_or(JsonrpcErrorObj::client("report not found".into()))?;
        Ok(poe)
    }

    fn prove(&self, arg: RpcArgs<(ProveParams,)>) -> Result<Poe, JsonrpcErrorObj> {
        let params = arg.params.0;
        let pob = params.pob;
        let new_withdrawal_trie_root = params.withdrawal_root;
        let new_state_root = params.new_state_root;

        let prev_state_root = pob.data.prev_state_root;
        let state_hash = pob.state_hash();
        let block_hash = pob.block_hash();

        let block_num = pob.block.header.number.as_u64();
        let db = Database::new(102400);
        let result = self
            .prover
            .execute_block(&db, &pob)
            .map_err(|err| JsonrpcErrorObj::client(format!("block execution fail: {:?}", err)))?;

        if new_state_root != result.new_state_root {
            return Err(JsonrpcErrorObj::client(format!(
                "state not match[{}]: local: {:?} -> remote: {:?}",
                block_num, result.new_state_root, new_state_root,
            )));
        }
        if new_withdrawal_trie_root != result.withdrawal_root {
            return Err(JsonrpcErrorObj::client(format!(
                "withdrawal not match[{}]: local: {:?} -> remote: {:?}",
                block_num, result.withdrawal_root, new_withdrawal_trie_root,
            )));
        }

        let poe = Poe {
            batch_hash: block_hash,
            state_hash,
            prev_state_root,
            new_state_root: result.new_state_root,
            withdrawal_root: result.withdrawal_root,
            ..Default::default()
        };

        return Ok(poe);
    }
}

impl Getter<RpcServer<PublicApi>> for App {
    fn generate(&self) -> RpcServer<PublicApi> {
        let port = self.args.get(self).port;
        let cfg = self.cfg.get(self);

        let (tls_cert, tls_key) = match cfg.server.tls.as_str() {
            "" => (Vec::new(), Vec::new()),
            path => (
                read_file(&format!("{}.crt", path)).unwrap(),
                read_file(&format!("{}.key", path)).unwrap(),
            ),
        };

        let api = Arc::new(PublicApi {
            alive: self.alive.clone(),
            l2_el: self.l2_el.option_get(self),
            l2_chain_id: self.l2_chain_id.get(self).0,
            l1_el: self.l1_el.option_get(self),
            prover: self.prover.get(self),
            verifier: self.verifier.option_get(self),
            insecure: self.args.get(self).insecure,
            check_report_metadata: self.args.get(self).check_report_metadata,
            sampling: self.args.get(self).sampling,
            task_mgr: TaskManager::new(100),
            pob_da: self.pob_da.get(self),
            pobda_task_mgr: TaskManager::new(100),
            metrics: self.metric_collector.get(self),
            force_with_context: self.args.get(self).force_with_context,
        });

        let cfg = RpcServerConfig {
            listen_addr: format!("0.0.0.0:{}", port),
            tls_cert,
            tls_key,
            http_max_body_length: Some(cfg.server.body_limit),
            ws_frame_size: 64 << 10,
            threads: cfg.server.workers,
            queue_size: cfg.server.workers * 16,
            max_idle_secs: Some(60),
        };
        let mut srv = RpcServer::new(self.alive.clone(), cfg, api.clone()).unwrap();
        srv.jsonrpc("prove", PublicApi::prove);
        srv.jsonrpc("report", PublicApi::report);
        srv.jsonrpc("validate", PublicApi::validate);
        srv.jsonrpc(
            "generateAttestationReport",
            PublicApi::generate_attestation_report,
        );
        srv.jsonrpc("getPoe", PublicApi::get_poe);

        srv.jsonrpc("prover_proveTask", PublicApi::prove_task);
        srv.jsonrpc("prover_genContext", PublicApi::generate_context);
        srv.jsonrpc("prover_metadata", PublicApi::metadata);
        srv.jsonrpc(
            "prover_proveTaskWithoutContext",
            PublicApi::prove_task_without_context,
        );
        srv.jsonrpc("da_putPob", PublicApi::da_put_pob);
        srv.jsonrpc("da_tryLock", PublicApi::da_try_lock);
        srv.http_get("/metrics", PublicApi::metric);

        srv
    }
}

use std::prelude::v1::*;

use std::fs::read_to_string;

use apps::Getter;
use base::format::debug;
use base::fs::read_file;
use base::trace::Alive;
use crypto::Secp256k1PrivateKey;
use eth_client::ExecutionClient;
use eth_types::{HexBytes, SU256};
use eth_types::{SH256, SU64};
use jsonrpc::{JsonrpcErrorObj, RpcArgs, RpcServer, RpcServerConfig};
use prover::{Database, Prover};
use scroll_types::Poe;
use std::sync::Arc;

use crate::{App, BatchTask, L1ExecutionClient, PoeResponse, ProveParams, TaskManager};

pub struct PublicApi {
    pub alive: Alive,
    pub prover: Arc<Prover>,
    pub verifier: Arc<verifier::Client>,
    pub l2_el: Arc<ExecutionClient>,
    pub l1_el: Arc<L1ExecutionClient>,
    pub relay: Option<Secp256k1PrivateKey>,
    pub insecure: bool,
    pub check_report_metadata: bool,
    pub task_mgr: TaskManager,
}

impl PublicApi {
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

    fn get_poe(&self, arg: RpcArgs<(SH256,)>) -> Result<PoeResponse, JsonrpcErrorObj> {
        let tx = self
            .l1_el
            .get_transaction(&arg.params.0)
            .map_err(JsonrpcErrorObj::unknown)?;
        let receipt = self
            .l1_el
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
        if batch_id.as_u64() % 20 != 0 {
            return Err(JsonrpcErrorObj::client(
                "ratelimited, skip this, try next time".into(),
            ));
        }
        let batch_hash = log.topics[2];
        let batch_task = BatchTask::from_calldata(batch_id, batch_hash, &tx.input[4..])
            .map_err(JsonrpcErrorObj::unknown)?;

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
                let result =
                    App::generate_poe(&self.alive, &self.l2_el, &self.prover, batch_task.clone());
                self.task_mgr
                    .update_task(batch_task.clone(), result.clone());
                result
            }
        }
        .map_err(JsonrpcErrorObj::unknown)?;

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

        #[cfg(feature = "tstd")]
        {
            let mut report_data = [0_u8; 64];
            report_data.copy_from_slice(&arg.params.0);
            let quote =
                sgxlib_ra::dcap_generate_quote(report_data).map_err(JsonrpcErrorObj::unknown)?;
            if self.check_report_metadata {
                let pass_mrenclave = self
                    .verifier
                    .verify_mrenclave(quote.get_mr_enclave())
                    .map_err(JsonrpcErrorObj::unknown)?;
                let pass_mrsigner = self
                    .verifier
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

            self.verifier
                .verify_report_on_chain(&report_data, &data)
                .map_err(JsonrpcErrorObj::unknown)?;
            return Ok(data.into());
        }
        return Err(JsonrpcErrorObj::unknown(
            "generate attestation report is unsupported",
        ));
    }

    // validate a block and generate a execution report
    fn report(&self, arg: RpcArgs<(SU64,)>) -> Result<Poe, JsonrpcErrorObj> {
        let block_trace = self
            .l2_el
            .get_block_trace(arg.params.0.into())
            .map_err(JsonrpcErrorObj::unknown)?;

        let codes = self
            .prover
            .fetch_codes(&self.l2_el, &block_trace)
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
            .execute_block(&db, pob)
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
            l2_el: self.l2_el.get(self),
            l1_el: self.l1_el.get(self),
            prover: self.prover.get(self),
            verifier: self.verifier.get(self),
            relay: self.cfg.get(self).relay_account.clone(),
            insecure: self.args.get(self).insecure,
            check_report_metadata: self.args.get(self).check_report_metadata,
            task_mgr: TaskManager::new(100),
        });

        let cfg = RpcServerConfig {
            listen_addr: format!("0.0.0.0:{}", port),
            tls_cert,
            tls_key,
            http_max_body_length: Some(cfg.server.body_limit),
            ws_frame_size: 64 << 10,
            threads: cfg.server.workers,
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

        srv
    }
}

use std::prelude::v1::*;

use std::fs::read_to_string;

use apps::Getter;
use base::trace::Alive;
use crypto::Secp256k1PrivateKey;
use eth_client::ExecutionClient;
use eth_types::{SU64, SH256};
use jsonrpc::{JsonrpcErrorObj, RpcArgs, RpcServer, RpcServerConfig};
use prover::{Database, Prover};
use scroll_types::Poe;
use std::sync::Arc;

use crate::{App, ProveParams};

pub struct PublicApi {
    pub alive: Alive,
    pub prover: Arc<Prover>,
    pub verifier: Arc<verifier::Client>,
    pub l2_el: Arc<ExecutionClient>,
    pub relay: Secp256k1PrivateKey,
    pub insecure: bool,
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
                read_to_string(format!("{}.crt", path)).unwrap().into(),
                read_to_string(format!("{}.key", path)).unwrap().into(),
            ),
        };

        let api = Arc::new(PublicApi {
            alive: self.alive.clone(),
            l2_el: self.l2_el.get(self),
            prover: self.prover.get(self),
            verifier: self.verifier.get(self),
            relay: self.cfg.get(self).relay_account.clone(),
            insecure: self.args.get(self).insecure,
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

        srv
    }
}

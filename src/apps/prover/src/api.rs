use std::prelude::v1::*;

use std::borrow::Cow;
use std::fs::read_to_string;
use std::sync::Arc;

use apps::Getter;
use base::trace::Alive;
use crypto::{keccak_hash, Secp256k1PrivateKey};
use eth_client::ExecutionClient;
use eth_types::{BlockSelector, SH256, SU64};
use jsonrpc::{JsonrpcErrorObj, RpcArgs, RpcServer, RpcServerConfig};
use prover::Prover;
use statedb::{TrieMemStore, TrieNode, TrieStore};

use crate::{App, ExecutionReport, ProveParams, ProveResult};

pub struct PublicApi {
    pub alive: Alive,
    pub prover: Arc<Prover>,
    pub verifier: Arc<verifier::Client>,
    pub l2_el: Arc<ExecutionClient>,
    pub relay: Secp256k1PrivateKey,
}

impl PublicApi {
    fn mock(&self, arg: RpcArgs<(SU64, SU64)>) -> Result<ProveResult, JsonrpcErrorObj> {
        // mock transaction from a existing block
        let mut blocks = Vec::new();
        let start = arg.params.0.as_u64() - 1;
        let end = arg.params.1.as_u64();
        let mut prev_state_root = None;
        let mut new_state_root = None;
        for number in start..=end {
            let blk = self
                .l2_el
                .get_block(BlockSelector::Number(number.into()))
                .map_err(JsonrpcErrorObj::unknown)?;

            if number == start {
                prev_state_root = Some(blk.header.state_root);
            } else {
                if number == end {
                    new_state_root = Some(blk.header.state_root);
                }
                blocks.push(blk);
            }
        }
        let prev_state_root = prev_state_root.unwrap();

        let pob = self.prover.generate_pob(prev_state_root, blocks).unwrap();

        glog::info!("pob: {:?}", pob);

        let params = ProveParams {
            pob,
            new_state_root: new_state_root.unwrap(),
            withdrawal_root: SH256::default(),
        };

        self.prove(RpcArgs {
            path: arg.path,
            method: arg.method,
            params: (params,),
            session: arg.session,
        })
    }

    fn prove(&self, arg: RpcArgs<(ProveParams,)>) -> Result<ProveResult, JsonrpcErrorObj> {
        // let params = arg.params.0;
        if !self.verifier.is_attested() {
            return Err(JsonrpcErrorObj::client("prover not attested".into()));
        }

        let p = arg.params.0;

        glog::info!("=================================================");
        glog::info!(
            "prev_state_root:{:?}, new_state_root:{:?}, withdrawal_root:{:?}",
            p.pob.data.prev_state_root,
            p.new_state_root,
            p.withdrawal_root
        );
        let block_hash = p.pob.block_hash();
        let state_hash = p.pob.state_hash();

        for blk in &p.pob.blocks {
            glog::info!(
                "blk[{}]: {:?}, txn: {:?}",
                blk.header.number,
                blk.header.state_root,
                blk.transactions.len(),
            );
        }

        let current_state = self
            .verifier
            .current_state()
            .map_err(JsonrpcErrorObj::unknown)?;

        if !current_state.is_zero() && current_state != p.pob.data.prev_state_root {
            return Err(JsonrpcErrorObj::client(format!(
                "prev state mismatch: want {:?}, got: {:?}",
                current_state, p.pob.data.prev_state_root
            )));
        }

        let mut store = TrieMemStore::new(102400);
        for node in &p.pob.data.mpt_nodes {
            let proofs = std::slice::from_ref(node);
            let node = TrieNode::from_proofs(&store, proofs).unwrap();
            store.add_nodes(node);
        }
        for code in p.pob.data.codes {
            let mut hash = SH256::default();
            hash.0 = keccak_hash(&code);
            store.set_code(hash, Cow::Owned(code));
        }
        store.commit();

        let mut prev_state_root = p.pob.data.prev_state_root;
        for blk in p.pob.blocks {
            let number = blk.header.number;
            let result = self
                .prover
                .execute_block(
                    prev_state_root,
                    store.clone(),
                    &p.pob.data.block_hashes,
                    blk,
                )
                .map_err(|err| {
                    JsonrpcErrorObj::client(format!("prove block: {} fail: {:?}", number, err))
                })?;
            prev_state_root = result.new_state_root;
        }

        if prev_state_root != p.new_state_root {
            return Err(JsonrpcErrorObj::client(format!(
                "state_root not match: local={:?}, input={:?}",
                prev_state_root, p.new_state_root
            )));
        }

        let mut report = ExecutionReport {
            block_hash,
            state_hash,
            prev_state_root: p.pob.data.prev_state_root,
            new_state_root: p.new_state_root,
            withdrawal_root: p.withdrawal_root,
            ..Default::default()
        };
        report.sign(self.prover.prvkey());

        glog::info!("report: {:?}", report);
        // return Err(JsonrpcErrorObj::client("reject".into()));

        let tx_hash = self
            .verifier
            .submit_proof(&self.relay, &report.encode())
            .map_err(JsonrpcErrorObj::unknown)?;

        Ok(ProveResult { report, tx_hash })
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
        srv.jsonrpc("mock", PublicApi::mock);

        srv
    }
}

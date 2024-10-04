use std::{collections::BTreeMap, time::Duration};

use alloy::primitives::Bytes;
use base::debug;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use linea_shomei::ShomeiConfig;
use prover_types::{PoeResponse, ProveTaskParams, SuccinctPobList, B256};
use serde::{Deserialize, Serialize};

use crate::DaItemLockStatus;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub scroll_chain: Option<ScrollChain>,
    #[serde(default)]
    pub server: ServerConfig,
    pub scroll_endpoint: Option<String>,
    pub scroll_chain_id: Option<u64>,

    pub linea_endpoint: Option<String>,
    pub linea_shomei: Option<ShomeiConfig>,

    #[serde(default = "default_l2_timeout_secs")]
    pub l2_timeout_secs: u64,
}

impl Config {
    pub fn read_file(fp: &str) -> Result<Self, String> {
        let data = std::fs::read(fp).map_err(debug)?;
        serde_json::from_slice(&data).map_err(debug)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct ScrollChain {
    pub endpoint: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ServerConfig {
    #[serde(default)]
    pub tls: String,
    #[serde(default = "default_body_limit")]
    pub body_limit: usize,
    #[serde(default = "default_worker")]
    pub workers: usize,
    #[serde(default = "default_queue_size")]
    pub queue_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tls: "".into(),
            body_limit: default_body_limit(),
            workers: default_worker(),
            queue_size: default_queue_size(),
        }
    }
}

fn default_queue_size() -> usize {
    256
}

fn default_body_limit() -> usize {
    52428800
}

fn default_worker() -> usize {
    10
}

pub fn get_timeout(timeout_secs: u64) -> Option<Duration> {
    if timeout_secs > 0 {
        Some(Duration::from_secs(timeout_secs))
    } else {
        None
    }
}

fn default_l2_timeout_secs() -> u64 {
    60
}

#[rpc(server, namespace = "prover")]
pub trait ProverV2Api {
    #[method(name = "proveTask")]
    async fn prove_task(&self, arg: ProveTaskParams) -> RpcResult<PoeResponse>;

    #[method(name = "proveTaskWithoutContext")]
    async fn prove_task_without_context(&self, task_data: Bytes, ty: u64) -> RpcResult<PoeResponse>;

    #[method(name = "genContext")]
    async fn generate_context(
        &self,
        start_block: u64,
        end_block: u64,
        ty: u64,
    ) -> RpcResult<SuccinctPobList>;

    #[method(name = "metadata")]
    async fn metadata(&self) -> RpcResult<Metadata>;
}

#[rpc(server, namespace = "da")]
pub trait DaApi {
    #[method(name = "putPob")]
    async fn da_put_pob(&self, arg: SuccinctPobList) -> RpcResult<()>;
    #[method(name = "tryLock")]
    async fn da_try_lock(&self, arg: B256) -> RpcResult<DaItemLockStatus>;
}

#[rpc(server)]
pub trait ProverV1Api {
    #[method(name = "generateAttestationReport")]
    async fn generate_attestation_report(&self, req: Bytes) -> RpcResult<Bytes>;
    #[method(name = "getPoe")]
    async fn get_poe(&self, arg: B256) -> RpcResult<PoeResponse>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub with_context: bool,
    pub version: &'static str,
    pub task_with_context: BTreeMap<u64, bool>,
}

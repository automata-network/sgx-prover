mod api;
pub use api::*;
mod types;
use jsonrpsee::{
    server::{ServerBuilder, TlsLayer},
    Methods,
};
pub use types::*;
mod da;
pub use crate::da::*;
mod task_manager;
pub use task_manager::*;

use base::Alive;
use clients::Eth;
use std::sync::Arc;

use automata_sgx_builder::types::SgxStatus;
use std::path::Path;

pub static BUILD_TAG: Option<&str> = option_env!("BUILD_TAG");

use clap::Parser;

#[derive(Debug, Parser)]
#[command(version, about = "SGX Prover")]
struct Opt {
    #[clap(short, default_value = "18232")]
    port: u64,
    #[clap(short, default_value = "config/prover.json")]
    cfg: String,
    #[clap(long, default_value = "false")]
    disable_check_report_metadata: bool,
    #[clap(long, default_value = "false")]
    force_with_context: bool,
}

pub async fn entrypoint() {
    let opt: Opt = Opt::parse();

    let cfg = Config::read_file(&opt.cfg).unwrap();

    let alive = Alive::new();

    let scroll_el = cfg
        .scroll_endpoint
        .filter(|n| !n.is_empty())
        .map(|url| Eth::dial(&url));

    let l1_el = cfg
        .scroll_chain
        .map(|n| n.endpoint)
        .filter(|n| !n.is_empty())
        .map(|url| Eth::dial(&url));

    let api = ProverApi {
        alive: alive.clone(),
        force_with_context: opt.force_with_context,
        l1_el,
        scroll_el,
        task_mgr: Arc::new(TaskManager::new(100)),
        pobda_task_mgr: Arc::new(TaskManager::new(100)),
        pob_da: Arc::new(DaManager::new()),
    };

    run_jsonrpc(opt.port, cfg.server.tls, api.rpc()).await
}

pub async fn run_jsonrpc(port: u64, tls: String, methods: impl Into<Methods>) {
    let addr = format!("0.0.0.0:{}", port);
    if tls.len() == 0 {
        let srv = ServerBuilder::new().build(&addr).await.unwrap();
        log::info!("[http] listen on {}", addr);
        srv.start(methods).stopped().await
    } else {
        let certs = format!("{}.crt", tls);
        let key = format!("{}.key", tls);
        let cfg = TlsLayer::single_cert_with_path(Path::new(&certs), Path::new(&key)).unwrap();
        let srv = ServerBuilder::new()
            .set_transport_cfg(cfg)
            .build(&addr)
            .await
            .unwrap();
        log::info!("[https] listen on {}", addr);
        srv.start(methods).stopped().await
    }
}

#[no_mangle]
pub extern "C" fn run_prover() -> SgxStatus {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(entrypoint());
    SgxStatus::Success
}

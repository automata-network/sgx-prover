mod api;
pub use api::*;
mod types;
use linea_verifier::LineaBatchVerifier;
use scroll_verifier::ScrollBatchVerifier;
pub use types::*;
mod da;
pub use da::*;
mod task_manager;
pub use task_manager::*;
mod metrics;
pub use metrics::*;

use base::{eth::Keypair, trace::Alive};
use base::eth::Eth;
use jsonrpsee::{
    server::{tower, ServerBuilder, TlsLayer},
    Methods,
};
use std::{sync::Arc, time::Duration};

use automata_sgx_sdk::types::SgxStatus;
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
    #[clap(long = "disable_check_report_metadata", default_value = "false")]
    disable_check_report_metadata: bool,
    #[clap(long, default_value = "0")]
    sampling: u64,
    #[clap(long = "force_with_context", default_value = "false")]
    force_with_context: bool,
}

pub async fn entrypoint() {
    let opt: Opt = Opt::parse();

    let cfg = Config::read_file(&opt.cfg).unwrap();

    let alive = Alive::new();

    let keypair = Keypair::new();

    let scroll = ScrollBatchVerifier::new(
        cfg.scroll_endpoint.as_ref().map(|n| n.as_str()),
        Some(Duration::from_secs(cfg.l2_timeout_secs)),
    )
    .unwrap();

    let linea = LineaBatchVerifier::new(
        cfg.linea_endpoint.as_ref().map(|n| n.as_str()),
        Some(Duration::from_secs(cfg.l2_timeout_secs)),
        cfg.linea_shomei,
    )
    .unwrap();

    let l1_el = cfg
        .scroll_chain
        .map(|n| n.endpoint)
        .filter(|n| !n.is_empty())
        .map(|url| Eth::dial(&url, None).unwrap());

    let collector = Arc::new(Collector::new("avs"));

    let api = ProverApi {
        alive: alive.clone(),
        force_with_context: opt.force_with_context,
        sampling: opt.sampling,
        l1_el,
        scroll,
        linea,
        task_mgr: Arc::new(TaskManager::new(100)),
        pobda_task_mgr: Arc::new(TaskManager::new(100)),
        pob_da: Arc::new(DaManager::new()),
        metrics: collector.clone(),
        keypair,
    };

    run_jsonrpc(&cfg.server, opt.port, api.rpc(), collector).await
}

pub async fn run_jsonrpc(
    cfg: &ServerConfig,
    port: u64,
    methods: impl Into<Methods>,
    collector: Arc<Collector>,
) {
    let addr = format!("0.0.0.0:{}", port);
    let idle_timeout = Duration::from_secs(60);
    if cfg.tls.len() == 0 {
        let srv = ServerBuilder::new()
            .idle_timeout(idle_timeout)
            .max_request_body_size(cfg.body_limit as _)
            .max_response_body_size(cfg.body_limit as _)
            .set_http_middleware(tower::ServiceBuilder::new().layer(MetricLayer::new(collector)))
            .build(&addr)
            .await
            .unwrap();
        log::info!("[http] listen on {}", addr);
        srv.start(methods).stopped().await
    } else {
        let certs = format!("{}.crt", cfg.tls);
        let key = format!("{}.key", cfg.tls);
        let transport_cfg =
            TlsLayer::single_cert_with_path(Path::new(&certs), Path::new(&key)).unwrap();
        let srv = ServerBuilder::new()
            .idle_timeout(idle_timeout)
            .max_request_body_size(cfg.body_limit as _)
            .max_response_body_size(cfg.body_limit as _)
            .set_transport_cfg(transport_cfg)
            .set_http_middleware(tower::ServiceBuilder::new().layer(MetricLayer::new(collector)))
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

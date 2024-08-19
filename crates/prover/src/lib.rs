mod api;
pub use api::*;
mod types;
pub use types::*;
mod da;
pub use crate::da::*;
mod task_manager;
pub use task_manager::*;

use base::Alive;
use clients::Eth;
use std::sync::Arc;

use automata_sgx_builder::types::SgxStatus;

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

    let scroll_el = cfg.scroll_endpoint.map(|url| Eth::dial(&url));

    let api = ProverApi {
        alive: alive.clone(),
        force_with_context: opt.force_with_context,
        scroll_el,
        task_mgr: Arc::new(TaskManager::new(100)),
        pobda_task_mgr: Arc::new(TaskManager::new(100)),
        pob_da: Arc::new(DaManager::new()),
    };
    let srv = jsonrpsee::server::ServerBuilder::new()
        .build(&format!("0.0.0.0:{}", opt.port))
        .await
        .unwrap();
    let handle = srv.start(api.rpc());
    handle.stopped().await
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

use std::prelude::v1::*;

use prometheus::{CollectorRegistry, Counter, Gauge};
use std::sync::{Arc, Mutex};

pub struct Collector {
    pub counter_gen_ctx: Arc<Mutex<Counter<1>>>,
    pub counter_prove: Arc<Mutex<Counter<1>>>,
    pub counter_metadata: Arc<Mutex<Counter<1>>>,
    pub gauge_gen_ctx_ms: Arc<Mutex<Gauge<1>>>,
    pub gauge_prove_ms: Arc<Mutex<Gauge<1>>>,
    pub rpc_call_ms: Arc<Mutex<Gauge<1>>>,
    pub pob_size: Arc<Mutex<Gauge<1>>>,

    pub gen_attestation_report_ms: Arc<Mutex<Gauge<0>>>,

    pub registry: CollectorRegistry,
}

impl Collector {
    pub fn new(ns: &str) -> Self {
        let mut registry = CollectorRegistry::new();
        let counter_metadata = registry.create_counter(
            ns,
            "prover",
            "metadata",
            "counter for metadata",
            ["version"],
        );
        let counter_gen_ctx = registry.create_counter(
            ns,
            "prover",
            "gen_ctx",
            "counter for generate pob",
            ["type"],
        );
        let counter_prove =
            registry.create_counter(ns, "prover", "prove", "counter for generate poe", ["type"]);
        let gauge_gen_ctx_ms = registry.create_gauge(
            ns,
            "prover",
            "ctx_ms",
            "gauge for generating context",
            ["type"],
        );
        let gauge_prove_ms =
            registry.create_gauge(ns, "prover", "prove_ms", "gauge for generate poe", ["type"]);
        let pob_size = registry.create_gauge(ns, "prover", "pob_size", "the size of pob", ["type"]);
        let rpc_call_ms = registry.create_gauge(
            ns,
            "prover",
            "rpc_call_ms",
            "the milliseconds a rpc call takes",
            ["method"],
        );
        let gen_attestation_report_ms = registry.create_gauge(
            ns,
            "prover",
            "attestation_report_ms",
            "gauge for generate attestation report",
            [],
        );
        Self {
            counter_gen_ctx,
            counter_prove,
            gauge_gen_ctx_ms,
            gauge_prove_ms,
            pob_size,
            rpc_call_ms,
            counter_metadata,

            gen_attestation_report_ms,

            registry,
        }
    }
}

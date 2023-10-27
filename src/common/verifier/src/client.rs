use std::prelude::v1::*;

use base::{format::debug, trace::Alive};
use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use crypto::{keccak_hash, Secp256k1PrivateKey};
use eth_client::{EthCall, ExecutionClient, LogFilter};
use eth_types::{BlockSelector, HexBytes, LegacyTx, TransactionInner, SH160, SH256, SU256};
use jsonrpc::{MixRpcClient, RpcError};
use serde::Deserialize;
use solidity::EncodeArg;
use std::sync::Arc;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    pub addr: SH160,
    pub endpoint: String,
}

#[derive(Clone)]
pub struct Client {
    alive: Alive,
    chain_id: SU256,
    el: ExecutionClient<Arc<MixRpcClient>>,
    to: SH160,
    attested: Arc<AtomicBool>,
}

impl Client {
    pub fn new(alive: &Alive, cfg: Config) -> Self {
        let mut mix = MixRpcClient::new(None);
        mix.add_endpoint(alive, &[cfg.endpoint.clone()]).unwrap();

        let el = ExecutionClient::new(Arc::new(mix));
        let chain_id = el.chain_id().unwrap().into();
        Self {
            alive: alive.clone(),
            chain_id,
            el,
            to: cfg.addr,
            attested: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn el(&self) -> ExecutionClient<Arc<MixRpcClient>> {
        self.el.clone()
    }

    pub fn monitor_attested<F>(
        &self,
        signer: &Secp256k1PrivateKey,
        prover_key: &Secp256k1PrivateKey,
        f: F,
    ) where
        F: Fn() -> Result<Vec<u8>, String>,
    {
        let prover = prover_key.public().eth_accountid().into();
        let mut attested_validity_secs;
        while self.alive.is_alive() {
            let attested_time = match self.prover_status(&prover) {
                Ok(status) => status,
                Err(err) => {
                    glog::error!("getting prover status fail: {:?}", err);
                    self.alive.sleep_ms(1000);
                    continue;
                }
            };

            attested_validity_secs = match self.attest_validity_seconds() {
                Ok(secs) => secs,
                Err(err) => {
                    glog::error!("getting attest_validity_seconds fail: {:?}", err);
                    self.alive.sleep_ms(1000);
                    continue;
                }
            };

            let now = base::time::now().as_secs();
            let is_attesed = attested_time + attested_validity_secs > now;
            self.attested.store(is_attesed, Ordering::SeqCst);
            if attested_time + attested_validity_secs / 2 < now {
                glog::info!("getting prover attested...");
                let report = match f() {
                    Ok(report) => report,
                    Err(err) => {
                        glog::info!("generate report fail: {}", err);
                        self.alive.sleep_ms(1000);
                        continue;
                    }
                };
                if let Err(err) = self.submit_attestation_report(signer, &prover, &report) {
                    glog::info!("submit attestation report fail: {:?}", err);
                    self.alive.sleep_ms(1000);
                    continue;
                }
            } else {
                glog::info!("prover is attested...");
                self.alive
                    .sleep_ms(60.min(attested_validity_secs / 2) * 1000);
                continue;
            }
            self.alive.sleep_ms(5000);
        }
    }

    pub fn is_attested(&self) -> bool {
        self.attested.load(Ordering::SeqCst)
    }

    pub fn attest_validity_seconds(&self) -> Result<u64, RpcError> {
        let data = solidity::Encoder::new("attestValiditySeconds").encode();
        let call = EthCall {
            to: self.to.clone(),
            data: data.into(),
            ..Default::default()
        };
        let val: SU256 = self.el.eth_call(call, BlockSelector::Latest)?;
        Ok(val.as_u64())
    }

    pub fn current_state(&self) -> Result<SH256, RpcError> {
        let data = solidity::Encoder::new("currentStateRoot").encode();
        let call = EthCall {
            to: self.to.clone(),
            data: data.into(),
            ..Default::default()
        };
        let val: SH256 = self.el.eth_call(call, BlockSelector::Latest)?;
        Ok(val)
    }

    pub fn subscribe_attestation_request(
        &self,
        start: Option<u64>,
        signer: &Secp256k1PrivateKey,
        insecure: bool,
    ) -> Result<(), RpcError> {
        let log_trace = eth_client::LogTrace::new(self.alive.clone(), self.el.clone(), 10, 0);
        let sig = solidity::encode_eventsig("RequestAttestation(bytes32)");
        let filter = LogFilter {
            address: vec![self.to],
            topics: vec![vec![sig]],
            ..Default::default()
        };
        let client = self.clone();
        let start = start.unwrap_or(0);
        log_trace.subscribe(start, filter, move |logs| {
            glog::info!("scan attestaion request: {:?}", logs);
            for log in logs {
                let tx = client
                    .el
                    .get_transaction(&log.transaction_hash)
                    .map_err(debug)?;
                let prover = solidity::parse_h160(0, &tx.input[4..]);
                let report = solidity::parse_bytes(32, &tx.input[4..]);
                glog::info!("tx: {:?} -> {}", prover, HexBytes::from(report.as_slice()));
                if let Err(err) = client.validate_report(signer, prover, report, insecure) {
                    glog::error!("validate fail: {}", err);
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    #[allow(unused_variables)]
    fn validate_report(
        &self,
        signer: &Secp256k1PrivateKey,
        prover: SH160,
        report: Vec<u8>,
        insecure: bool,
    ) -> Result<(), String> {
        if !insecure {
            #[cfg(feature = "sgx")]
            {
                use crypto::Secp256k1PublicKey;
                let quote: sgxlib_ra::SgxQuote = serde_json::from_slice(&report).map_err(debug)?;
                sgxlib_ra::RaFfi::dcap_verify_quote(&quote)?;
                let report_data = quote.get_report_body().report_data;
                let mut pubkey = Secp256k1PublicKey::from_raw_bytes(&report_data.d);
                let report_prover_key: SH160 = pubkey.eth_accountid().into();
                if report_prover_key != prover {
                    return Err(format!(
                        "prover account not match: want={:?}, got={:?}",
                        prover, report_prover_key
                    ));
                }
            }
        }

        let hash: SH256 = keccak_hash(&report).into();
        let mut encoder = solidity::Encoder::new("voteAttestationReport");
        encoder.add(&hash);
        encoder.add(&true);

        let result = self.send_tx(signer, encoder.encode()).map_err(debug)?;
        self.wait_receipt(&result, Duration::from_secs(60))
            .map_err(debug)?;
        Ok(())
    }

    pub fn is_attestor(&self, addr: &SH160) -> Result<bool, RpcError> {
        let mut encoder = solidity::Encoder::new("attestors");
        encoder.add(addr);
        let args = encoder.encode();
        let call = EthCall {
            to: self.to.clone(),
            data: args.into(),
            ..Default::default()
        };
        let val: SU256 = self.el.eth_call(call, BlockSelector::Latest)?;
        Ok(val != SU256::zero())
    }

    pub fn prover_status(&self, addr: &SH160) -> Result<u64, RpcError> {
        let mut encoder = solidity::Encoder::new("attestedProvers");
        encoder.add(addr);
        let args = encoder.encode();
        let call = EthCall {
            to: self.to.clone(),
            data: args.into(),
            ..Default::default()
        };
        let val: SU256 = self.el.eth_call(call, BlockSelector::Latest)?;
        Ok(val.as_u64())
    }

    fn send_tx(&self, signer: &Secp256k1PrivateKey, data: Vec<u8>) -> Result<SH256, RpcError> {
        let addr = signer.public().eth_accountid().into();
        let nonce = self.el.nonce(&addr, BlockSelector::Latest)?;
        let gas_price = self.el.gas_price()?;

        let call: Result<serde_json::Value, RpcError> = self.el.eth_call(
            EthCall {
                to: self.to.clone(),
                from: Some(addr),
                gas: None,
                gas_price: None,
                data: data.clone().into(),
            },
            BlockSelector::Latest,
        );
        match call {
            Ok(_) => {}
            Err(err) => {
                glog::info!("call: {:?}", err);
                return Err(err);
            }
        }

        let mut tx = TransactionInner::Legacy(LegacyTx {
            nonce,
            gas_price,
            gas: 1000000.into(),
            to: Some(self.to.clone()).into(),
            data: data.into(),
            ..Default::default()
        });
        tx.sign(signer, self.chain_id.as_u64());

        self.el.send_raw_transaction(&tx)
    }

    pub fn submit_proof(
        &self,
        relay: &Secp256k1PrivateKey,
        report: &[u8],
    ) -> Result<SH256, String> {
        let mut encoder = solidity::Encoder::new("submitProof");
        encoder.add(report);

        let hash = self.send_tx(relay, encoder.encode()).map_err(debug)?;
        self.wait_receipt(&hash, Duration::from_secs(60))?;
        Ok(hash)
    }

    pub fn submit_attestation_report(
        &self,
        relay: &Secp256k1PrivateKey,
        prover: &SH160,
        report: &[u8],
    ) -> Result<(), String> {
        let mut encoder = solidity::Encoder::new("submitAttestationReport");
        encoder.add(prover);
        encoder.add(report);
        let data = encoder.encode();
        let result = self.send_tx(relay, data).map_err(debug)?;
        self.wait_receipt(&result, Duration::from_secs(60))?;
        Ok(())
    }

    pub fn wait_receipt(&self, hash: &SH256, timeout: Duration) -> Result<(), String> {
        let alive = self.alive.fork_with_timeout(timeout);
        while alive.is_alive() {
            match self.el.get_receipt(&hash) {
                Ok(Some(receipt)) => {
                    glog::info!("got receipt({:?}): {:?}", hash, receipt);
                    return Ok(());
                }
                Ok(None) => {
                    glog::info!("waiting receipt({:?}): unconfirmed, retry in 1 secs", hash,);
                }
                Err(err) => {
                    glog::info!("waiting receipt({:?}): {:?}, retry in 1 secs", hash, err);
                }
            }
            alive.sleep_ms(1000);
        }
        Err(format!("waiting receipt({:?}) failed: timeout", hash))
    }
}

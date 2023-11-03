use std::prelude::v1::*;

use base::time::Time;
use base::{format::debug, trace::Alive};
use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use crypto::{keccak_hash, Secp256k1PrivateKey};
use eth_client::{EthCall, ExecutionClient, LogFilter, TxSender};
use eth_types::{
    BlockSelector, HexBytes, LegacyTx, Receipt, TransactionInner, SH160, SH256, SU256,
};
use jsonrpc::{MixRpcClient, RpcError};
use serde::Deserialize;
use solidity::{EncodeArg, Encoder};
use std::sync::Arc;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    pub addr: SH160,
    pub endpoint: String,
}

#[derive(Clone)]
pub struct Client {
    alive: Alive,
    chain_id: u64,
    el: ExecutionClient<Arc<MixRpcClient>>,
    tx_sender: TxSender<Arc<MixRpcClient>>,
    to: SH160,
    attested: Arc<AtomicBool>,
}

impl Client {
    pub fn new(alive: &Alive, cfg: Config) -> Self {
        let mut mix = MixRpcClient::new(None);
        mix.add_endpoint(alive, &[cfg.endpoint.clone()]).unwrap();

        let el = ExecutionClient::new(Arc::new(mix));
        let chain_id = el.chain_id().unwrap();
        let tx_sender = TxSender::new(alive, chain_id, el.clone(), Duration::from_secs(120));
        Self {
            alive: alive.clone(),
            tx_sender,
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
        let mut last_submit = None;
        let submit_cooldown = Duration::from_secs(60);
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

            let mut need_attestation = attested_time + attested_validity_secs / 2 < now;
            if !need_attestation {
                glog::info!("prover is attested...");
                self.alive
                    .sleep_ms(60.min(attested_validity_secs / 2) * 1000);
                continue;
            }

            let need_attestation = if let Some(last_submit) = &last_submit {
                Time::now() > *last_submit + submit_cooldown
            } else {
                true
            };

            if need_attestation {
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
                last_submit = Some(Time::now());
                glog::info!("attestation report submitted");
            } else {
                glog::info!("waiting attestor to approve");
            }
            self.alive.sleep_ms(5000);
        }
    }

    pub fn is_attested(&self) -> bool {
        self.attested.load(Ordering::SeqCst)
    }

    pub fn fetch_report(&self, report_hash: &SH256) -> Result<Option<Vec<u8>>, RpcError> {
        let mut encoder = solidity::Encoder::new("getReportBlockNumber");
        encoder.add(report_hash);
        let call = EthCall {
            to: self.to.clone(),
            data: encoder.encode().into(),
            ..Default::default()
        };
        let val: SU256 = self.el.eth_call(call, BlockSelector::Latest)?;

        let sig = solidity::encode_eventsig("RequestAttestation(bytes32)");
        let filter = LogFilter {
            address: vec![self.to],
            topics: vec![vec![sig]],
            to_block: Some(val),
            from_block: Some(val),
            ..Default::default()
        };
        let logs = self.el.get_logs(&filter)?;
        for log in logs {
            let hash = solidity::parse_h256(0, &log.data);
            if &hash == report_hash {
                let tx = self.el.get_transaction(&log.transaction_hash)?;
                let report = solidity::parse_bytes(32, &tx.input[4..]);
                return Ok(Some(report));
            }
        }
        return Ok(None);
    }

    pub fn get_report_prover(&self, report_hash: &SH256) -> Result<SH160, RpcError> {
        let mut encoder = solidity::Encoder::new("getReportProver");
        encoder.add(report_hash);
        let call = EthCall {
            to: self.to.clone(),
            data: encoder.encode().into(),
            ..Default::default()
        };
        let val: SH256 = self.el.eth_call(call, BlockSelector::Latest)?;
        let mut addr = SH160::default();
        addr.raw_mut().0.copy_from_slice(&val.as_bytes()[12..]);
        Ok(addr)
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

    pub fn subscribe_vote_request(
        &self,
        start: Option<u64>,
        signer: &Secp256k1PrivateKey,
    ) -> Result<(), RpcError> {
        let log_trace = eth_client::LogTrace::new(self.alive.clone(), self.el.clone(), 10, 0);
        let sig = solidity::encode_eventsig("VoteAttestationReport(address,bytes32)");
        let filter = LogFilter {
            address: vec![self.to],
            topics: vec![vec![sig]],
            ..Default::default()
        };
        let client = self.clone();
        let start = start.unwrap_or(0);
        log_trace.subscribe("subscribe_vote_request", start, filter, move |logs| {
            glog::info!("scan vote request: {:?}", logs);
            for log in logs {
                let attestor = solidity::parse_h160(0, &log.data);
                let hash = solidity::parse_h256(32, &log.data);
                glog::info!(
                    "validate vote request: sender:{:?},report:{:?}",
                    attestor,
                    hash
                );
                if let Ok(Some(report)) = client.fetch_report(&hash) {
                    // validate
                    let mut pass = false;
                    if let Ok(prover) = self.get_report_prover(&hash) {
                        pass = self.verify_quote(&prover, &report).is_ok();
                    }

                    if !pass {
                        let result = client.challenge_vote(&attestor, signer, &report);
                        glog::info!("challenge report[{}]: {:?}", hash, result);
                    }
                }
            }
            Ok(())
        })?;
        Ok(())
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
        log_trace.subscribe(
            "subscribe_attestation_request",
            start,
            filter,
            move |logs| {
                glog::info!("scan attestaion request: {:?}", logs);
                for log in logs {
                    let tx = client
                        .el
                        .get_transaction(&log.transaction_hash)
                        .map_err(debug)?;
                    let prover = solidity::parse_h160(0, &tx.input[4..]);
                    let report = solidity::parse_bytes(32, &tx.input[4..]);
                    glog::info!("tx: {:?} -> {}", prover, HexBytes::from(report.as_slice()));
                    if let Err(err) =
                        client.validate_and_vote_report(signer, prover, report, insecure)
                    {
                        glog::error!("validate fail: {}", err);
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    fn challenge_vote(
        &self,
        attestor: &SH160,
        signer: &Secp256k1PrivateKey,
        report: &[u8],
    ) -> Result<(), String> {
        let mut encoder = Encoder::new("challengeReport");
        encoder.add(attestor);
        encoder.add(report);
        let receipt = self
            .send_tx("challenge_vote", signer, encoder.encode())
            .map_err(debug)?;
        Ok(())
    }

    fn verify_quote(&self, prover: &SH160, report: &[u8]) -> Result<(), String> {
        #[cfg(feature = "sgx")]
        {
            use crypto::Secp256k1PublicKey;
            let quote: sgxlib_ra::SgxQuote = serde_json::from_slice(report).map_err(debug)?;
            sgxlib_ra::RaFfi::dcap_verify_quote(&quote)?;
            let report_data = quote.get_report_body().report_data;
            let mut pubkey = Secp256k1PublicKey::from_raw_bytes(&report_data.d);
            let report_prover_key: SH160 = pubkey.eth_accountid().into();
            if &report_prover_key != prover {
                return Err(format!(
                    "prover account not match: want={:?}, got={:?}",
                    prover, report_prover_key
                ));
            }
        }
        Ok(())
    }

    #[allow(unused_variables)]
    fn validate_and_vote_report(
        &self,
        signer: &Secp256k1PrivateKey,
        prover: SH160,
        report: Vec<u8>,
        insecure: bool,
    ) -> Result<(), String> {
        if !insecure {
            self.verify_quote(&prover, &report)?;
        }

        let hash: SH256 = keccak_hash(&report).into();
        let mut encoder = solidity::Encoder::new("voteAttestationReport");
        encoder.add(&hash);
        encoder.add(&true);

        let _ = self.send_tx("vote_attestation_report", signer, encoder.encode())?;
        Ok(())
    }

    pub fn get_voted(&self, report: &SH256, addr: &SH160) -> Result<SU256, RpcError> {
        let mut encoder = solidity::Encoder::new("getVote");
        encoder.add(report);
        encoder.add(addr);
        let args = encoder.encode();
        let call = EthCall {
            to: self.to.clone(),
            data: args.into(),
            ..Default::default()
        };
        let val: SU256 = self.el.eth_call(call, BlockSelector::Latest)?;
        Ok(val)
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

    fn send_tx(
        &self,
        tag: &str,
        signer: &Secp256k1PrivateKey,
        data: Vec<u8>,
    ) -> Result<Receipt, String> {
        let mut receipt = self
            .tx_sender
            .send(signer, Some(self.to), SU256::zero(), data.into())
            .map_err(debug)?;
        glog::info!("[{}]tx sent: {:?}", tag, receipt);
        let result = receipt
            .wait_finished(&self.alive, |this| {
                glog::info!("[{}] tx updates: {:?}", tag, this.status);
            })
            .ok_or_else(|| format!("tx aborted"))?;
        Ok(result)
    }

    pub fn submit_proof(
        &self,
        relay: &Secp256k1PrivateKey,
        report: &[u8],
    ) -> Result<SH256, String> {
        let mut encoder = solidity::Encoder::new("submitProof");
        encoder.add(report);

        let receipt = self.send_tx("submitProof", relay, encoder.encode())?;
        Ok(receipt.transaction_hash)
    }

    pub fn commit_batch(
        &self,
        relay: &Secp256k1PrivateKey,
        batch_id: &SU256,
        report: &[u8],
    ) -> Result<SH256, String> {
        let mut encoder = solidity::Encoder::new("commitBatch");
        encoder.add(batch_id);
        encoder.add(report);

        let receipt = self.send_tx("commit_batch", relay, encoder.encode())?;
        Ok(receipt.transaction_hash)
    }

    pub fn verify_report_on_chain(&self, report: &[u8]) -> Result<bool, RpcError> {
        let mut encoder = solidity::Encoder::new("verifyAttestation");
        encoder.add(report);

        let call = EthCall {
            to: self.to.clone(),
            data: encoder.encode().into(),
            ..Default::default()
        };
        let val: SU256 = self.el.eth_call(call, BlockSelector::Latest)?;
        Ok(val.as_u64() == 1)
    }

    pub fn submit_attestation_report(
        &self,
        relay: &Secp256k1PrivateKey,
        prover: &SH160,
        report: &[u8],
    ) -> Result<SH256, String> {
        let mut encoder = solidity::Encoder::new("submitAttestationReport");
        encoder.add(prover);
        encoder.add(report);
        let data = encoder.encode();
        let receipt = self.send_tx("submit_attestation_report", relay, data)?;
        Ok(receipt.transaction_hash)
    }
}

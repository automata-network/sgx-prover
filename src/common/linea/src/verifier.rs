use std::prelude::v1::*;

use base::{format::debug, trace::Alive};
use crypto::Secp256k1PrivateKey;
use eth_tools::{EthCall, ExecutionClient, RpcClient, RpcError, TxSender};
use eth_types::{BlockSelector, EngineTypes, ReceiptTrait, SH160, SH256, SU256};
use solidity::EncodeArg;
use std::time::Duration;

pub struct VerifierConfig {
    pub addr: SH160,
    pub endpoint: String,
}

#[derive(Debug, Clone)]
pub struct Verifier<C, E>
where
    C: RpcClient,
    E: EngineTypes,
{
    alive: Alive,
    el: ExecutionClient<C, E>,
    tx_sender: TxSender<C, E>,
    to: SH160,
}

impl<C, E> Verifier<C, E>
where
    C: RpcClient + Clone + Send + 'static,
    E: EngineTypes,
{
    pub fn new(
        alive: &Alive,
        chain_id: u64,
        el: ExecutionClient<C, E>,
        resend_timeout: Duration,
        contract: SH160,
    ) -> Self {
        let tx_sender = TxSender::new(alive, chain_id, el.clone(), resend_timeout);
        Self {
            alive: alive.clone(),
            tx_sender,
            el,
            to: contract,
        }
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

    pub fn verify_mrenclave(&self, mrenclave: [u8; 32]) -> Result<bool, String> {
        let mut hash = SH256::default();
        hash.raw_mut().0 = mrenclave;
        let mut encoder = solidity::Encoder::new("verifyMrEnclave");
        encoder.add(&hash);
        let args = encoder.encode();
        let call = EthCall {
            to: self.to.clone(),
            data: args.into(),
            ..Default::default()
        };
        let val: SU256 = self
            .el
            .eth_call(call, BlockSelector::Latest)
            .map_err(debug)?;
        Ok(!val.is_zero())
    }

    pub fn verify_mrsigner(&self, mrenclave: [u8; 32]) -> Result<bool, String> {
        let mut hash = SH256::default();
        hash.raw_mut().0 = mrenclave;
        let mut encoder = solidity::Encoder::new("verifyMrSigner");
        encoder.add(&hash);
        let args = encoder.encode();
        let call = EthCall {
            to: self.to.clone(),
            data: args.into(),
            ..Default::default()
        };
        let val: SU256 = self
            .el
            .eth_call(call, BlockSelector::Latest)
            .map_err(debug)?;
        Ok(!val.is_zero())
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
        Ok(*receipt.transaction_hash())
    }

    fn send_tx(
        &self,
        tag: &str,
        signer: &Secp256k1PrivateKey,
        data: Vec<u8>,
    ) -> Result<E::Receipt, String> {
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

    pub fn verify_report_on_chain(&self, prover: &SH160, report: &[u8]) -> Result<bool, RpcError> {
        let mut encoder = solidity::Encoder::new("verifyAttestation");
        encoder.add(prover);
        encoder.add(report);

        let call = EthCall {
            to: self.to.clone(),
            data: encoder.encode().into(),
            ..Default::default()
        };
        let val: SU256 = self.el.eth_call(call, BlockSelector::Latest)?;
        Ok(val.as_u64() == 1)
    }

    pub fn generate_prover_report(
        &self,
        prover_key: &SH160,
        _check_report_metadata: bool,
    ) -> Result<Vec<u8>, String> {
        let mut report_data = [0_u8; 64];
        report_data[44..].copy_from_slice(prover_key.as_bytes());
        #[cfg(feature = "tstd")]
        {
            let quote = sgxlib_ra::dcap_generate_quote(report_data).map_err(debug)?;
            if _check_report_metadata {
                use eth_types::HexBytes;
                let pass_mrenclave = self
                    .verify_mrenclave(quote.get_mr_enclave())
                    .map_err(debug)?;
                let pass_mrsigner = self.verify_mrsigner(quote.get_mr_signer()).map_err(debug)?;
                if !pass_mrenclave || !pass_mrsigner {
                    return Err(format!(
                        "mrenclave[{}:{}] or mr_signer[{}:{}] not trusted",
                        HexBytes::from(&quote.get_mr_enclave()[..]),
                        pass_mrenclave,
                        pass_mrsigner,
                        HexBytes::from(&quote.get_mr_signer()[..])
                    ));
                }
            }

            let data = quote.to_bytes();

            self.verify_report_on_chain(&prover_key, &data)
                .map_err(debug)?;
            return Ok(data.into());
        }
        #[cfg(not(feature = "tstd"))]
        return Err("fail to generate attestation report".into());
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
        Ok(*receipt.transaction_hash())
    }

    pub fn recover_poe(&self, poe: &[u8]) -> Result<SH160, RpcError> {
        let mut encoder = solidity::Encoder::new("recoverPoe");
        encoder.add(poe);

        let call = EthCall {
            to: self.to.clone(),
            data: encoder.encode().into(),
            ..Default::default()
        };
        let val: SH256 = self.el.eth_call(call, BlockSelector::Latest)?;
        let mut addr = SH160::default();
        addr.as_bytes_mut().copy_from_slice(&val.0[12..]);
        Ok(addr)
    }

    pub fn l2_chain_id(&self) -> Result<u64, RpcError> {
        let data = solidity::Encoder::new("layer2ChainId").encode();
        let call = EthCall {
            to: self.to.clone(),
            data: data.into(),
            ..Default::default()
        };
        let val: SU256 = self.el.eth_call(call, BlockSelector::Latest)?;
        Ok(val.as_u64())
    }
}

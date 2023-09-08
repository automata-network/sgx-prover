use core::time::Duration;
use std::prelude::v1::*;

use crate::{IasReport, IasReportData, IasReportRequest, SgxQuote};

use base::format::debug;
use eth_types::HexBytes;

use net_http::{HttpClient, HttpMethod, HttpRequestBuilder, Uri};

pub struct IasServer {
    api_key: String,
    client: HttpClient,
    timeout: Option<Duration>,
    base_url: &'static str,
}

impl IasServer {
    pub fn new(apikey: &str, is_dev: bool, timeout: Option<Duration>) -> IasServer {
        let base_url = if is_dev {
            "https://api.trustedservices.intel.com/sgx/dev"
        } else {
            "https://api.trustedservices.intel.com/sgx"
        };

        IasServer {
            client: HttpClient::new(),
            api_key: String::from(apikey),
            base_url,
            timeout,
        }
    }

    pub fn verify_quote(&self, quote: SgxQuote) -> Result<IasReport, String> {
        let quote_bytes = quote.as_bytes();

        // get a random nonce
        let random_nonce = {
            let mut buf = [0_u8; 16];
            crypto::read_rand(&mut buf);
            let random_nonce = format!("{}", HexBytes::from(&buf[..]));
            random_nonce[2..].to_owned()
        };

        let report_request = IasReportRequest {
            isv_enclave_quote: base64::encode(quote_bytes),
            nonce: Some(random_nonce),
        };
        let report_request_json = serde_json::to_string(&report_request).unwrap();

        let api_uri: Uri = format!("{}/attestation/v4/report", self.base_url)
            .parse()
            .map_err(|err| format!("generate uri fail: {:?}", err))?;

        let api_key = self.api_key.clone();
        let mut req =
            HttpRequestBuilder::new_ex(api_uri, Some(report_request_json.into()), move |req| {
                req.header("Ocp-Apim-Subscription-Key", &api_key)
                    .header("Content-Type", "application/json")
                    .method(HttpMethod::Post);
            });
        let response = self
            .client
            .send(&mut req, self.timeout)
            .map_err(|err| format!("send request fail: {:?}", err))?;
        if !response.status.is_success() {
            if response.status.is(|c| c == 400) {
                return Err("invalid quote".into());
            }
            let msg = String::from_utf8_lossy(&response.body);
            return Err(format!("verify fail: {:?}: {}", response.status, msg));
        }
        let sig = response
            .headers
            .get("X-IASReport-Signature")
            .ok_or("should have report sig")?;
        let cert = response
            .headers
            .get("X-IASReport-Signing-Certificate")
            .ok_or("should have report cert")?
            .clone();
        let cert = cert
            .replace("%20", " ")
            .replace("%0A", "\n")
            .replace("%2B", "+")
            .replace("%2F", "/")
            .replace("%3D", "=");
        let _avr: IasReportData = serde_json::from_slice(&response.body).map_err(debug)?;

        let sig = base64::decode(&sig)
            .map_err(|err| format!("decode sig fail: {}", err))?
            .into();

        let report = IasReport {
            raw: response.body.into(),
            sig,
            cert: cert.clone(),
        };
        Ok(report)
    }

    pub fn get_sigrl(&self, gid: &[u8; 4]) -> Result<Vec<u8>, String> {
        let mut gid_be = [0_u8; 4];
        gid_be.copy_from_slice(gid);
        gid_be.reverse();
        let gid_base16 = base16::encode_lower(&gid_be);
        let api_uri: Uri = format!("{}/attestation/v4/sigrl/{}", self.base_url, gid_base16)
            .parse()
            .map_err(debug)?;
        let api_key = self.api_key.clone();
        let mut req = HttpRequestBuilder::new_ex(api_uri, None, move |req| {
            req.header("Ocp-Apim-Subscription-Key", &api_key)
                .method(HttpMethod::Get);
        });
        let res = self.client.send(&mut req, self.timeout).map_err(debug)?;
        if !res.status.is_success() {
            if res.body.len() == 0 {
                return Err(format!("get_sigrl: {:?}", res.status));
            }
            return Err(String::from_utf8_lossy(&res.body).into());
        }
        Ok(base64::decode(&res.body).map_err(debug)?)
    }
}

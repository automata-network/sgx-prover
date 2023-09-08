use std::prelude::v1::*;

use base::time::Time;
use eth_types::{BlockHeader, HexBytes, SH160, SH256, SU64};
use net_http::{HttpClient, HttpConnError, HttpMethod, HttpRequestBuilder};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum BeaconClientError {
    HttpError(HttpConnError),
    OtherError(String),
    RemoteError(BeaconRemoteError),
    SerdeResponseError(serde_json::Error, String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BeaconRemoteError {
    pub code: u64,
    pub message: String,
}

#[derive(Clone, Copy)]
pub struct BeaconSlot {
    pub block_time: u64,
    pub genesis_time: u64,
}

impl BeaconSlot {
    pub fn new(block_time: u64, genesis_time: u64) -> Self {
        Self {
            block_time,
            genesis_time,
        }
    }

    pub fn current(&self) -> u64 {
        let now = base::time::now().as_secs();
        (now - self.genesis_time) / self.block_time
    }

    // pub fn instant(&self, slot: u64) -> Instant {
    //     base::time::instant(Duration::from_secs(self.secs(slot)))
    // }

    pub fn time(&self, slot: u64) -> Time {
        Time::from_secs(self.secs(slot))
    }

    pub fn secs(&self, slot: u64) -> u64 {
        self.genesis_time + self.block_time * slot
    }

    pub fn slot(&self, ts: u64) -> u64 {
        (ts - self.genesis_time) / self.block_time
    }

    pub fn duration(&self, slot: u64) -> Duration {
        Duration::from_secs(self.secs(slot))
    }

    pub fn next_block_time(&self, blk: &BlockHeader, blks: u64) -> Duration {
        Duration::from_secs(blk.timestamp.as_u64() + blks * self.block_time)
    }
}

pub struct BeaconClient {
    endpoint: String,
    client: HttpClient,
    timeout: Option<Duration>,
}

impl BeaconClient {
    pub fn new(endpoint: String, timeout: Option<Duration>) -> Self {
        let client = HttpClient::new();
        Self { endpoint, client, timeout }
    }

    pub fn get_head_header(&self) -> Result<BlockHeaderResponse, BeaconClientError> {
        self.rpc("/eth/v1/beacon/headers/head")
    }

    pub fn get_header(&self, header: u64) -> Result<BlockHeaderResponse, BeaconClientError> {
        self.rpc(format!("/eth/v1/beacon/headers/{}", header))
    }

    pub fn get_randao(&self, slot: u64) -> Result<RandaoResponse, BeaconClientError> {
        self.rpc(format!("/eth/v1/beacon/states/{}/randao", slot))
    }

    pub fn genesis(&self) -> Result<GenesisResponse, BeaconClientError> {
        self.rpc("/eth/v1/beacon/genesis")
    }

    pub fn withdrawal(&self, slot: u64) -> Result<WithdrawalResponse, BeaconClientError> {
        self.rpc(format!("/eth/v1/beacon/states/{}/withdrawals", slot))
    }

    fn rpc<T, P>(&self, path: P) -> Result<T, BeaconClientError>
    where
        T: for<'a> serde::Deserialize<'a>,
        P: AsRef<str>,
    {
        let start = Instant::now();
        let uri = format!("{}{}", self.endpoint, path.as_ref())
            .parse()
            .unwrap();
        let mut req = HttpRequestBuilder::new(HttpMethod::Get, uri, None);
        let response = self
            .client
            .send(&mut req, self.timeout)
            .map_err(|err| BeaconClientError::HttpError(err))?;

        if !response.status.is_success() {
            let err = match serde_json::from_slice(&response.body) {
                Ok(err) => err,
                Err(err) => return Err(BeaconClientError::OtherError(format!("{:?}", err))),
            };
            return Err(BeaconClientError::RemoteError(err));
        }

        let data = serde_json::from_slice(&response.body).map_err(|err| {
            BeaconClientError::SerdeResponseError(
                err,
                String::from_utf8_lossy(&response.body).into(),
            )
        })?;
        glog::debug!(exclude: "dry_run", target: "rpc_time", "Call {}: {:?}", path.as_ref(), start.elapsed());
        Ok(data)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub struct RandaoResponse {
    pub data: Randao,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub struct Randao {
    pub randao: SH256,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub struct WithdrawalResponse {
    pub data: WithdrawalList,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub struct WithdrawalList {
    pub withdrawals: Vec<Withdrawal>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub struct Withdrawal {
    pub index: SU64,
    pub validator_index: SU64,
    pub address: SH160,
    pub amount: SU64,
}

impl Withdrawal {
    pub fn to_standard(&self) -> eth_types::Withdrawal {
        eth_types::Withdrawal {
            index: self.index,
            validator_index: self.validator_index,
            address: self.address,
            amount: self.amount,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub struct GenesisResponse {
    pub data: Genesis,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub struct Genesis {
    // UTC time specified in the chain start event in the deposit contract.
    pub genesis_time: SU64,
    // 32 byte hash tree root of the genesis validator set.
    pub genesis_validators_root: SH256,
    // 4 byte genesis fork version.
    pub genesis_fork_version: HexBytes,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub struct BlockHeaderResponse {
    pub data: BlockHeaderContainer,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub struct BlockHeaderContainer {
    pub root: SH256,
    pub canonical: bool,
    pub header: BeaconBlockHeaderContainer,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub struct BeaconBlockHeaderContainer {
    pub message: BeaconBlockHeader,
    pub signature: HexBytes,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Eq, PartialEq)]
pub struct BeaconBlockHeader {
    pub slot: SU64,
    pub proposer_index: SU64,
    pub parent_root: SH256,
    pub state_root: SH256,
    pub body_root: SH256,
}

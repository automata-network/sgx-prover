use std::{borrow::Cow, sync::Arc};

use alloy::{
    eips::BlockId,
    primitives::{Address, Bytes, B256, U256},
    providers::{
        network::{Ethereum, EthereumWallet, TransactionBuilder},
        PendingTransactionBuilder, Provider, ProviderBuilder,
    },
    rpc::{
        client::{BatchRequest, RpcClientInner},
        json_rpc::{RpcParam, RpcReturn},
        types::{BlockTransactionsKind, Transaction, TransactionRequest},
    },
    signers::local::{LocalSignerError, PrivateKeySigner},
    sol_types::{SolCall, SolInterface},
    transports::{
        http::{Client, Http},
        RpcError, TransportErrorKind,
    },
};

base::stack_error! {
    #[derive(Debug)]
    name: EthError,
    stack_name: EthErrorStack,
    error: {},
    wrap: {
        Signer(LocalSignerError),
        Url(url::ParseError),
        Rpc(RpcError<TransportErrorKind>),
        Type(alloy::sol_types::Error),
    },
    stack: {
        OnTransact(contract: Address, sig: &'static str),
        OnCall(contract: Address, sig: &'static str),
        OnDecodeReturn(contract: Address, sig: &'static str, data: Bytes),
        BatchRequestSerFail(),
        BatchRequestDerRespFail(),
        BatchSend(),
    }
}

impl EthError {
    pub fn revert(&self) -> Option<Bytes> {
        match self.origin() {
            Self::Rpc(RpcError::ErrorResp(payload)) => payload.as_revert_data(),
            _ => None,
        }
    }

    pub fn revert_data<T: SolInterface>(self) -> Result<(T, EthError), EthError> {
        match self.origin() {
            Self::Rpc(RpcError::ErrorResp(payload)) => match payload.as_revert_data() {
                Some(data) => Ok((T::abi_decode(&data, true)?, self)),
                None => Err(self),
            },
            _ => Err(self),
        }
    }
}

#[derive(Clone)]
pub struct Eth {
    client: Arc<Box<dyn Provider<Http<Client>>>>,
}

impl Eth {
    pub fn dial(endpoint: &str, private_key: Option<&str>) -> Result<Eth, EthError> {
        let url = endpoint.try_into()?;

        let provider: Box<dyn Provider<Http<Client>>> = match private_key {
            Some(pk) => {
                let signer = pk.parse::<PrivateKeySigner>()?;
                let wallet = EthereumWallet::new(signer);
                let provider = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(wallet)
                    .on_http(url);
                Box::new(provider)
            }
            None => {
                let provider = ProviderBuilder::new().on_http(url);
                Box::new(provider)
            }
        };

        Ok(Eth {
            client: Arc::new(provider),
        })
    }

    pub async fn transact<T: SolCall>(
        &self,
        contract: Address,
        call: &T,
    ) -> Result<PendingTransactionBuilder<Http<Client>, Ethereum>, EthError> {
        let tx = TransactionRequest::default().with_call(call).to(contract);
        let result = self
            .client
            .send_transaction(tx)
            .await
            .map_err(EthError::OnTransact(&contract, &T::SIGNATURE))?;
        Ok(result)
    }

    pub async fn call<T: SolCall>(
        &self,
        contract: Address,
        call: &T,
    ) -> Result<T::Return, EthError> {
        let tx = TransactionRequest::default().with_call(call).to(contract);
        let result = self
            .client
            .call(&tx)
            .await
            .map_err(EthError::OnCall(&contract, &T::SIGNATURE))?;
        let result = T::abi_decode_returns(&result, true).map_err(EthError::OnDecodeReturn(
            &contract,
            &T::SIGNATURE,
            &result,
        ))?;
        Ok(result)
    }

    pub async fn select_reference_block(&self) -> Result<(U256, B256), EthError> {
        // corner case:
        //  1. block numbers may not sequential
        //  2. the types.Header.Hash() may not compatible with the chain
        let k = BlockTransactionsKind::Hashes;
        let p = self.provider();
        let head = p.get_block(BlockId::latest(), k).await?.unwrap();
        let hash = head.header.parent_hash;
        let reference_block = p.get_block(hash.into(), k).await?.unwrap();
        let number = reference_block.header.number.unwrap();
        Ok((U256::from_limbs_slice(&[number]), hash))
    }

    pub fn provider(&self) -> Arc<Box<dyn Provider<Http<Client>>>> {
        self.client.clone()
    }

    pub fn client(&self) -> &RpcClientInner<Http<Client>> {
        self.client.client()
    }

    pub async fn get_transaction(&self, hash: B256) -> Option<Transaction> {
        let tx = self.client.get_transaction_by_hash(hash).await.unwrap();
        tx
    }

    pub async fn batch_request<Params: RpcParam + std::fmt::Debug, Resp: RpcReturn>(
        &self,
        method: impl Into<Cow<'static, str>>,
        params: &[Params],
    ) -> Result<Vec<Resp>, EthError> {
        let method: Cow<'static, str> = method.into();
        let mut batch = BatchRequest::new(self.client());
        let mut waiters = Vec::new();
        for param in params {
            waiters.push((
                param,
                batch
                    .add_call::<_, Resp>(method.clone(), param)
                    .map_err(EthError::BatchRequestSerFail())?,
            ));
        }
        batch.send().await.map_err(EthError::BatchSend())?;
        let mut out = Vec::new();
        for (_params, waiter) in waiters {
            out.push(waiter.await.map_err(EthError::BatchRequestDerRespFail())?);
        }
        Ok(out)
    }
}

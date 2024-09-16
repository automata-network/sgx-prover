use eth_types::{
    types::Bloom as EBloom, AccessListItem as EAccessListItem, Bytes as EBytes, H160,
    H256 as EB256, H64, U256 as EU256, U64 as EU64,
};
use scroll_revm::primitives::{
    alloy_primitives::{Bloom as ABloom, B64, U64 as AU64},
    AccessListItem as AAccessListItem, Address, Bytes as ABytes, B256 as AB256, U256 as AU256,
};

pub trait EthPrimitivesConvert<T> {
    fn to(self) -> T;
}

impl<A, B> EthPrimitivesConvert<Option<B>> for Option<A>
where
    A: EthPrimitivesConvert<B>,
{
    fn to(self) -> Option<B> {
        Some(self?.to())
    }
}

impl<A, B> EthPrimitivesConvert<Vec<B>> for Vec<A>
where
    A: EthPrimitivesConvert<B>,
{
    fn to(self) -> Vec<B> {
        self.into_iter().map(|n| n.to()).collect()
    }
}

impl EthPrimitivesConvert<Address> for H160 {
    fn to(self) -> Address {
        Address::from_slice(&self.0)
    }
}

impl EthPrimitivesConvert<H160> for Address {
    fn to(self) -> H160 {
        H160::from_slice(self.as_slice())
    }
}

impl EthPrimitivesConvert<AU256> for EU256 {
    fn to(self) -> AU256 {
        AU256::from_limbs(self.0)
    }
}

impl EthPrimitivesConvert<EU256> for AU256 {
    fn to(self) -> EU256 {
        EU256(*self.as_limbs())
    }
}


impl EthPrimitivesConvert<AB256> for EB256 {
    fn to(self) -> AB256 {
        self.0.into()
    }
}

impl EthPrimitivesConvert<ABytes> for EBytes {
    fn to(self) -> ABytes {
        ABytes(self.0)
    }
}

impl EthPrimitivesConvert<B64> for H64 {
    fn to(self) -> B64 {
        self.0.into()
    }
}

impl EthPrimitivesConvert<ABloom> for EBloom {
    fn to(self) -> ABloom {
        ABloom::new(self.0)
    }
}

impl EthPrimitivesConvert<AU64> for EU64 {
    fn to(self) -> AU64 {
        AU64::from_limbs(self.0)
    }
}

impl EthPrimitivesConvert<AAccessListItem> for EAccessListItem {
    fn to(self) -> AAccessListItem {
        AAccessListItem {
            address: self.address.to(),
            storage_keys: self.storage_keys.into_iter().map(|n| n.to()).collect(),
        }
    }
}

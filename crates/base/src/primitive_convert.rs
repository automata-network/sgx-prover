use alloy::primitives::{Bytes, U256, U64};

pub trait PrimitivesConvert<T> {
    fn to(self) -> T;
}

impl<A, B> PrimitivesConvert<Option<B>> for Option<A>
where
    A: PrimitivesConvert<B>,
{
    fn to(self) -> Option<B> {
        Some(self?.to())
    }
}

impl PrimitivesConvert<U256> for usize {
    fn to(self) -> U256 {
        U256::from_be_slice(&self.to_be_bytes())
    }
}

impl PrimitivesConvert<U256> for u64 {
    fn to(self) -> U256 {
        U256::from_limbs_slice(&[self])
    }
}

impl PrimitivesConvert<U256> for u128 {
    fn to(self) -> U256 {
        U256::from_be_slice(&self.to_be_bytes())
    }
}

impl PrimitivesConvert<U64> for u64 {
    fn to(self) -> U64 {
        U64::from_limbs([self])
    }
}

impl PrimitivesConvert<Bytes> for Vec<u8> {
    fn to(self) -> Bytes {
        Bytes::from(self)
    }
}
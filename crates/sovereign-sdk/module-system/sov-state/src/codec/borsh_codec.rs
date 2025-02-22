use alloy_primitives::{Address as AlloyAddress, U256 as AlloyU256};
use borsh::BorshSerialize;
use sov_modules_core::{Address as ModuleAddress, EncodeKeyLike};

use super::{StateCodec, StateKeyCodec};
use crate::codec::StateValueCodec;

/// A [`StateCodec`] that uses [`borsh`] for all keys and values.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct BorshCodec;

impl StateKeyCodec<AlloyU256> for BorshCodec {
    fn encode_key(&self, value: &AlloyU256) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        BorshSerialize::serialize(value.as_limbs(), &mut buf).unwrap();
        buf
    }
}

impl StateKeyCodec<AlloyAddress> for BorshCodec {
    fn encode_key(&self, value: &AlloyAddress) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20);
        BorshSerialize::serialize(&value.0 .0, &mut buf).unwrap();
        buf
    }
}

impl StateKeyCodec<ModuleAddress> for BorshCodec {
    fn encode_key(&self, value: &ModuleAddress) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        BorshSerialize::serialize(&value, &mut buf).unwrap();
        buf
    }
}

impl StateValueCodec<AlloyU256> for BorshCodec {
    type Error = std::io::Error;

    fn encode_value(&self, value: &AlloyU256) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        BorshSerialize::serialize(value.as_limbs(), &mut buf).unwrap();
        buf
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<AlloyU256, Self::Error> {
        let s: [u64; 4] = borsh::from_slice(bytes)?;
        Ok(AlloyU256::from_limbs(s))
    }
}

// This one is needed for PublicKey only.
// FIXME: Remove before mainnet
impl StateKeyCodec<Vec<u8>> for BorshCodec {
    fn encode_key(&self, value: &Vec<u8>) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + value.len());
        BorshSerialize::serialize(value, &mut buf).unwrap();
        buf
    }
}
// FIXME: Remove before mainnet
impl EncodeKeyLike<[u8], Vec<u8>> for BorshCodec {
    fn encode_key_like(&self, borrowed: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + borrowed.len());
        BorshSerialize::serialize(borrowed, &mut buf).unwrap();
        buf
    }
}

impl StateValueCodec<Vec<u8>> for BorshCodec {
    type Error = std::io::Error;

    fn encode_value(&self, value: &Vec<u8>) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + value.len());
        BorshSerialize::serialize(value, &mut buf).unwrap();
        buf
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
        borsh::from_slice(bytes)
    }
}

macro_rules! impl_borsh_codec {
    ($t:tt) => {
        impl StateKeyCodec<$t> for BorshCodec {
            fn encode_key(&self, value: &$t) -> Vec<u8> {
                let mut buf = Vec::with_capacity(8);
                BorshSerialize::serialize(value, &mut buf).unwrap();
                buf
            }
        }

        impl StateValueCodec<$t> for BorshCodec {
            type Error = std::io::Error;

            fn encode_value(&self, value: &$t) -> Vec<u8> {
                let mut buf = Vec::with_capacity(8);
                BorshSerialize::serialize(value, &mut buf).unwrap();
                buf
            }

            fn try_decode_value(&self, bytes: &[u8]) -> Result<$t, Self::Error> {
                borsh::from_slice(bytes)
            }
        }
    };
}

impl_borsh_codec!(u8);
impl_borsh_codec!(i32);
impl_borsh_codec!(u32);
impl_borsh_codec!(u64);
impl_borsh_codec!(usize);
impl_borsh_codec!(String);

impl StateCodec for BorshCodec {
    type KeyCodec = Self;
    type ValueCodec = Self;

    fn key_codec(&self) -> &Self::KeyCodec {
        self
    }

    fn value_codec(&self) -> &Self::ValueCodec {
        self
    }
}

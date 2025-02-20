use alloy_primitives::{Address as AlloyAddress, U256 as AlloyU256};
use borsh::{BorshDeserialize, BorshSerialize};
use sov_modules_core::{Address as ModuleAddress, EncodeKeyLike};

use super::{StateCodec, StateKeyCodec};
use crate::codec::StateValueCodec;

/// A [`StateCodec`] that uses [`borsh`] for all keys and values.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct BorshCodec;

impl StateKeyCodec<AlloyU256> for BorshCodec {
    fn encode_key(&self, value: &AlloyU256) -> Vec<u8> {
        borsh::to_vec(value.as_limbs()).expect("Failed to serialize key")
    }
}

impl StateKeyCodec<AlloyAddress> for BorshCodec {
    fn encode_key(&self, value: &AlloyAddress) -> Vec<u8> {
        borsh::to_vec(&value.0 .0).expect("Failed to serialize key")
    }
}

impl StateKeyCodec<ModuleAddress> for BorshCodec {
    fn encode_key(&self, value: &ModuleAddress) -> Vec<u8> {
        borsh::to_vec(&value).expect("Failed to serialize key")
    }
}

impl StateValueCodec<AlloyU256> for BorshCodec {
    type Error = std::io::Error;

    fn encode_value(&self, value: &AlloyU256) -> Vec<u8> {
        let t = value.as_limbs();
        borsh::to_vec(t).unwrap()
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<AlloyU256, Self::Error> {
        let s: [u64; 4] = borsh::from_slice(bytes)?;
        Ok(AlloyU256::from_limbs(s))
    }
}

impl<T> StateKeyCodec<Vec<T>> for BorshCodec
where
    T: BorshSerialize,
{
    fn encode_key(&self, value: &Vec<T>) -> Vec<u8> {
        borsh::to_vec(value).expect("Failed to serialize key")
    }
}

impl<T> StateValueCodec<Vec<T>> for BorshCodec
where
    T: BorshSerialize + BorshDeserialize,
{
    type Error = std::io::Error;

    fn encode_value(&self, value: &Vec<T>) -> Vec<u8> {
        borsh::to_vec(value).expect("Failed to serialize value")
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<Vec<T>, Self::Error> {
        borsh::from_slice(bytes)
    }
}

macro_rules! impl_borsh_codec {
    ($t:tt) => {
        impl StateKeyCodec<$t> for BorshCodec {
            fn encode_key(&self, value: &$t) -> Vec<u8> {
                borsh::to_vec(value).expect("Failed to serialize key")
            }
        }

        impl StateValueCodec<$t> for BorshCodec {
            type Error = std::io::Error;

            fn encode_value(&self, value: &$t) -> Vec<u8> {
                borsh::to_vec(value).expect("Failed to serialize value")
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

// In borsh, a slice is encoded the same way as a vector except in edge case where
// T is zero-sized, in which case Vec<T> is not borsh encodable.
impl<T> EncodeKeyLike<[T], Vec<T>> for BorshCodec
where
    T: BorshSerialize,
{
    fn encode_key_like(&self, borrowed: &[T]) -> Vec<u8> {
        borsh::to_vec(borrowed).unwrap()
    }
}

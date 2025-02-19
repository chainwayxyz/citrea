use alloy_primitives::{Address as AlloyAddress, B256 as AlloyB256, U256 as AlloyU256};
use borsh::io::{Error, Read, Write};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_modules_core::{Address as ModuleAddress, EncodeKeyLike};

use super::{StateCodec, StateKeyCodec};
use crate::codec::StateValueCodec;

/// A [`StateCodec`] that uses [`borsh`] for all keys and values.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct BorshCodec;

impl StateKeyCodec<AlloyU256> for BorshCodec {
    fn encode_key(&self, value: &AlloyU256) -> Vec<u8> {
        borsh::to_vec(value.as_le_slice()).expect("Failed to serialize key")
    }
}

impl StateKeyCodec<AlloyAddress> for BorshCodec {
    fn encode_key(&self, value: &AlloyAddress) -> Vec<u8> {
        borsh::to_vec(value.as_slice()).expect("Failed to serialize key")
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
        let t = value.as_le_slice();
        borsh::to_vec(t).unwrap()
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<AlloyU256, Self::Error> {
        let s: [u8; 32] = borsh::from_slice(bytes)?;
        Ok(AlloyU256::from_le_bytes(s))
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
        borsh::to_vec(value).unwrap()
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

impl_borsh_codec!(usize);
impl_borsh_codec!(i32);
impl_borsh_codec!(u32);
impl_borsh_codec!(u64);
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

/// U256 wrapper to support borsh serde for alloy::U256
#[derive(
    Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Clone,
)]
#[repr(transparent)]
pub struct U256(
    #[borsh(serialize_with = "ser_u256", deserialize_with = "der_u256")]
    /// Original value
    AlloyU256,
);

impl From<AlloyU256> for U256 {
    fn from(value: AlloyU256) -> Self {
        Self(value)
    }
}

impl From<&AlloyU256> for U256 {
    fn from(value: &AlloyU256) -> Self {
        Self(*value)
    }
}

impl From<U256> for AlloyU256 {
    fn from(value: U256) -> Self {
        value.0
    }
}
/// Serialize U256
fn ser_u256<W: Write>(x: &AlloyU256, writer: &mut W) -> Result<(), Error> {
    let t = x.as_le_slice();
    BorshSerialize::serialize(&t, writer)
}

/// Deserialize U256
fn der_u256<R: Read>(reader: &mut R) -> Result<AlloyU256, Error> {
    let s: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
    Ok(AlloyU256::from_le_slice(&s))
}

/// B256 wrapper to support borsh serde for alloy::B256
#[derive(
    Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Clone,
)]
#[repr(transparent)]
pub struct B256(
    #[borsh(serialize_with = "ser_b256", deserialize_with = "der_b256")]
    /// Original value
    pub AlloyB256,
);

impl From<AlloyB256> for B256 {
    fn from(value: AlloyB256) -> Self {
        Self(value)
    }
}

impl From<B256> for AlloyB256 {
    fn from(value: B256) -> Self {
        value.0
    }
}

/// Serialize B256
fn ser_b256<W: Write>(x: &AlloyB256, writer: &mut W) -> Result<(), Error> {
    let t = x.as_slice();
    BorshSerialize::serialize(&t, writer)
}

/// Deserialize B256
fn der_b256<R: Read>(reader: &mut R) -> Result<AlloyB256, Error> {
    let s: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
    Ok(AlloyB256::from_slice(&s))
}

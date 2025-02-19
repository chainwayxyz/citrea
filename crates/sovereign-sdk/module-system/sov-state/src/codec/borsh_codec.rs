use core::ops::Deref;

use alloy_primitives::{Address as AddressOrig, B256 as B256Orig, U256 as U256Orig};
use borsh::io::{Error, Read, Write};
use borsh::{BorshDeserialize, BorshSerialize};
// use ruint::aliases::{B256 as B256Orig, U256 as U256Orig};
use serde::{Deserialize, Serialize};
use sov_modules_core::EncodeKeyLike;

use super::{StateCodec, StateKeyCodec};
use crate::codec::StateValueCodec;

/// A [`StateCodec`] that uses [`borsh`] for all keys and values.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct BorshCodec;

impl<K> StateKeyCodec<K> for BorshCodec
where
    K: BorshSerialize + BorshDeserialize,
{
    fn encode_key(&self, value: &K) -> Vec<u8> {
        borsh::to_vec(value).expect("Failed to serialize key")
    }
}

impl<V> StateValueCodec<V> for BorshCodec
where
    V: BorshSerialize + BorshDeserialize,
{
    type Error = std::io::Error;

    fn encode_value(&self, value: &V) -> Vec<u8> {
        borsh::to_vec(value).expect("Failed to serialize value")
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<V, Self::Error> {
        borsh::from_slice(bytes)
    }
}

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

impl EncodeKeyLike<AddressOrig, Address> for BorshCodec {
    fn encode_key_like(&self, borrowed: &AddressOrig) -> Vec<u8> {
        let t = borrowed.as_slice();
        borsh::to_vec(t).unwrap()
    }
}

impl EncodeKeyLike<U256Orig, U256> for BorshCodec {
    fn encode_key_like(&self, borrowed: &U256Orig) -> Vec<u8> {
        let t = borrowed.as_le_slice();
        borsh::to_vec(t).unwrap()
    }
}

/// Address wrapper to support borsh serde for alloy::Address
#[derive(
    Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Clone,
)]
#[repr(transparent)]
pub struct Address(
    #[borsh(serialize_with = "ser_address", deserialize_with = "der_address")]
    /// Original value
    AddressOrig,
);

/// Serialize Address
fn ser_address<W: Write>(x: &AddressOrig, writer: &mut W) -> Result<(), Error> {
    let t = x.as_slice();
    BorshSerialize::serialize(&t, writer)
}

/// Deserialize Address
fn der_address<R: Read>(reader: &mut R) -> Result<AddressOrig, Error> {
    let s: [u8; 20] = BorshDeserialize::deserialize_reader(reader)?;
    Ok(AddressOrig::from_slice(&s))
}

/// U256 wrapper to support borsh serde for alloy::U256
#[derive(
    Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Clone,
)]
#[repr(transparent)]
pub struct U256(
    #[borsh(serialize_with = "ser_u256", deserialize_with = "der_u256")]
    /// Original value
    U256Orig,
);

impl From<U256Orig> for U256 {
    fn from(value: U256Orig) -> Self {
        Self(value)
    }
}

impl From<&U256Orig> for U256 {
    fn from(value: &U256Orig) -> Self {
        Self(*value)
    }
}

impl From<U256> for U256Orig {
    fn from(value: U256) -> Self {
        value.0
    }
}

impl PartialEq<U256Orig> for U256 {
    fn eq(&self, other: &U256Orig) -> bool {
        self.0.eq(other)
    }
}

/// Serialize U256
fn ser_u256<W: Write>(x: &U256Orig, writer: &mut W) -> Result<(), Error> {
    let t = x.as_le_slice();
    BorshSerialize::serialize(&t, writer)
}

/// Deserialize U256
fn der_u256<R: Read>(reader: &mut R) -> Result<U256Orig, Error> {
    let s: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
    Ok(U256Orig::from_le_slice(&s))
}

/// B256 wrapper to support borsh serde for alloy::B256
#[derive(
    Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Clone,
)]
#[repr(transparent)]
pub struct B256(
    #[borsh(serialize_with = "ser_b256", deserialize_with = "der_b256")]
    /// Original value
    pub B256Orig,
);

impl From<B256Orig> for B256 {
    fn from(value: B256Orig) -> Self {
        Self(value)
    }
}

impl From<B256> for B256Orig {
    fn from(value: B256) -> Self {
        value.0
    }
}

impl PartialEq<B256Orig> for B256 {
    fn eq(&self, other: &B256Orig) -> bool {
        self.0.eq(other)
    }
}

impl PartialEq<B256> for B256Orig {
    fn eq(&self, other: &B256) -> bool {
        self.eq(&other.0)
    }
}

impl Deref for B256 {
    type Target = B256Orig;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Serialize B256
fn ser_b256<W: Write>(x: &B256Orig, writer: &mut W) -> Result<(), Error> {
    let t = x.as_slice();
    BorshSerialize::serialize(&t, writer)
}

/// Deserialize B256
fn der_b256<R: Read>(reader: &mut R) -> Result<B256Orig, Error> {
    let s: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
    Ok(B256Orig::from_slice(&s))
}

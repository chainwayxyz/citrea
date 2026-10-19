use std::borrow::Cow;

use alloy_primitives::{Address as AlloyAddress, B256 as AlloyB256, U256 as AlloyU256};
use borsh::BorshSerialize;
use sov_keys::default_signature::K256PublicKey;
use sov_modules_core::Address as ModuleAddress;

use super::{StateCodec, StateKeyCodec};
use crate::codec::StateValueCodec;

/// A [`StateCodec`] that uses [`borsh`] for all keys and values.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct BorshCodec;

impl StateKeyCodec<AlloyU256> for BorshCodec {
    fn encode_key<'k>(&self, key: &'k AlloyU256) -> Cow<'k, [u8]> {
        #[cfg(target_endian = "little")]
        return Cow::Borrowed(key.as_le_slice());

        #[cfg(target_endian = "big")]
        Cow::Owned(key.as_le_bytes().to_vec())
    }
}

impl StateKeyCodec<AlloyB256> for BorshCodec {
    fn encode_key<'k>(&self, key: &'k AlloyB256) -> Cow<'k, [u8]> {
        Cow::Borrowed(key.as_slice())
    }
}

impl StateKeyCodec<AlloyAddress> for BorshCodec {
    fn encode_key<'k>(&self, key: &'k AlloyAddress) -> Cow<'k, [u8]> {
        Cow::Borrowed(&key.0 .0)
    }
}

impl StateKeyCodec<ModuleAddress> for BorshCodec {
    fn encode_key<'k>(&self, key: &'k ModuleAddress) -> Cow<'k, [u8]> {
        Cow::Borrowed(key.as_ref())
    }
}

impl StateKeyCodec<K256PublicKey> for BorshCodec {
    fn encode_key<'k>(&self, key: &'k K256PublicKey) -> Cow<'k, [u8]> {
        Cow::Owned(borsh::to_vec(key).unwrap())
    }
}

impl StateValueCodec<ModuleAddress> for BorshCodec {
    type Error = std::io::Error;

    fn encode_value(&self, value: &ModuleAddress) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        BorshSerialize::serialize(value, &mut buf).unwrap();
        buf
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<ModuleAddress, Self::Error> {
        borsh::from_slice(bytes)
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

impl StateValueCodec<AlloyB256> for BorshCodec {
    type Error = std::io::Error;

    fn encode_value(&self, value: &AlloyB256) -> Vec<u8> {
        let mut buf = vec![0; 32];

        buf.copy_from_slice(value.as_slice());
        buf
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<AlloyB256, Self::Error> {
        // from slice panics if the length is not 32
        if bytes.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid B256 length",
            ));
        }

        Ok(AlloyB256::from_slice(bytes))
    }
}

impl StateValueCodec<K256PublicKey> for BorshCodec {
    type Error = std::io::Error;

    fn encode_value(&self, value: &K256PublicKey) -> Vec<u8> {
        borsh::to_vec(value).unwrap()
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<K256PublicKey, Self::Error> {
        borsh::from_slice(bytes)
    }
}

macro_rules! impl_borsh_codec {
    ($t:tt) => {
        impl StateKeyCodec<$t> for BorshCodec {
            fn encode_key<'k>(&self, key: &'k $t) -> Cow<'k, [u8]> {
                #[cfg(target_endian = "little")]
                {
                    use ::zerocopy::IntoBytes;
                    Cow::Borrowed(key.as_bytes())
                }

                #[cfg(target_endian = "big")]
                Cow::Owned(key.to_le_bytes().to_vec())
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

// This is for tests only
impl StateKeyCodec<String> for BorshCodec {
    fn encode_key<'k>(&self, key: &'k String) -> Cow<'k, [u8]> {
        let mut buf = Vec::with_capacity(4 + key.len());
        BorshSerialize::serialize(key, &mut buf).unwrap();
        Cow::Owned(buf)
    }
}

impl StateValueCodec<String> for BorshCodec {
    type Error = std::io::Error;

    fn encode_value(&self, value: &String) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + value.len());
        BorshSerialize::serialize(value, &mut buf).unwrap();
        buf
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<String, Self::Error> {
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

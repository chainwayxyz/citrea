use alloy_rlp::{Decodable, Encodable, Error};

use super::{StateCodec, StateKeyCodec};
use crate::codec::StateValueCodec;

/// A [`StateCodec`] that uses [`bcs`] for all keys and values.
#[derive(Debug, Default, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub struct RlpCodec;

impl<K> StateKeyCodec<K> for RlpCodec
where
    K: Encodable,
{
    fn encode_key(&self, key: &K) -> Vec<u8> {
        let mut buf = vec![];
        key.encode(&mut buf);
        buf
    }
}

impl<V> StateValueCodec<V> for RlpCodec
where
    V: Encodable + Decodable,
{
    type Error = Error;

    fn encode_value(&self, value: &V) -> Vec<u8> {
        let mut buf = vec![];
        value.encode(&mut buf);
        buf
    }

    fn try_decode_value(&self, mut bytes: &[u8]) -> Result<V, Self::Error> {
        <V as Decodable>::decode(&mut bytes)
    }
}

impl StateCodec for RlpCodec {
    type KeyCodec = Self;
    type ValueCodec = Self;

    fn key_codec(&self) -> &Self::KeyCodec {
        self
    }

    fn value_codec(&self) -> &Self::ValueCodec {
        self
    }
}

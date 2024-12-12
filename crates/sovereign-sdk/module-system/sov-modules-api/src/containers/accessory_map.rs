use std::marker::PhantomData;

use sov_modules_core::{AccessoryWorkingSet, Prefix, StateCodec, StateKeyCodec, StateValueCodec};
use sov_state::codec::BorshCodec;
use sov_state::Storage;

use super::traits::StateMapAccessor;

/// A container that maps keys to values stored as "accessory" state, outside of
/// the JMT.
///
/// # Type parameters
/// [`AccessoryStateMap`] is generic over:
/// - a key type `K`;
/// - a value type `V`;
/// - a [`StateValueCodec`] `Codec`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    borsh::BorshDeserialize,
    borsh::BorshSerialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct AccessoryStateMap<K, V, Codec = BorshCodec> {
    _phantom: (PhantomData<K>, PhantomData<V>),
    codec: Codec,
    prefix: Prefix,
}

impl<K, V> AccessoryStateMap<K, V> {
    /// Creates a new [`AccessoryStateMap`] with the given prefix and the default
    /// [`StateValueCodec`] (i.e. [`BorshCodec`]).
    pub fn new(prefix: Prefix) -> Self {
        Self::with_codec(prefix, BorshCodec)
    }
}

impl<K, V, Codec> AccessoryStateMap<K, V, Codec> {
    /// Creates a new [`AccessoryStateMap`] with the given prefix and [`StateValueCodec`].
    pub fn with_codec(prefix: Prefix, codec: Codec) -> Self {
        Self {
            _phantom: (PhantomData, PhantomData),
            codec,
            prefix,
        }
    }

    /// Returns the prefix used when this [`AccessoryStateMap`] was created.
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }
}

impl<'a, K, V, Codec, S> StateMapAccessor<K, V, Codec, AccessoryWorkingSet<'a, S>>
    for AccessoryStateMap<K, V, Codec>
where
    Codec: StateCodec,
    Codec::KeyCodec: StateKeyCodec<K>,
    Codec::ValueCodec: StateValueCodec<V>,
    S: Storage,
{
    /// Returns the prefix used when this [`AccessoryStateMap`] was created.
    fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    fn codec(&self) -> &Codec {
        &self.codec
    }
}

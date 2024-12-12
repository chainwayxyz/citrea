use std::marker::PhantomData;

use sov_modules_core::{Prefix, StateCodec, StateKeyCodec, StateValueCodec, WorkingSet};
use sov_state::codec::BorshCodec;
use sov_state::Storage;

use super::traits::StateMapAccessor;
/// A container that maps keys to values.
///
/// # Type parameters
/// [`StateMap`] is generic over:
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
pub struct StateMap<K, V, Codec = BorshCodec> {
    _phantom: (PhantomData<K>, PhantomData<V>),
    codec: Codec,
    prefix: Prefix,
}

impl<K, V> StateMap<K, V> {
    /// Creates a new [`StateMap`] with the given prefix and the default
    /// [`StateValueCodec`] (i.e. [`BorshCodec`]).
    pub fn new(prefix: Prefix) -> Self {
        Self::with_codec(prefix, BorshCodec)
    }
}

impl<K, V, Codec> StateMap<K, V, Codec> {
    /// Creates a new [`StateMap`] with the given prefix and [`StateValueCodec`].
    pub fn with_codec(prefix: Prefix, codec: Codec) -> Self {
        Self {
            _phantom: (PhantomData, PhantomData),
            codec,
            prefix,
        }
    }

    /// Returns a reference to the codec used by this [`StateMap`].
    pub fn codec(&self) -> &Codec {
        &self.codec
    }

    /// Returns the prefix used when this [`StateMap`] was created.
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }
}

impl<K, V, Codec, S: Storage> StateMapAccessor<K, V, Codec, WorkingSet<S>> for StateMap<K, V, Codec>
where
    Codec: StateCodec,
    Codec::KeyCodec: StateKeyCodec<K>,
    Codec::ValueCodec: StateValueCodec<V>,
{
    /// Returns a reference to the codec used by this [`StateMap`].
    fn codec(&self) -> &Codec {
        &self.codec
    }

    /// Returns the prefix used when this [`StateMap`] was created.
    fn prefix(&self) -> &Prefix {
        &self.prefix
    }
}

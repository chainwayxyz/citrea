use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use sov_modules_core::{Context, OffchainWorkingSet, Prefix, StateCodec, StateValueCodec};
use sov_state::codec::BorshCodec;

use crate::StateValueAccessor;

/// Container for a single value stored as "accessory" state, outside of the
/// JMT.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    BorshDeserialize,
    BorshSerialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct OffchainStateValue<V, Codec = BorshCodec> {
    _phantom: PhantomData<V>,
    codec: Codec,
    prefix: Prefix,
}

impl<V> OffchainStateValue<V> {
    /// Crates a new [`OffchainStateValue`] with the given prefix and the default
    /// [`StateValueCodec`] (i.e. [`BorshCodec`]).
    pub fn new(prefix: Prefix) -> Self {
        Self::with_codec(prefix, BorshCodec)
    }
}

impl<V, Codec> OffchainStateValue<V, Codec> {
    /// Creates a new [`OffchainStateValue`] with the given prefix and codec.
    pub fn with_codec(prefix: Prefix, codec: Codec) -> Self {
        Self {
            _phantom: PhantomData,
            codec,
            prefix,
        }
    }

    /// Returns the prefix used when this [`OffchainStateValue`] was created.
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }
}

impl<'a, V, Codec, C: Context> StateValueAccessor<V, Codec, OffchainWorkingSet<'a, C>>
    for OffchainStateValue<V, Codec>
where
    Codec: StateCodec,
    Codec::ValueCodec: StateValueCodec<V>,
{
    fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    fn codec(&self) -> &Codec {
        &self.codec
    }
}

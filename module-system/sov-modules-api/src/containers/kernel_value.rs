use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use sov_modules_core::{
    Context, KernelWorkingSet, Prefix, StateCodec, StateKeyCodec, StateReaderAndWriter,
    StateValueCodec, VersionedWorkingSet,
};
use sov_state::codec::BorshCodec;

/// A `versioned` value stored in kernel state. The semantics of this type are different
/// depending on the priveleges of the accessor. For a standard ("user space") interaction
/// via a `VersionedWorkingSet`, only one version of this value is accessible. Inside the kernel,
/// (where access is mediated by a `KernelWorkingSet`), all versions of this value are accessible.
///
/// Under the hood, a versioned value is implemented as a map from a slot number to a value. From the kernel, any
/// value can be accessed using the `StateMapAccessor` trait with the slot number as the key. For convenience,
/// the value can also be accessed using the `StateValueAccessor` trait, which will interact with the value for the current
/// slot number.
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
pub struct KernelStateValue<V, Codec = BorshCodec> {
    _phantom: PhantomData<V>,
    codec: Codec,
    prefix: Prefix,
}

impl<V> KernelStateValue<V> {
    /// Crates a new [`KernelStateValue`] with the given prefix and the default
    /// [`StateValueCodec`] (i.e. [`BorshCodec`]).
    pub fn new(prefix: Prefix) -> Self {
        Self::with_codec(prefix, BorshCodec)
    }
}

impl<V, Codec> KernelStateValue<V, Codec> {
    /// Creates a new [`KernelStateValue`] with the given prefix and codec.
    pub fn with_codec(prefix: Prefix, codec: Codec) -> Self {
        Self {
            _phantom: PhantomData,
            codec,
            prefix,
        }
    }

    /// Returns the prefix used when this [`KernelStateValue`] was created.
    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }
}

mod as_user_value {
    use super::*;
    use crate::StateValueAccessor;

    impl<'a, V, Codec, C: Context> StateValueAccessor<V, Codec, VersionedWorkingSet<'a, C>>
        for KernelStateValue<V, Codec>
    where
        Codec: StateCodec,
        Codec::ValueCodec: StateValueCodec<V>,
        Codec::KeyCodec: StateKeyCodec<u64>,
    {
        fn prefix(&self) -> &Prefix {
            &self.prefix
        }

        fn codec(&self) -> &Codec {
            &self.codec
        }

        fn set(&self, value: &V, working_set: &mut VersionedWorkingSet<'a, C>) {
            working_set.set_value(
                self.prefix(),
                &working_set.slot_num(),
                value,
                StateValueAccessor::<V, Codec, VersionedWorkingSet<'a, C>>::codec(self),
            );
        }

        fn get(&self, working_set: &mut VersionedWorkingSet<'a, C>) -> Option<V> {
            working_set.get_value(
                self.prefix(),
                &working_set.slot_num(),
                StateValueAccessor::<V, Codec, VersionedWorkingSet<'a, C>>::codec(self),
            )
        }

        fn get_or_err(
            &self,
            working_set: &mut VersionedWorkingSet<'a, C>,
        ) -> Result<V, crate::StateValueError> {
            self.get(working_set)
                .ok_or_else(|| crate::StateValueError::MissingValue(self.prefix().clone()))
        }

        fn remove(&self, working_set: &mut VersionedWorkingSet<'a, C>) -> Option<V> {
            working_set.remove_value(
                self.prefix(),
                &working_set.slot_num(),
                StateValueAccessor::<V, Codec, VersionedWorkingSet<'a, C>>::codec(self),
            )
        }

        fn remove_or_err(
            &self,
            working_set: &mut VersionedWorkingSet<'a, C>,
        ) -> Result<V, crate::StateValueError> {
            self.remove(working_set)
                .ok_or_else(|| crate::StateValueError::MissingValue(self.prefix().clone()))
        }

        fn delete(&self, working_set: &mut VersionedWorkingSet<'a, C>) {
            working_set.delete_value(
                self.prefix(),
                &working_set.slot_num(),
                StateValueAccessor::<V, Codec, VersionedWorkingSet<'a, C>>::codec(self),
            );
        }
    }
}

mod as_kernel_value {
    use super::*;
    use crate::StateValueAccessor;

    impl<'a, V, Codec, C: Context> StateValueAccessor<V, Codec, KernelWorkingSet<'a, C>>
        for KernelStateValue<V, Codec>
    where
        Codec: StateCodec,
        Codec::ValueCodec: StateValueCodec<V>,
        Codec::KeyCodec: StateKeyCodec<u64>,
    {
        fn prefix(&self) -> &Prefix {
            &self.prefix
        }

        fn codec(&self) -> &Codec {
            &self.codec
        }

        fn set(&self, value: &V, working_set: &mut KernelWorkingSet<'a, C>) {
            working_set.set_value(
                self.prefix(),
                &working_set.current_slot(),
                value,
                StateValueAccessor::<V, Codec, VersionedWorkingSet<'a, C>>::codec(self),
            );
        }

        fn get(&self, working_set: &mut KernelWorkingSet<'a, C>) -> Option<V> {
            working_set.get_value(
                self.prefix(),
                &working_set.current_slot(),
                StateValueAccessor::<V, Codec, KernelWorkingSet<'a, C>>::codec(self),
            )
        }

        fn get_or_err(
            &self,
            working_set: &mut KernelWorkingSet<'a, C>,
        ) -> Result<V, crate::StateValueError> {
            self.get(working_set)
                .ok_or_else(|| crate::StateValueError::MissingValue(self.prefix().clone()))
        }

        fn remove(&self, working_set: &mut KernelWorkingSet<'a, C>) -> Option<V> {
            working_set.remove_value(
                self.prefix(),
                &working_set.current_slot(),
                StateValueAccessor::<V, Codec, KernelWorkingSet<'a, C>>::codec(self),
            )
        }

        fn remove_or_err(
            &self,
            working_set: &mut KernelWorkingSet<'a, C>,
        ) -> Result<V, crate::StateValueError> {
            self.remove(working_set)
                .ok_or_else(|| crate::StateValueError::MissingValue(self.prefix().clone()))
        }

        fn delete(&self, working_set: &mut KernelWorkingSet<'a, C>) {
            working_set.delete_value(
                self.prefix(),
                &working_set.current_slot(),
                StateValueAccessor::<V, Codec, KernelWorkingSet<'a, C>>::codec(self),
            );
        }
    }
}

mod as_kernel_map {
    use super::*;
    use crate::StateMapAccessor;
    impl<'a, V, Codec, C: Context> StateMapAccessor<u64, V, Codec, KernelWorkingSet<'a, C>>
        for KernelStateValue<V, Codec>
    where
        Codec: StateCodec,
        Codec::ValueCodec: StateValueCodec<V>,
        Codec::KeyCodec: StateKeyCodec<u64>,
    {
        fn prefix(&self) -> &Prefix {
            &self.prefix
        }

        fn codec(&self) -> &Codec {
            &self.codec
        }

        fn set<Q>(&self, key: &Q, value: &V, working_set: &mut KernelWorkingSet<'a, C>)
        where
            <Codec as StateCodec>::KeyCodec: sov_modules_core::EncodeKeyLike<Q, u64>,
            Q: ?Sized,
        {
            working_set.set_value(
                self.prefix(),
                key,
                value,
                StateMapAccessor::<u64, V, Codec, KernelWorkingSet<'a, C>>::codec(self),
            )
        }

        fn get<Q>(&self, key: &Q, working_set: &mut KernelWorkingSet<'a, C>) -> Option<V>
        where
            Codec: StateCodec,
            <Codec as StateCodec>::KeyCodec: sov_modules_core::EncodeKeyLike<Q, u64>,
            <Codec as StateCodec>::ValueCodec: StateValueCodec<V>,
            Q: ?Sized,
        {
            working_set.get_value(
                self.prefix(),
                key,
                StateMapAccessor::<u64, V, Codec, KernelWorkingSet<'a, C>>::codec(self),
            )
        }

        fn get_or_err<Q>(
            &self,
            key: &Q,
            working_set: &mut KernelWorkingSet<'a, C>,
        ) -> Result<V, crate::StateMapError>
        where
            Codec: StateCodec,
            <Codec as StateCodec>::KeyCodec: sov_modules_core::EncodeKeyLike<Q, u64>,
            <Codec as StateCodec>::ValueCodec: StateValueCodec<V>,
            Q: ?Sized,
        {
            self.get(key, working_set).ok_or_else(|| {
                crate::StateMapError::MissingValue(
                    self.prefix().clone(),
                    sov_modules_core::StorageKey::new(
                        self.prefix(),
                        key,
                        StateMapAccessor::<u64, V, Codec, KernelWorkingSet<'a, C>>::codec(self)
                            .key_codec(),
                    ),
                )
            })
        }

        fn remove<Q>(&self, key: &Q, working_set: &mut KernelWorkingSet<'a, C>) -> Option<V>
        where
            Codec: StateCodec,
            <Codec as StateCodec>::KeyCodec: sov_modules_core::EncodeKeyLike<Q, u64>,
            <Codec as StateCodec>::ValueCodec: StateValueCodec<V>,
            Q: ?Sized,
        {
            working_set.remove_value(
                self.prefix(),
                key,
                StateMapAccessor::<u64, V, Codec, KernelWorkingSet<'a, C>>::codec(self),
            )
        }

        fn remove_or_err<Q>(
            &self,
            key: &Q,
            working_set: &mut KernelWorkingSet<'a, C>,
        ) -> Result<V, crate::StateMapError>
        where
            Codec: StateCodec,
            <Codec as StateCodec>::KeyCodec: sov_modules_core::EncodeKeyLike<Q, u64>,
            <Codec as StateCodec>::ValueCodec: StateValueCodec<V>,
            Q: ?Sized,
        {
            self.remove(key, working_set).ok_or_else(|| {
                crate::StateMapError::MissingValue(
                    self.prefix().clone(),
                    sov_modules_core::StorageKey::new(
                        self.prefix(),
                        key,
                        StateMapAccessor::<u64, V, Codec, KernelWorkingSet<'a, C>>::codec(self)
                            .key_codec(),
                    ),
                )
            })
        }

        fn delete<Q>(&self, key: &Q, working_set: &mut KernelWorkingSet<'a, C>)
        where
            Codec: StateCodec,
            <Codec as StateCodec>::KeyCodec: sov_modules_core::EncodeKeyLike<Q, u64>,
            Q: ?Sized,
        {
            working_set.delete_value(
                self.prefix(),
                key,
                StateMapAccessor::<u64, V, Codec, KernelWorkingSet<'a, C>>::codec(self),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use sov_mock_da::MockDaSpec;
    use sov_modules_core::capabilities::mocks::MockKernel;
    use sov_modules_core::{Address, Context, KernelWorkingSet, Prefix, WorkingSet};
    use sov_state::{DefaultStorageSpec, ProverStorage};

    use crate::default_context::DefaultContext;
    use crate::KernelStateValue;
    #[test]
    fn test_kernel_state_value_as_value() {
        use crate::StateValueAccessor;
        let tmpdir = tempfile::tempdir().unwrap();
        let storage = ProverStorage::<DefaultStorageSpec>::with_path(tmpdir.path()).unwrap();
        let mut working_set: WorkingSet<DefaultContext> = WorkingSet::new(storage);

        let prefix = Prefix::new(b"test".to_vec());
        let value = KernelStateValue::<u64>::new(prefix.clone());

        // Initialize a value in the kernel state during slot 4
        {
            let kernel = MockKernel::<DefaultContext, MockDaSpec>::new(4, 1);
            let mut kernel_state = KernelWorkingSet::from_kernel(&kernel, &mut working_set);
            value.set(&100, &mut kernel_state);
            assert_eq!(value.get(&mut kernel_state), Some(100));
        }

        {
            {
                let mut versioned_state =
                    working_set.versioned_state(&DefaultContext::new(Address::from([1; 32]), 1));
                // Try to read the value from user space with the slot number set to 1. Should fail.
                assert_eq!(value.get(&mut versioned_state), None);
            }
            // Try to read the value from user space with the slot number set to 4. Should succeed.
            let mut versioned_state =
                working_set.versioned_state(&DefaultContext::new(Address::from([1; 32]), 4));
            // Try to read the value from user space with the slot number set to 1. Should fail.
            assert_eq!(value.get(&mut versioned_state), Some(100));
        }
    }

    #[test]
    fn test_kernel_state_value_as_map() {
        let tmpdir = tempfile::tempdir().unwrap();
        let storage = ProverStorage::<DefaultStorageSpec>::with_path(tmpdir.path()).unwrap();
        let mut working_set: WorkingSet<DefaultContext> = WorkingSet::new(storage);

        let prefix = Prefix::new(b"test".to_vec());
        let value = KernelStateValue::<u64>::new(prefix.clone());
        let kernel = MockKernel::<DefaultContext, MockDaSpec>::new(4, 1);

        // Initialize a versioned value in the kernel state to be available starting at slot 2
        {
            use crate::StateMapAccessor;
            let mut kernel_state = KernelWorkingSet::from_kernel(&kernel, &mut working_set);
            value.set(&2, &100, &mut kernel_state);
            assert_eq!(value.get(&2, &mut kernel_state), Some(100));
        }

        {
            use crate::StateValueAccessor;
            {
                let mut versioned_state =
                    working_set.versioned_state(&DefaultContext::new(Address::from([1; 32]), 1));
                // Try to read the value from user space with the slot number set to 1. Should fail.
                assert_eq!(value.get(&mut versioned_state), None);
            }
            // Try to read the value from user space with the slot number set to 2. Should succeed.
            let mut versioned_state =
                working_set.versioned_state(&DefaultContext::new(Address::from([1; 32]), 2));

            assert_eq!(value.get(&mut versioned_state), Some(100));
        }
    }
}

//! Trait that represents life time of the state
//!

use crate::da::DaSpec;

/// Storage manager persistence and allows to work on state
/// Temporal placeholder for ForkManager
pub trait StorageManager {
    /// Type that can be consumed by `[crate::state_machine::stf::StateTransitionFunction]` in native context
    type NativeStorage;
    /// Type that is produced by `[crate::state_machine::stf::StateTransitionFunction]`
    type NativeChangeSet;

    /// Get latest native state
    fn get_native_storage(&self) -> Self::NativeStorage;
}

/// Storage manager, that supports tree-like hierarchy of snapshots
/// So different rollup state can be mapped to DA state 1 to 1, including chain forks.
pub trait HierarchicalStorageManager<Da: DaSpec> {
    /// Type that can be consumed by `[crate::state_machine::stf::StateTransitionFunction]` in native context.
    type NativeStorage;
    /// Type that is produced by `[crate::state_machine::stf::StateTransitionFunction]`.
    type NativeChangeSet;

    /// Creates storage based on given Da block header,
    /// meaning that at will have access to previous blocks state in same fork.
    fn get_native_storage_on(
        &mut self,
        block_header: &Da::BlockHeader,
    ) -> anyhow::Result<Self::NativeStorage>;

    /// Adds [`Self::NativeChangeSet`] to the storage.
    /// [`DaSpec::BlockHeader`] must be provided for efficient consistency checking.
    fn save_change_set(
        &mut self,
        block_header: &Da::BlockHeader,
        change_set: Self::NativeChangeSet,
    ) -> anyhow::Result<()>;

    /// Finalizes snapshot on given block header
    fn finalize(&mut self, block_header: &Da::BlockHeader) -> anyhow::Result<()>;
}

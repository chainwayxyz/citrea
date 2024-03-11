//! Trait that represents life time of the state
//!

use crate::da::DaSpec;

/// Storage manager, that supports tree-like hierarchy of snapshots
/// So different rollup state can be mapped to DA state 1 to 1, including chain forks.
pub trait HierarchicalStorageManager<Da: DaSpec> {
    /// Type that can be consumed by `[crate::state_machine::stf::StateTransitionFunction]` in native context.
    type NativeStorage: Clone;
    /// Type that is produced by `[crate::state_machine::stf::StateTransitionFunction]`.
    type NativeChangeSet;

    /// Creates storage based on given l2 block height,
    fn create_storage_on_l2_height(
        &mut self,
        l2_block_height: u64,
    ) -> anyhow::Result<Self::NativeStorage>;

    /// Finalizes snapshot on given l2 block height
    fn finalize_l2(&mut self, l2_block_height: u64) -> anyhow::Result<()>;

    /// Adds [`Self::NativeChangeSet`] to the storage.
    fn save_change_set_l2(
        &mut self,
        l2_block_height: u64,
        change_set: Self::NativeChangeSet,
    ) -> anyhow::Result<()>;

    /// Creates storage based on given Da block header,
    /// meaning that at will have access to previous blocks state in same fork.
    fn create_storage_on(
        &mut self,
        block_header: &Da::BlockHeader,
    ) -> anyhow::Result<Self::NativeStorage>;

    /// Snapshots that points directly to finalized storage.
    /// Won't be saved if somehow 'saved'
    fn create_finalized_storage(&mut self) -> anyhow::Result<Self::NativeStorage>;

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

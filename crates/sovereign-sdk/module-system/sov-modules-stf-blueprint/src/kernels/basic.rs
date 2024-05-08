//! The basic kernel provides censorship resistance by processing all blobs immediately in the order they appear on DA
use std::path::PathBuf;

use sov_blob_storage::BlobStorage;
use sov_modules_api::runtime::capabilities::{
    BlobRefOrOwned, BlobSelector, Kernel, KernelSlotHooks,
};
use sov_modules_api::{Context, DaSpec, WorkingSet};
use sov_state::Storage;

/// The simplest imaginable kernel. It does not do any batching or reordering of blobs.
pub struct BasicKernel<C: Context, Da: DaSpec> {
    phantom: std::marker::PhantomData<C>,
    blob_storage: BlobStorage<C, Da>,
}

impl<C: Context, Da: DaSpec> Default for BasicKernel<C, Da> {
    fn default() -> Self {
        Self {
            phantom: std::marker::PhantomData,
            blob_storage: Default::default(),
        }
    }
}

/// Path information required to initialize a basic kernel from files
pub struct BasicKernelGenesisPaths {
    /// The path to the chain_state genesis config
    pub chain_state: PathBuf,
}

/// The genesis configuration for the basic kernel
pub struct BasicKernelGenesisConfig<C: Context, Da: DaSpec> {
    _phantom: core::marker::PhantomData<fn() -> (C, Da)>,
}

impl<C: Context, Da: DaSpec> Default for BasicKernelGenesisConfig<C, Da> {
    fn default() -> Self {
        BasicKernelGenesisConfig {
            _phantom: Default::default(),
        }
    }
}

impl<C: Context, Da: DaSpec> Kernel<C, Da> for BasicKernel<C, Da> {
    fn true_height(&self, _working_set: &mut WorkingSet<C>) -> u64 {
        0
    }
    fn visible_height(&self, _working_set: &mut WorkingSet<C>) -> u64 {
        0
    }

    type GenesisConfig = BasicKernelGenesisConfig<C, Da>;

    #[cfg(feature = "native")]
    type GenesisPaths = BasicKernelGenesisPaths;

    fn genesis(
        &self,
        _config: &Self::GenesisConfig,
        _working_set: &mut WorkingSet<C>,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

impl<C: Context, Da: DaSpec> BlobSelector<Da> for BasicKernel<C, Da> {
    type Context = C;

    fn get_blobs_for_this_slot<'a, 'k, I>(
        &self,
        current_blobs: I,
        _working_set: &mut sov_modules_api::KernelWorkingSet<'k, Self::Context>,
    ) -> anyhow::Result<Vec<BlobRefOrOwned<'a, Da::BlobTransaction>>>
    where
        I: IntoIterator<Item = &'a mut Da::BlobTransaction>,
    {
        self.blob_storage
            .get_blobs_for_this_slot(current_blobs, _working_set)
    }
}

impl<C: Context, Da: DaSpec> KernelSlotHooks<C, Da> for BasicKernel<C, Da> {
    fn begin_slot_hook(
        &self,
        _slot_header: &<Da as DaSpec>::BlockHeader,
        _validity_condition: &<Da as DaSpec>::ValidityCondition,
        _pre_state_root: &<<Self::Context as sov_modules_api::Spec>::Storage as Storage>::Root,
        _working_set: &mut sov_modules_api::WorkingSet<Self::Context>,
    ) {
    }

    fn end_slot_hook(&self, _working_set: &mut sov_modules_api::WorkingSet<Self::Context>) {}
}

use serde::{Deserialize, Serialize};
use sov_modules_api::{Context, DaSpec, StateValueAccessor, WorkingSet};

use crate::SoftConfirmationRuleEnforcer;

/// Config for the SoftConfirmationRuleEnforcer module.
/// Sets max L2 blocks per L1 and authority.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SoftConfirmationRuleEnforcerConfig<C: Context> {
    /// Authority address. Address of the sequencer.
    /// This address is allowed to modify the max L2 blocks per L1.
    pub(crate) authority: C::Address,
    ///  Maximum number of L2 blocks per L1 slot.
    pub(crate) max_l2_blocks_per_l1: u64,
}

impl<C: Context, Da: DaSpec> SoftConfirmationRuleEnforcer<C, Da> {
    pub(crate) fn init_module(
        &self,
        config: &<Self as sov_modules_api::Module>::Config,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        self.authority.set(&config.authority, working_set);
        self.max_l2_blocks_per_l1
            .set(&config.max_l2_blocks_per_l1, working_set);
        Ok(())
    }
}

use serde::{Deserialize, Serialize};
use sov_modules_api::{Context, DaSpec, StateValueAccessor, WorkingSet};

use crate::SoftConfirmationRuleEnforcer;

/// Config for the SoftConfirmationRuleEnforcer module.
/// Sets limiting number and authority.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SoftConfirmationRuleEnforcerConfig<C: Context> {
    /// Authority address. Address of the sequencer.
    /// This address is allowed to modify the limiting number.
    pub(crate) authority: C::Address,
    ///  Maximum number of L2 blocks per L1 slot.
    pub(crate) limiting_number: u64,
}

impl<C: Context, Da: DaSpec> SoftConfirmationRuleEnforcer<C, Da> {
    pub(crate) fn init_module(
        &self,
        config: &<Self as sov_modules_api::Module>::Config,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        self.authority.set(&config.authority, working_set);
        self.limiting_number
            .set(&config.limiting_number, working_set);
        Ok(())
    }
}

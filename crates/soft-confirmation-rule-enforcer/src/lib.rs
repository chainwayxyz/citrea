mod call;
mod genesis;
mod hooks;
pub use call::*;
pub use genesis::*;

#[cfg(feature = "native")]
mod query;
#[cfg(feature = "native")]
pub use query::*;

#[cfg(all(test, feature = "native"))]
mod tests;

// "Given DA slot hasn't been used for more than N soft confirmation blocks."
use sov_modules_api::{Context, DaSpec, ModuleInfo, StateMap, StateValue, WorkingSet};
use sov_state::codec::BcsCodec;

#[derive(ModuleInfo, Clone)]
pub struct SoftConfirmationRuleEnforcer<C: Context, Da: DaSpec> {
    /// Address of the SoftConfirmationRuleEnforcer module.
    #[address]
    address: C::Address,
    ///  Maximum number of L2 blocks per L1 slot.
    #[state]
    pub(crate) max_l2_blocks_per_l1: StateValue<u64, BcsCodec>,
    /// Mapping from DA root hash to a number.
    /// Checks how many L1 blocks were published for a specific L1 block with given DA root hash.
    #[state]
    pub(crate) da_root_hash_to_number: StateMap<[u8; 32], u64, BcsCodec>,
    /// Authority address. Address of the sequencer.
    /// This address is allowed to modify the max L2 blocks per L1.
    #[state]
    pub(crate) authority: StateValue<C::Address, BcsCodec>,
    /// Sequencer's block timestamp
    #[state]
    pub(crate) last_timestamp: StateValue<u64, BcsCodec>,
    /// Phantom state using the da type.
    /// This is used to make sure that the state is generic over the DA type.
    #[allow(dead_code)]
    #[state]
    pub(crate) phantom: StateValue<Da::SlotHash, BcsCodec>,
}

impl<C: Context, Da: DaSpec> sov_modules_api::Module for SoftConfirmationRuleEnforcer<C, Da> {
    type Context = C;

    type Config = SoftConfirmationRuleEnforcerConfig<C>;

    type CallMessage = CallMessage<C>;

    type Event = ();

    fn call(
        &self,
        message: Self::CallMessage,
        context: &Self::Context,
        working_set: &mut WorkingSet<Self::Context>,
    ) -> Result<sov_modules_api::CallResponse, sov_modules_api::Error> {
        match message {
            CallMessage::ChangeAuthority { new_authority } => {
                Ok(self.change_authority(new_authority, context, working_set)?)
            }
            CallMessage::ModifyMaxL2BlocksPerL1 {
                max_l2_blocks_per_l1,
            } => {
                Ok(self.modify_max_l2_blocks_per_l1(max_l2_blocks_per_l1, context, working_set)?)
            }
        }
    }

    fn genesis(
        &self,
        config: &Self::Config,
        working_set: &mut WorkingSet<Self::Context>,
    ) -> Result<(), sov_modules_api::Error> {
        Ok(self.init_module(config, working_set)?)
    }
}

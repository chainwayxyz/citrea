mod call;
mod genesis;
mod hooks;
mod query;
mod tests;
pub use call::*;
pub use genesis::*;
pub use query::*;
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
    pub(crate) limiting_number: StateValue<u64, BcsCodec>,
    /// Mapping from DA root hash to a number.
    /// Checks how many L1 blocks were published for a specific L1 block with given DA root hash.
    #[state]
    pub(crate) da_root_hash_to_number: StateMap<[u8; 32], u64, BcsCodec>,
    /// Authority address. Address of the sequencer.
    /// This address is allowed to modify the limiting number.
    #[state]
    pub(crate) authority: StateValue<C::Address, BcsCodec>,
    /// L1 fee rate change percentage
    /// First block after genesis does not need to abide to this rule since last l1 fee rate does not exist.
    #[state]
    pub(crate) l1_fee_rate_change_percentage: StateValue<u64, BcsCodec>,
    /// Last processed L1 fee rate
    /// 0 at genesis
    #[state]
    pub(crate) last_l1_fee_rate: StateValue<u64, BcsCodec>,
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
            CallMessage::ModifyLimitingNumber { limiting_number } => {
                Ok(self.modify_limiting_number(limiting_number, context, working_set)?)
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

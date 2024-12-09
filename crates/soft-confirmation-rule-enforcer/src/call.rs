use core::result::Result;

use borsh::{BorshDeserialize, BorshSerialize};
use sov_modules_api::{
    CallResponse, Context, DaSpec, SoftConfirmationModuleCallError, StateValueAccessor, WorkingSet,
};

use crate::SoftConfirmationRuleEnforcer;

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    derive(serde::Deserialize)
)]
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub enum CallMessage<C: Context> {
    /// Change the authority of soft confirmation rule enforcing.
    ChangeAuthority {
        /// The sov address of the new authority.
        new_authority: C::Address,
    },
    /// Remove a sequencer from the sequencer registry.
    ModifyMaxL2BlocksPerL1 {
        /// The new max L2 blocks per L1 representing max number of L2 blocks published per L1 block.
        max_l2_blocks_per_l1: u32,
    },
}

impl<C: Context, Da: DaSpec> SoftConfirmationRuleEnforcer<C, Da> {
    /// Returns the address of authority.
    fn get_authority(&self, working_set: &mut WorkingSet<C::Storage>) -> C::Address {
        self.authority
            .get(working_set)
            .expect("Authority must be set")
    }

    pub(crate) fn change_authority(
        &self,
        address: C::Address,
        context: &C,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<CallResponse, SoftConfirmationModuleCallError> {
        if *context.sender() != self.get_authority(working_set) {
            return Err(SoftConfirmationModuleCallError::RuleEnforcerUnauthorized);
        }

        self.authority.set(&address, working_set);
        Ok(CallResponse::default())
    }

    pub(crate) fn modify_max_l2_blocks_per_l1(
        &self,
        max_l2_blocks_per_l1: u32,
        context: &C,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<CallResponse, SoftConfirmationModuleCallError> {
        if *context.sender() != self.get_authority(working_set) {
            return Err(SoftConfirmationModuleCallError::RuleEnforcerUnauthorized);
        }

        let mut data = self.data.get(working_set).expect("Data must be set");

        data.max_l2_blocks_per_l1 = max_l2_blocks_per_l1;

        self.data.set(&data, working_set);

        Ok(CallResponse::default())
    }
}

use core::result::Result;

use borsh::{BorshDeserialize, BorshSerialize};
use sov_modules_api::{
    Address, CallResponse, Context, DaSpec, L2BlockModuleCallError, StateValueAccessor, WorkingSet,
};

use crate::L2BlockRuleEnforcer;

#[derive(
    Debug,
    Clone,
    BorshDeserialize,
    BorshSerialize,
    Eq,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum CallMessage {
    /// Change the authority of l2 block rule enforcing.
    ChangeAuthority {
        /// The sov address of the new authority.
        new_authority: Address,
    },
    /// Remove a sequencer from the sequencer registry.
    ModifyMaxL2BlocksPerL1 {
        /// The new max L2 blocks per L1 representing max number of L2 blocks published per L1 block.
        max_l2_blocks_per_l1: u32,
    },
}

impl<C: Context, Da: DaSpec> L2BlockRuleEnforcer<C, Da> {
    /// Returns the address of authority.
    fn get_authority(&self, working_set: &mut WorkingSet<C::Storage>) -> Address {
        self.authority
            .get(working_set)
            .expect("Authority must be set")
    }

    pub(crate) fn change_authority(
        &self,
        address: Address,
        context: &C,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<CallResponse, L2BlockModuleCallError> {
        if *context.sender() != self.get_authority(working_set) {
            return Err(L2BlockModuleCallError::RuleEnforcerUnauthorized);
        }

        self.authority.set(&address, working_set);
        Ok(CallResponse::default())
    }

    pub(crate) fn modify_max_l2_blocks_per_l1(
        &self,
        max_l2_blocks_per_l1: u32,
        context: &C,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<CallResponse, L2BlockModuleCallError> {
        if *context.sender() != self.get_authority(working_set) {
            return Err(L2BlockModuleCallError::RuleEnforcerUnauthorized);
        }

        let mut data = self.data.get(working_set).expect("Data must be set");

        data.max_l2_blocks_per_l1 = max_l2_blocks_per_l1;

        self.data.set(&data, working_set);

        Ok(CallResponse::default())
    }
}

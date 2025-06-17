//! Call message types and handlers for the L2 Block Rule Enforcer module.
//!
//! This module defines the external API for interacting with the rule enforcer,
//! including authority management and configuration changes.

use core::result::Result;

use borsh::{BorshDeserialize, BorshSerialize};
use sov_modules_api::{
    Address, CallResponse, Context, DaSpec, L2BlockModuleCallError, StateValueAccessor, WorkingSet,
};

use crate::L2BlockRuleEnforcer;

/// Call messages that can be sent to the L2 Block Rule Enforcer module.
///
/// These messages allow for runtime configuration changes, but require
/// authorization from the current authority address.
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
    ///
    /// # Panics
    ///
    /// Panics if the authority has not been set during genesis initialization.
    fn get_authority(&self, working_set: &mut WorkingSet<C::Storage>) -> Address {
        self.authority
            .get(working_set)
            .expect("Authority must be set")
    }

    /// Changes the authority address that can modify the rule enforcer configuration.
    ///
    /// This operation can only be performed by the current authority.
    ///
    /// # Arguments
    ///
    /// * `address` - The new authority address
    /// * `context` - The execution context containing the sender information
    /// * `working_set` - The working set for state modifications
    ///
    /// # Returns
    ///
    /// Returns `Ok(CallResponse::default())` on success, or an error if unauthorized.
    ///
    /// # Errors
    ///
    /// Returns `L2BlockModuleCallError::RuleEnforcerUnauthorized` if the sender
    /// is not the current authority.
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

    /// Modifies the maximum number of L2 blocks allowed per L1 block.
    ///
    /// This operation can only be performed by the current authority.
    ///
    /// # Arguments
    ///
    /// * `max_l2_blocks_per_l1` - The new maximum number of L2 blocks per L1 block
    /// * `context` - The execution context containing the sender information
    /// * `working_set` - The working set for state modifications
    ///
    /// # Returns
    ///
    /// Returns `Ok(CallResponse::default())` on success, or an error if unauthorized.
    ///
    /// # Errors
    ///
    /// Returns `L2BlockModuleCallError::RuleEnforcerUnauthorized` if the sender
    /// is not the current authority.
    ///
    /// # Panics
    ///
    /// Panics if the rule enforcer data has not been initialized during genesis.
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

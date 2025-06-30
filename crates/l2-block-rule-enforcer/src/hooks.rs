//! Hook implementations for the L2 Block Rule Enforcer module.
//!
//! This module implements the core rule enforcement logic that runs at the end
//! of each L2 block to validate sequencer behavior according to the configured rules.

use citrea_evm::{get_last_l1_height_and_hash_in_light_client, Evm};
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::{Context, DaSpec, L2BlockHookError, StateValueAccessor, WorkingSet};
#[cfg(feature = "native")]
use tracing::instrument;

use crate::{L2BlockRuleEnforcer, RuleEnforcerData};

impl<C: Context, Da: DaSpec> L2BlockRuleEnforcer<C, Da> {
    /// Checks the block count rule.
    /// For every L1 block, the number of L2 blocks should not exceed the max L2 blocks per L1.
    /// If the number of L2 blocks exceeds the max L2 blocks per L1, the l2 block should fail and not be accepted by full nodes.
    /// This ensures the sequencer cannot publish more than the allowed number of L2 blocks per L1 block.
    /// Thus blocks the ability of the sequencer to censor the forced transactions in a future L1 block by not using that block.
    ///
    /// # Arguments
    ///
    /// * `_l2_block_info` - Information about the current L2 block (unused in current implementation)
    /// * `max_l2_blocks_per_l1` - The maximum allowed L2 blocks per L1 block
    /// * `last_da_root_hash` - Mutable reference to the last seen DA root hash
    /// * `counter` - Mutable reference to the current L2 block counter for this L1 block
    /// * `working_set` - The working set for reading state
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the block count rule is satisfied, or an error if violated.
    ///
    /// # Errors
    ///
    /// Returns `L2BlockHookError::TooManyL2BlocksOnDaSlot` if adding this L2 block
    /// would exceed the maximum allowed L2 blocks per L1 block.
    ///
    /// # Logic
    ///
    /// 1. Gets the current DA root hash from the light client
    /// 2. If the DA root hash is the same as the last one, increments the counter
    /// 3. If the DA root hash is different, resets the counter to 1 (new L1 block)
    /// 4. Validates that the counter doesn't exceed the maximum allowed
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, err, ret))]
    fn apply_block_count_rule(
        &self,
        _l2_block_info: &HookL2BlockInfo,
        max_l2_blocks_per_l1: u32,
        last_da_root_hash: &mut [u8; 32],
        counter: &mut u32,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), L2BlockHookError> {
        let da_root_hash = {
            let evm = Evm::<C>::default();
            get_last_l1_height_and_hash_in_light_client(&evm, working_set)
                .1
                .to_be_bytes::<32>()
        };

        if da_root_hash == *last_da_root_hash {
            *counter += 1;

            // Adding one more l2 block will exceed the max L2 blocks per L1
            if *counter > max_l2_blocks_per_l1 {
                // block count per l1 block should not be more than max L2 blocks per L1
                return Err(L2BlockHookError::TooManyL2BlocksOnDaSlot);
            }
        } else {
            *counter = 1;
            *last_da_root_hash = da_root_hash;
        }

        Ok(())
    }

    /// Checks that the current block's timestamp.
    /// This is to make sure that the set timestamp is greater than the last block's timestamp.
    ///
    /// # Arguments
    ///
    /// * `l2_block` - Information about the current L2 block, including its timestamp
    /// * `last_timestamp` - Mutable reference to the last block's timestamp
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the timestamp rule is satisfied, or an error if violated.
    ///
    /// # Errors
    ///
    /// Returns `L2BlockHookError::TimestampShouldBeGreater` if the current block's
    /// timestamp is less than the previous block's timestamp.
    ///
    /// # Logic
    ///
    /// 1. Gets the current block's timestamp
    /// 2. Compares it with the last block's timestamp
    /// 3. Updates the last timestamp if valid
    /// 4. Ensures strict temporal ordering of blocks
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, err, ret))]
    fn apply_timestamp_rule(
        &self,
        l2_block: &HookL2BlockInfo,
        last_timestamp: &mut u64,
    ) -> Result<(), L2BlockHookError> {
        let current_timestamp = l2_block.timestamp();

        if current_timestamp < *last_timestamp {
            return Err(L2BlockHookError::TimestampShouldBeGreater);
        }

        *last_timestamp = current_timestamp;

        Ok(())
    }

    /// Block count and timestamp check logic executed at the end of the L2 block.
    ///
    /// This is the main hook handler that orchestrates all rule validation.
    /// It loads the current rule enforcer state, applies all validation rules,
    /// and updates the state with the new values.
    ///
    /// # Arguments
    ///
    /// * `l2_block_info` - Information about the current L2 block being validated
    /// * `working_set` - The working set for reading and writing state
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all rules pass, or an error if any rule is violated.
    ///
    /// # Errors
    ///
    /// This method can return any error from the individual rule validation methods:
    /// - `L2BlockHookError::TooManyL2BlocksOnDaSlot` - Too many L2 blocks for current L1 block
    /// - `L2BlockHookError::TimestampShouldBeGreater` - Invalid timestamp ordering
    ///
    /// # Panics
    ///
    /// Panics if the rule enforcer data has not been initialized during genesis.
    ///
    /// # Logic Flow
    ///
    /// 1. Loads the current rule enforcer state
    /// 2. Applies the block count rule
    /// 3. Applies the timestamp rule
    /// 4. Saves the updated state back to storage
    pub fn hook_handler(
        &self,
        l2_block_info: &HookL2BlockInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), L2BlockHookError> {
        let RuleEnforcerData {
            max_l2_blocks_per_l1,
            mut last_da_root_hash,
            mut counter,
            mut last_timestamp,
        } = self
            .data
            .get(working_set)
            .expect("should be set in genesis");

        self.apply_block_count_rule(
            l2_block_info,
            max_l2_blocks_per_l1,
            &mut last_da_root_hash,
            &mut counter,
            working_set,
        )?;

        self.apply_timestamp_rule(l2_block_info, &mut last_timestamp)?;

        self.data.set(
            &RuleEnforcerData {
                max_l2_blocks_per_l1,
                last_da_root_hash,
                counter,
                last_timestamp,
            },
            working_set,
        );

        Ok(())
    }

    /// This is put in the end because if the block count exceeds the max L2 blocks per L1,
    /// and since the rule is checked before set block info is applied by the sequencer,
    /// the sequencer halts and never produces any more blocks.
    /// Works for post tangerine blocks
    ///
    /// This is the main entry point for the L2 block hook that gets called by the
    /// rollup framework at the end of each L2 block execution.
    ///
    /// # Arguments
    ///
    /// * `l2_block_info` - Information about the L2 block that just finished execution
    /// * `working_set` - The working set for state access and modifications
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all validation rules pass, or an error if any rule fails.
    ///
    /// # Errors
    ///
    /// Returns validation errors from the underlying rule enforcement logic.
    ///
    /// # Important Notes
    ///
    /// This hook is designed to run at the end of block execution, which means:
    /// - If rules are violated, the entire block is rejected
    /// - The sequencer will halt if it tries to violate the rules
    /// - This prevents malicious sequencer behavior proactively
    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", skip(self, working_set), err, ret)
    )]
    pub fn end_l2_block_hook(
        &self,
        l2_block_info: &HookL2BlockInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), L2BlockHookError> {
        self.hook_handler(l2_block_info, working_set)
    }
}

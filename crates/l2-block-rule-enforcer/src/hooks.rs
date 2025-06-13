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

    /// Block count  and timestamp check Logic executed at the end of the l2 block.
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

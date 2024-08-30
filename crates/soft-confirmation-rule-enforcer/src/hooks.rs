use sov_modules_api::hooks::{HookSoftConfirmationInfo, SoftConfirmationError};
use sov_modules_api::{Context, DaSpec, StateValueAccessor, WorkingSet};
use sov_state::Storage;
#[cfg(feature = "native")]
use tracing::instrument;

use crate::{RuleEnforcerData, SoftConfirmationRuleEnforcer};

impl<C: Context, Da: DaSpec> SoftConfirmationRuleEnforcer<C, Da>
where
    <C::Storage as Storage>::Root: Into<[u8; 32]>,
{
    /// Checks the block count rule.
    /// For every L1 block, the number of L2 blocks should not exceed the max L2 blocks per L1.
    /// If the number of L2 blocks exceeds the max L2 blocks per L1, the soft confirmation should fail and not be accepted by full nodes.
    /// This ensures the sequencer cannot publish more than the allowed number of L2 blocks per L1 block.
    /// Thus blocks the ability of the sequencer to censor the forced transactions in a future L1 block by not using that block.
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, err, ret))]
    fn apply_block_count_rule(
        &self,
        soft_confirmation_info: &HookSoftConfirmationInfo,
        max_l2_blocks_per_l1: u32,
        last_da_root_hash: &mut [u8; 32],
        counter: &mut u32,
    ) -> Result<(), SoftConfirmationError> {
        let da_root_hash = soft_confirmation_info.da_slot_hash();

        if da_root_hash == *last_da_root_hash {
            *counter += 1;

            // Adding one more l2 block will exceed the max L2 blocks per L1
            if *counter > max_l2_blocks_per_l1 {
                // block count per l1 block should not be more than max L2 blocks per L1
                return Err(SoftConfirmationError::Other(
                    "Too many soft confirmations on DA slot".to_string(),
                ));
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
        soft_confirmation: &HookSoftConfirmationInfo,
        last_timestamp: &mut u64,
    ) -> Result<(), SoftConfirmationError> {
        let current_timestamp = soft_confirmation.timestamp();

        if current_timestamp < *last_timestamp {
            return Err(SoftConfirmationError::Other(
                "Timestamp should be greater than last timestamp".to_string(),
            ));
        }

        *last_timestamp = current_timestamp;

        Ok(())
    }

    /// Logic executed at the beginning of the soft confirmation.
    /// Checks two rules: block count rule and fee rate rule.
    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", skip(self, working_set), err, ret)
    )]
    pub fn begin_soft_confirmation_hook(
        &self,
        soft_confirmation: &mut HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<C>,
    ) -> Result<(), SoftConfirmationError> {
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
            soft_confirmation,
            max_l2_blocks_per_l1,
            &mut last_da_root_hash,
            &mut counter,
        )?;

        self.apply_timestamp_rule(soft_confirmation, &mut last_timestamp)?;

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
}

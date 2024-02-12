use anyhow::anyhow;
use sov_modules_api::{Context, DaSpec, StateMapAccessor, StateValueAccessor, WorkingSet};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmationBatch;
use sov_state::Storage;

use crate::SoftConfirmationRuleEnforcer;

impl<C: Context, Da: DaSpec> SoftConfirmationRuleEnforcer<C, Da>
where
    <C::Storage as Storage>::Root: Into<[u8; 32]>,
{
    /// Checks the block count rule
    fn apply_block_count_rule(
        &self,
        soft_batch: &mut SignedSoftConfirmationBatch,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        let da_root_hash = soft_batch.da_slot_hash();
        let l2_block_count = self
            .get_block_count_by_da_root_hash(da_root_hash, working_set)
            .expect("Block count must be set by da root hash must be set");
        let limiting_number = self
            .get_limiting_number(working_set)
            .expect("Limiting number must be set");

        // Adding one more l2 block will exceed the limiting number
        if l2_block_count + 1 > limiting_number {
            // block count per l1 block should not be more than limiting number
            return Err(anyhow!(
                "Block count per l1 block {} should not be more than limiting number {}",
                l2_block_count,
                limiting_number
            ));
        }

        self.da_root_hash_to_number
            .set(&da_root_hash, &(l2_block_count + 1), working_set);

        Ok(())
    }

    /// Checks the L1 fee rate rule
    fn apply_fee_rate_rule(
        &self,
        soft_batch: &mut SignedSoftConfirmationBatch,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        let l1_fee_rate = soft_batch.l1_fee_rate();
        let last_l1_fee_rate = self.last_l1_fee_rate.get(working_set).unwrap_or(0);

        if last_l1_fee_rate == 0 {
            return Ok(());
        }

        let l1_fee_rate_change_percentage = u64::from(
            self.l1_fee_rate_change_percentage
                .get(working_set)
                .expect("L1 fee rate change should be set"),
        );

        if l1_fee_rate * (100 + l1_fee_rate_change_percentage) > last_l1_fee_rate * 100
            || l1_fee_rate * (100 + l1_fee_rate_change_percentage) < last_l1_fee_rate * 100
        {
            return Err(anyhow!(
                "L1 fee rate {} changed more than allowed limit %{}",
                l1_fee_rate,
                l1_fee_rate_change_percentage
            ));
        }

        self.last_l1_fee_rate
            .set(&soft_batch.l1_fee_rate, working_set);

        Ok(())
    }

    /// Logic executed at the beginning of the soft confirmation.
    /// Here it is checked if the number of L2 blocks published for the
    /// L1 block with given DA root hash is less than the limiting number.
    pub fn begin_soft_confirmation_hook(
        &self,
        soft_batch: &mut SignedSoftConfirmationBatch,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        self.apply_block_count_rule(soft_batch, working_set)?;

        self.apply_fee_rate_rule(soft_batch, working_set)?;

        Ok(())
    }
}

use anyhow::anyhow;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::{Context, DaSpec, StateMapAccessor, StateValueAccessor, WorkingSet};
use sov_state::Storage;

use crate::SoftConfirmationRuleEnforcer;

impl<C: Context, Da: DaSpec> SoftConfirmationRuleEnforcer<C, Da>
where
    <C::Storage as Storage>::Root: Into<[u8; 32]>,
{
    /// Checks the block count rule.
    /// For every L1 block, the number of L2 blocks should not exceed the limiting number.
    /// If the number of L2 blocks exceeds the limiting number, the soft confirmation should fail and not be accepted by full nodes.
    /// This ensures the sequencer cannot publish more than the allowed number of L2 blocks per L1 block.
    /// Thus blocks the ability of the sequencer to censor the forced transactions in a future L1 block by not using that block.
    fn apply_block_count_rule(
        &self,
        soft_batch_info: &mut HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        let da_root_hash = soft_batch_info.da_slot_hash();
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

        // increment the block count
        self.da_root_hash_to_number
            .set(&da_root_hash, &(l2_block_count + 1), working_set);

        Ok(())
    }

    /// Checks the L1 fee rate rule.
    /// The L1 fee rate should not change more than the allowed percentage.
    /// If the L1 fee rate changes more than the allowed percentage, the soft confirmation should fail and not be accepted by full nodes.
    /// This ensures the sequencer cannot change the fee rate more than the allowed percentage.
    /// Thus blocks the ability of the sequencer to raise the L1 fee rates arbitrarily and charging a transaction maliciously.
    /// An ideal solution would have the L1 fee trustlessly determined by the L2 users, but that is not possible currently.
    fn apply_fee_rate_rule(
        &self,
        soft_batch: &mut HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        let l1_fee_rate = soft_batch.l1_fee_rate();
        let last_l1_fee_rate = self.last_l1_fee_rate.get(working_set).unwrap_or(0);

        // if we are in the block right after genesis, we don't have a last fee rate
        // so just accept the given fee rate
        if last_l1_fee_rate == 0 {
            // early return so don't forget to set
            self.last_l1_fee_rate
                .set(&soft_batch.l1_fee_rate, working_set);
            return Ok(());
        }

        let l1_fee_rate_change_percentage = self
            .l1_fee_rate_change_percentage
            .get(working_set)
            .expect("L1 fee rate change should be set");

        // check last fee * (100 - change percentage) / 100 <= current fee <= last fee * (100 + change percentage) / 100
        if l1_fee_rate * 100 < last_l1_fee_rate * (100 - l1_fee_rate_change_percentage)
            || l1_fee_rate * 100 > last_l1_fee_rate * (100 + l1_fee_rate_change_percentage)
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
    /// Checks two rules: block count rule and fee rate rule.
    pub fn begin_soft_confirmation_hook(
        &self,
        soft_batch: &mut HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        self.apply_block_count_rule(soft_batch, working_set)?;

        self.apply_fee_rate_rule(soft_batch, working_set)?;

        Ok(())
    }
}

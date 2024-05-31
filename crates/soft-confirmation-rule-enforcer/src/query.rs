use std::ops::RangeInclusive;

use jsonrpsee::core::RpcResult;
use sov_modules_api::macros::rpc_gen;
use sov_modules_api::{Context, DaSpec, StateMapAccessor, StateValueAccessor, WorkingSet};

use crate::SoftConfirmationRuleEnforcer;

#[rpc_gen(client, server, namespace = "softConfirmationRuleEnforcer")]
impl<C: Context, Da: DaSpec> SoftConfirmationRuleEnforcer<C, Da> {
    #[rpc_method(name = "getLimitingNumber")]
    /// Get the account corresponding to the given public key.
    pub fn get_max_l2_blocks_per_l1(&self, working_set: &mut WorkingSet<C>) -> RpcResult<u64> {
        Ok(self
            .max_l2_blocks_per_l1
            .get(working_set)
            .expect("Limiting number must be set"))
    }

    #[rpc_method(name = "getBlockCountByDaRootHash")]
    /// Get number of L2 blocks published for L1 block with the given DA root hash.
    pub fn get_block_count_by_da_root_hash(
        &self,
        da_root_hash: [u8; 32],
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<u64> {
        Ok(self
            .da_root_hash_to_number
            .get(&da_root_hash, working_set)
            .unwrap_or(0))
    }

    #[rpc_method(name = "getMaxL1FeeRateChangePercentage")]
    /// Get the maximum L1 fee rate change percentage.
    pub fn get_max_l1_fee_rate_change_percentage(
        &self,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<u128> {
        Ok(self
            .l1_fee_rate_change_percentage
            .get(working_set)
            .expect("L1 fee rate change should be set"))
    }

    #[rpc_method(name = "getLastL1FeeRate")]
    /// Get the last processed L1 fee rate.
    /// 0 at genesis.
    pub fn get_last_l1_fee_rate(&self, working_set: &mut WorkingSet<C>) -> RpcResult<u128> {
        Ok(self.last_l1_fee_rate.get(working_set).unwrap_or(0))
    }
    #[rpc_method(name = "getLatestBlockTimestamp")]
    /// Get the latest block's timestamp.
    /// 0 at genesis.
    pub fn get_last_timestamp(&self, working_set: &mut WorkingSet<C>) -> RpcResult<u64> {
        Ok(self.last_timestamp.get(working_set).unwrap_or(0))
    }

    /// function to get min and max for next L1 fee rate
    pub fn get_next_min_max_l1_fee_rate(
        &self,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<RangeInclusive<u128>> {
        let last_l1_fee_rate = self.last_l1_fee_rate.get(working_set).unwrap_or(0);

        if last_l1_fee_rate == 0 {
            // on the first soft confirmation, we don't have a last fee rate
            return Ok(0..=u128::MAX);
        }

        let l1_fee_rate_change_percentage = self
            .l1_fee_rate_change_percentage
            .get(working_set)
            .expect("L1 fee rate change should be set");

        let min = last_l1_fee_rate
            .saturating_sub((last_l1_fee_rate * l1_fee_rate_change_percentage) / 100);

        let max = last_l1_fee_rate
            .saturating_add((last_l1_fee_rate * l1_fee_rate_change_percentage) / 100);

        Ok(min..=max)
    }
}

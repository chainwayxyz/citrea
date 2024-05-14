use jsonrpsee::core::RpcResult;
use sov_modules_api::macros::rpc_gen;
use sov_modules_api::{Context, DaSpec, StateMapAccessor, StateValueAccessor, WorkingSet};

use crate::SoftConfirmationRuleEnforcer;

#[rpc_gen(client, server, namespace = "softConfirmationRuleEnforcer")]
impl<C: Context, Da: DaSpec> SoftConfirmationRuleEnforcer<C, Da> {
    #[rpc_method(name = "getLimitingNumber")]
    /// Get the account corresponding to the given public key.
    pub fn get_limiting_number(&self, working_set: &mut WorkingSet<C>) -> RpcResult<u64> {
        tokio::task::block_in_place(|| {
            Ok(self
                .limiting_number
                .get(working_set)
                .expect("Limiting number must be set"))
        })
    }

    #[rpc_method(name = "getBlockCountByDaRootHash")]
    /// Get number of L2 blocks published for L1 block with the given DA root hash.
    pub fn get_block_count_by_da_root_hash(
        &self,
        da_root_hash: [u8; 32],
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<u64> {
        tokio::task::block_in_place(|| {
            Ok(self
                .da_root_hash_to_number
                .get(&da_root_hash, working_set)
                .unwrap_or(0))
        })
    }

    #[rpc_method(name = "getMaxL1FeeRateChangePercentage")]
    /// Get the maximum L1 fee rate change percentage.
    pub fn get_max_l1_fee_rate_change_percentage(
        &self,
        working_set: &mut WorkingSet<C>,
    ) -> RpcResult<u128> {
        tokio::task::block_in_place(|| {
            Ok(self
                .l1_fee_rate_change_percentage
                .get(working_set)
                .expect("L1 fee rate change should be set"))
        })
    }

    #[rpc_method(name = "getLastL1FeeRate")]
    /// Get the last processed L1 fee rate.
    /// 0 at genesis.
    pub fn get_last_l1_fee_rate(&self, working_set: &mut WorkingSet<C>) -> RpcResult<u128> {
        tokio::task::block_in_place(|| Ok(self.last_l1_fee_rate.get(working_set).unwrap_or(0)))
    }
    #[rpc_method(name = "getLatestBlockTimestamp")]
    /// Get the latest block's timestamp.
    /// 0 at genesis.
    pub fn get_last_timestamp(&self, working_set: &mut WorkingSet<C>) -> RpcResult<u64> {
        tokio::task::block_in_place(|| Ok(self.last_timestamp.get(working_set).unwrap_or(0)))
    }
}

use jsonrpsee::core::RpcResult;
use sov_modules_api::macros::rpc_gen;
use sov_modules_api::{Context, DaSpec, StateValueAccessor, WorkingSet};

use crate::SoftConfirmationRuleEnforcer;

#[rpc_gen(client, server, namespace = "softConfirmationRuleEnforcer")]
impl<C: Context, Da: DaSpec> SoftConfirmationRuleEnforcer<C, Da> {
    #[rpc_method(name = "getMaxL2BlocksPerL1")]
    /// Get the account corresponding to the given public key.
    pub fn get_max_l2_blocks_per_l1(
        &self,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> RpcResult<u32> {
        Ok(self
            .data
            .get(working_set)
            .expect("Max L2 blocks per L1 must be set")
            .max_l2_blocks_per_l1)
    }

    #[rpc_method(name = "getLatestBlockTimestamp")]
    /// Get the latest block's timestamp.
    /// 0 at genesis.
    pub fn get_last_timestamp(&self, working_set: &mut WorkingSet<C::Storage>) -> RpcResult<u64> {
        Ok(self
            .data
            .get(working_set)
            .expect("should be set in genesis; qed")
            .last_timestamp)
    }
}

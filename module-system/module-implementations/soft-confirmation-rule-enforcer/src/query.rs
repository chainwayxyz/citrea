use jsonrpsee::core::RpcResult;
use sov_modules_api::macros::rpc_gen;
use sov_modules_api::{StateMapAccessor, StateValueAccessor, WorkingSet};

use crate::SoftConfirmationRuleEnforcer;

#[rpc_gen(client, server, namespace = "softConfirmationRuleEnforcer")]
impl<C: sov_modules_api::Context> SoftConfirmationRuleEnforcer<C> {
    #[rpc_method(name = "getLimitingNumber")]
    /// Get the account corresponding to the given public key.
    pub fn get_limiting_number(&self, working_set: &mut WorkingSet<C>) -> RpcResult<u64> {
        Ok(self
            .limiting_number
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
}

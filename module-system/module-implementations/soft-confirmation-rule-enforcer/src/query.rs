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
}

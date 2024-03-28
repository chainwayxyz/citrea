// use jsonrpsee::core::RpcResult;
use sov_modules_api::macros::rpc_gen;

// use sov_modules_api::WorkingSet;
use crate::ChainState;

#[rpc_gen(client, server, namespace = "chainState")]
impl<C: sov_modules_api::Context, Da: sov_modules_api::DaSpec> ChainState<C, Da> {
    // TODO: Re-enable this RPC method once the `KernelWorkingSet` type is removed
    // /// Get the height of the current slot.
    // /// Panics if the slot height is not set
    // #[rpc_method(name = "getSlotHeight")]
    // pub fn get_slot_height_rpc(
    //     &self,
    //     working_set: &mut WorkingSet<C>,
    // ) -> RpcResult<TransitionHeight> {
    //     Ok(self.get_slot_height(working_set))
    // }
}

use sov_accounts::AccountsTxHook;
use sov_modules_api::hooks::{
    ApplyL2BlockHooks, FinalizeHook, HookL2BlockInfo, SlotHooks, TxHooks,
};
use sov_modules_api::{AccessoryWorkingSet, Context, L2BlockHookError, SpecId, WorkingSet};
use sov_modules_stf_blueprint::RuntimeTxHook;
use sov_rollup_interface::da::DaSpec;
use sov_rollup_interface::transaction::Transaction;
use sov_rollup_interface::zk::StorageRootHash;
#[cfg(feature = "native")]
use tracing::instrument;

use crate::runtime::CitreaRuntime;

impl<C: Context, Da: DaSpec> TxHooks for CitreaRuntime<C, Da> {
    type Context = C;
    type PreArg = RuntimeTxHook;
    type PreResult = C;

    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, err))]
    fn pre_dispatch_tx_hook(
        &self,
        tx: &Transaction,
        working_set: &mut WorkingSet<C::Storage>,
        arg: &RuntimeTxHook,
        spec_id: SpecId,
    ) -> Result<C, L2BlockHookError> {
        let RuntimeTxHook {
            height,
            current_spec,
            l1_fee_rate,
        } = arg;
        let AccountsTxHook { sender } =
            self.accounts
                .pre_dispatch_tx_hook(tx, working_set, &None, spec_id)?;

        Ok(C::new(sender, *height, *current_spec, *l1_fee_rate))
    }

    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, ret))]
    fn post_dispatch_tx_hook(
        &self,
        tx: &Transaction,
        ctx: &C,
        working_set: &mut WorkingSet<C::Storage>,
        spec_id: SpecId,
    ) -> Result<(), L2BlockHookError> {
        self.accounts
            .post_dispatch_tx_hook(tx, ctx, working_set, spec_id)?;

        Ok(())
    }
}

impl<C: Context, Da: DaSpec> ApplyL2BlockHooks<Da> for CitreaRuntime<C, Da> {
    type Context = C;

    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", skip(self, working_set), err, ret)
    )]
    fn begin_l2_block_hook(
        &mut self,
        l2_block_info: &HookL2BlockInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), L2BlockHookError> {
        self.evm.begin_l2_block_hook(l2_block_info, working_set);

        Ok(())
    }

    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, err, ret))]
    fn end_l2_block_hook(
        &mut self,
        l2_block_info: HookL2BlockInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), L2BlockHookError> {
        self.l2_block_rule_enforcer
            .end_l2_block_hook(&l2_block_info, working_set)?;
        self.evm.end_l2_block_hook(&l2_block_info, working_set);
        Ok(())
    }
}

impl<C: Context, Da: DaSpec> SlotHooks<Da> for CitreaRuntime<C, Da> {
    type Context = C;

    fn begin_slot_hook(
        &self,
        _slot_header: &Da::BlockHeader,
        _pre_state_root: &StorageRootHash,
        _working_set: &mut sov_modules_api::WorkingSet<C::Storage>,
    ) {
    }

    fn end_slot_hook(&self, _working_set: &mut sov_modules_api::WorkingSet<C::Storage>) {}
}

impl<C: Context, Da: sov_modules_api::DaSpec> FinalizeHook<Da> for CitreaRuntime<C, Da> {
    type Context = C;

    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", skip(self, accessory_working_set), ret)
    )]
    fn finalize_hook(
        &self,
        root_hash: &StorageRootHash,
        accessory_working_set: &mut AccessoryWorkingSet<C::Storage>,
    ) {
        self.evm.finalize_hook(root_hash, accessory_working_set);
    }
}

use sov_accounts::AccountsTxHook;
use sov_modules_api::hooks::{
    ApplyBlobHooks, ApplySoftConfirmationError, ApplySoftConfirmationHooks, FinalizeHook,
    HookSoftConfirmationInfo, SlotHooks, TxHooks,
};
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{AccessoryWorkingSet, Context, Spec, WorkingSet};
use sov_modules_stf_blueprint::{RuntimeTxHook, SequencerOutcome};
use sov_rollup_interface::da::{BlobReaderTrait, DaSpec};
use sov_state::Storage;
#[cfg(feature = "native")]
use tracing::instrument;

use crate::runtime::Runtime;

impl<C: Context, Da: DaSpec> TxHooks for Runtime<C, Da> {
    type Context = C;
    type PreArg = RuntimeTxHook<C>;
    type PreResult = C;

    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, err))]
    fn pre_dispatch_tx_hook(
        &self,
        tx: &Transaction<Self::Context>,
        working_set: &mut WorkingSet<C>,
        arg: &RuntimeTxHook<C>,
    ) -> anyhow::Result<C> {
        let RuntimeTxHook { height, sequencer } = arg;
        let AccountsTxHook { sender, sequencer } =
            self.accounts
                .pre_dispatch_tx_hook(tx, working_set, sequencer)?;

        Ok(C::new(sender, sequencer, *height))
    }

    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, ret))]
    fn post_dispatch_tx_hook(
        &self,
        tx: &Transaction<Self::Context>,
        ctx: &C,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        self.accounts.post_dispatch_tx_hook(tx, ctx, working_set)?;

        Ok(())
    }
}

impl<C: Context, Da: DaSpec> ApplyBlobHooks<Da::BlobTransaction> for Runtime<C, Da> {
    type Context = C;
    type BlobResult =
        SequencerOutcome<<<Da as DaSpec>::BlobTransaction as BlobReaderTrait>::Address>;

    fn begin_blob_hook(
        &self,
        _blob: &mut Da::BlobTransaction,
        _working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn end_blob_hook(&self, _working_set: &mut WorkingSet<C>) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<C: Context, Da: DaSpec> ApplySoftConfirmationHooks<Da> for Runtime<C, Da> {
    type Context = C;
    type SoftConfirmationResult =
        SequencerOutcome<<<Da as DaSpec>::BlobTransaction as BlobReaderTrait>::Address>;

    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", skip(self, working_set), err, ret)
    )]
    fn begin_soft_confirmation_hook(
        &self,
        soft_batch: &mut HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<Self::Context>,
    ) -> Result<(), ApplySoftConfirmationError> {
        self.soft_confirmation_rule_enforcer
            .begin_soft_confirmation_hook(soft_batch, working_set)?;

        self.evm
            .begin_soft_confirmation_hook(soft_batch, working_set);

        Ok(())
    }

    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, err, ret))]
    fn end_soft_confirmation_hook(
        &self,
        working_set: &mut WorkingSet<C>,
    ) -> Result<(), ApplySoftConfirmationError> {
        self.evm.end_soft_confirmation_hook(working_set);
        Ok(())
    }
}

impl<C: Context, Da: DaSpec> SlotHooks<Da> for Runtime<C, Da> {
    type Context = C;

    fn begin_slot_hook(
        &self,
        _slot_header: &Da::BlockHeader,
        _validity_condition: &Da::ValidityCondition,
        _pre_state_root: &<<Self::Context as Spec>::Storage as Storage>::Root,
        _working_set: &mut sov_modules_api::WorkingSet<C>,
    ) {
    }

    fn end_slot_hook(&self, _working_set: &mut sov_modules_api::WorkingSet<C>) {}
}

impl<C: Context, Da: sov_modules_api::DaSpec> FinalizeHook<Da> for Runtime<C, Da> {
    type Context = C;

    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", skip(self, accessory_working_set), ret)
    )]
    fn finalize_hook(
        &self,
        root_hash: &<<Self::Context as Spec>::Storage as Storage>::Root,
        accessory_working_set: &mut AccessoryWorkingSet<C>,
    ) {
        self.evm.finalize_hook(root_hash, accessory_working_set);
    }
}

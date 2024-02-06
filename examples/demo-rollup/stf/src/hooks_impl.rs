use sov_accounts::AccountsTxHook;
use sov_bank::BankTxHook;
use sov_modules_api::hooks::{
    ApplyBlobHooks, ApplySoftConfirmationHooks, FinalizeHook, SlotHooks, TxHooks,
};
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{AccessoryWorkingSet, Context, Spec, WorkingSet};
use sov_modules_stf_blueprint::{RuntimeTxHook, SequencerOutcome};
use sov_rollup_interface::da::{BlobReaderTrait, BlockHeaderTrait, DaSpec};
use sov_sequencer_registry::SequencerRegistry;
use sov_state::Storage;
use tracing::info;

use crate::runtime::Runtime;

impl<C: Context, Da: DaSpec> TxHooks for Runtime<C, Da> {
    type Context = C;
    type PreArg = RuntimeTxHook<C>;
    type PreResult = C;

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

        let hook = BankTxHook { sender, sequencer };
        self.bank.pre_dispatch_tx_hook(tx, working_set, &hook)?;

        Ok(C::new(hook.sender, hook.sequencer, *height))
    }

    fn post_dispatch_tx_hook(
        &self,
        tx: &Transaction<Self::Context>,
        ctx: &C,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        self.accounts.post_dispatch_tx_hook(tx, ctx, working_set)?;
        self.bank.post_dispatch_tx_hook(tx, ctx, working_set)?;
        Ok(())
    }
}

impl<C: Context, Da: DaSpec> ApplyBlobHooks<Da::BlobTransaction> for Runtime<C, Da> {
    type Context = C;
    type BlobResult =
        SequencerOutcome<<<Da as DaSpec>::BlobTransaction as BlobReaderTrait>::Address>;

    fn begin_blob_hook(
        &self,
        blob: &mut Da::BlobTransaction,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        // Before executing each batch, check that the sender is registered as a sequencer
        self.sequencer_registry.begin_blob_hook(blob, working_set)
    }

    fn end_blob_hook(
        &self,
        result: Self::BlobResult,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        match result {
            SequencerOutcome::Rewarded(_reward) => {
                // TODO: Process reward here or above.
                <SequencerRegistry<C, Da> as ApplyBlobHooks<Da::BlobTransaction>>::end_blob_hook(
                    &self.sequencer_registry,
                    sov_sequencer_registry::SequencerOutcome::Completed,
                    working_set,
                )
            }
            SequencerOutcome::Ignored => Ok(()),
            SequencerOutcome::Slashed {
                reason,
                sequencer_da_address,
            } => {
                info!("Sequencer {} slashed: {:?}", sequencer_da_address, reason);
                <SequencerRegistry<C, Da> as ApplyBlobHooks<Da::BlobTransaction>>::end_blob_hook(
                    &self.sequencer_registry,
                    sov_sequencer_registry::SequencerOutcome::Slashed {
                        sequencer: sequencer_da_address,
                    },
                    working_set,
                )
            }
        }
    }
}

impl<C: Context, Da: DaSpec> ApplySoftConfirmationHooks<Da> for Runtime<C, Da> {
    type Context = C;
    type SoftConfirmationResult =
        SequencerOutcome<<<Da as DaSpec>::BlobTransaction as BlobReaderTrait>::Address>;

    fn begin_soft_confirmation_hook(
        &self,
        _soft_batch: &mut sov_rollup_interface::soft_confirmation::SignedSoftConfirmationBatch,
        _working_set: &mut WorkingSet<Self::Context>,
    ) -> anyhow::Result<()> {
        // Before executing each batch, check that the sender is registered as a sequencer
        Ok(())
    }

    fn end_soft_confirmation_hook(
        &self,
        _result: Self::SoftConfirmationResult,
        _working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<C: Context, Da: DaSpec> SlotHooks<Da> for Runtime<C, Da> {
    type Context = C;

    fn begin_slot_hook(
        &self,
        slot_header: &Da::BlockHeader,
        #[allow(unused_variables)] validity_condition: &Da::ValidityCondition,
        pre_state_root: &<<Self::Context as Spec>::Storage as Storage>::Root,
        working_set: &mut sov_modules_api::WorkingSet<C>,
    ) {
        // if soft confirmation rules are applied, then begin evm slot hook
        // TODO: If error: Do not panic, find a way to stop hooks until a new da slot arrives
        self.soft_confirmation_rule_enforcer
            .begin_slot_hook(&slot_header.hash(), pre_state_root, working_set)
            .expect("Sequencer gave too many soft confirmations for a single block.");
        // begin_soft_conf is a hack here so that tests of this stf run
        self.evm.begin_soft_confirmation_hook(
            slot_header.hash().into(),
            pre_state_root.as_ref(),
            working_set,
        );
    }

    fn end_slot_hook(&self, working_set: &mut sov_modules_api::WorkingSet<C>) {
        // end_soft_conf is a hack here so that tests of this stf run
        self.evm.end_soft_confirmation_hook(working_set);
    }
}

impl<C: Context, Da: sov_modules_api::DaSpec> FinalizeHook<Da> for Runtime<C, Da> {
    type Context = C;

    fn finalize_hook(
        &self,
        #[allow(unused_variables)] root_hash: &<<Self::Context as Spec>::Storage as Storage>::Root,
        #[allow(unused_variables)] accessory_working_set: &mut AccessoryWorkingSet<C>,
    ) {
        self.evm.finalize_hook(root_hash, accessory_working_set);
    }
}

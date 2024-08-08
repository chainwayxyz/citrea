use std::marker::PhantomData;

use sov_modules_api::hooks::{ApplySoftConfirmationError, HookSoftConfirmationInfo};
use sov_modules_api::{
    native_debug, native_error, Context, DaSpec, DispatchCall, StateCheckpoint, WorkingSet,
};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmationBatch;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::{BatchReceipt, TransactionReceipt};
use sov_state::Storage;
#[cfg(all(target_os = "zkvm", feature = "bench"))]
use sov_zk_cycle_macros::cycle_tracker;
#[cfg(feature = "native")]
use tracing::instrument;

use crate::tx_verifier::{verify_txs_stateless, TransactionAndRawHash};
use crate::{RawTx, Runtime, RuntimeTxHook, SlashingReason, TxEffect};

/// An implementation of the
/// [`StateTransitionFunction`](sov_rollup_interface::stf::StateTransitionFunction)
/// that is specifically designed to work with the module-system.
pub struct StfBlueprint<C: Context, Da: DaSpec, Vm, RT: Runtime<C, Da>> {
    /// State storage used by the rollup.
    /// The runtime includes all the modules that the rollup supports.
    pub(crate) runtime: RT,
    phantom_context: PhantomData<C>,
    phantom_vm: PhantomData<Vm>,
    phantom_da: PhantomData<Da>,
}

type ApplySoftConfirmationResult = Result<BatchReceipt<(), TxEffect>, ApplySoftConfirmationError>;

impl<C, Vm, Da, RT> Default for StfBlueprint<C, Da, Vm, RT>
where
    C: Context,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<C, Vm, Da, RT> StfBlueprint<C, Da, Vm, RT>
where
    C: Context,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    /// [`StfBlueprint`] constructor.
    pub fn new() -> Self {
        Self {
            runtime: RT::default(),
            phantom_context: PhantomData,
            phantom_vm: PhantomData,
            phantom_da: PhantomData,
        }
    }

    /// Applies sov txs to the state
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    pub fn apply_sov_txs_inner(
        &self,
        txs: Vec<Vec<u8>>,
        current_spec: SpecId,
        mut batch_workspace: WorkingSet<C>,
    ) -> (WorkingSet<C>, Vec<TransactionReceipt<TxEffect>>) {
        let txs = self.verify_txs_stateless_soft(&txs);

        let messages = self
            .decode_txs(&txs)
            .expect("Decoding transactions from the sequencer failed");

        // Sanity check after pre processing
        assert_eq!(
            txs.len(),
            messages.len(),
            "Error in preprocessing batch, there should be same number of txs and messages"
        );
        // Dispatching transactions
        let mut tx_receipts = Vec::with_capacity(txs.len());
        for (TransactionAndRawHash { tx, raw_tx_hash }, msg) in
            txs.into_iter().zip(messages.into_iter())
        {
            // Pre dispatch hook
            // TODO set the sequencer pubkey
            let hook = RuntimeTxHook {
                height: 1,
                sequencer: tx.pub_key().clone(),
                current_spec,
            };
            let ctx = match self
                .runtime
                .pre_dispatch_tx_hook(&tx, &mut batch_workspace, &hook)
            {
                Ok(verified_tx) => verified_tx,
                Err(e) => {
                    // Don't revert any state changes made by the pre_dispatch_hook even if the Tx is rejected.
                    // For example nonce for the relevant account is incremented.
                    native_error!("Stateful verification error - the sequencer included an invalid transaction: {}", e);
                    let receipt = TransactionReceipt {
                        tx_hash: raw_tx_hash,
                        body_to_save: None,
                        events: batch_workspace.take_events(),
                        receipt: TxEffect::Reverted,
                    };

                    tx_receipts.push(receipt);
                    continue;
                }
            };
            // Commit changes after pre_dispatch_tx_hook
            batch_workspace = batch_workspace.checkpoint().to_revertable();

            let tx_result = self.runtime.dispatch_call(msg, &mut batch_workspace, &ctx);

            let events = batch_workspace.take_events();
            let tx_effect = match tx_result {
                Ok(_) => TxEffect::Successful,
                Err(e) => {
                    native_error!(
                        "Tx 0x{} was reverted error: {}",
                        hex::encode(raw_tx_hash),
                        e
                    );
                    // The transaction causing invalid state transition is reverted
                    // but we don't slash and we continue processing remaining transactions.
                    batch_workspace = batch_workspace.revert().to_revertable();
                    TxEffect::Reverted
                }
            };
            native_debug!("Tx {} effect: {:?}", hex::encode(raw_tx_hash), tx_effect);

            let receipt = TransactionReceipt {
                tx_hash: raw_tx_hash,
                body_to_save: Some(borsh::to_vec(&tx).unwrap()),
                events,
                receipt: tx_effect,
            };

            tx_receipts.push(receipt);
            // We commit after events have been extracted into receipt.
            batch_workspace = batch_workspace.checkpoint().to_revertable();

            // TODO: `panic` will be covered in https://github.com/Sovereign-Labs/sovereign-sdk/issues/421
            // TODO: Check if we need to put this in end_soft_onfirmation, becuase I am not sure if we can call pre_dispatch again for new txs after this
            self.runtime
                .post_dispatch_tx_hook(&tx, &ctx, &mut batch_workspace)
                .expect("inconsistent state: error in post_dispatch_tx_hook");
        }
        (batch_workspace, tx_receipts)
    }

    /// Begins the inner processes of applying soft confirmation
    /// Module hooks are called here
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    pub fn begin_soft_confirmation_inner(
        &self,
        checkpoint: StateCheckpoint<C>,
        soft_batch: &mut SignedSoftConfirmationBatch,
        pre_state_root: &<C::Storage as Storage>::Root,
        current_spec: SpecId,
    ) -> (Result<(), ApplySoftConfirmationError>, WorkingSet<C>) {
        native_debug!(
            "Beginning soft batch 0x{} from sequencer: 0x{}",
            hex::encode(soft_batch.hash()),
            hex::encode(soft_batch.sequencer_pub_key())
        );

        let mut batch_workspace = checkpoint.to_revertable();

        // ApplySoftConfirmationHook: begin
        if let Err(e) = self.runtime.begin_soft_confirmation_hook(
            &mut HookSoftConfirmationInfo::new(
                soft_batch.clone(),
                pre_state_root.as_ref().to_vec(),
                current_spec,
            ),
            &mut batch_workspace,
        ) {
            native_error!(
                "Error: The batch was rejected by the 'begin_soft_confirmation_hook'. Skipping batch with error: {}",
                e
            );

            return (
                Err(e),
                // Reverted in apply_soft_batch and sequencer
                batch_workspace,
            );
        }

        // Write changes from begin_blob_hook
        batch_workspace = batch_workspace.checkpoint().to_revertable();

        // TODO: don't ignore these events: https://github.com/Sovereign-Labs/sovereign/issues/350
        let _ = batch_workspace.take_events();

        (Ok(()), batch_workspace)
    }

    /// Ends the inner processes of applying soft confirmation
    /// Module hooks are called here
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    pub fn end_soft_confirmation_inner(
        &self,
        soft_batch: &mut SignedSoftConfirmationBatch,
        tx_receipts: Vec<TransactionReceipt<TxEffect>>,
        mut batch_workspace: WorkingSet<C>,
    ) -> (ApplySoftConfirmationResult, StateCheckpoint<C>) {
        // TODO: calculate the amount based of gas and fees

        if let Err(e) = self
            .runtime
            .end_soft_confirmation_hook(&mut batch_workspace)
        {
            // TODO: will be covered in https://github.com/Sovereign-Labs/sovereign-sdk/issues/421
            native_error!("Failed on `end_blob_hook`: {}", e);
        };

        (
            Ok(BatchReceipt {
                hash: soft_batch.hash(),
                prev_hash: soft_batch.prev_hash(),
                tx_receipts,
                phantom_data: PhantomData,
            }),
            batch_workspace.checkpoint(),
        )
    }

    #[cfg_attr(all(target_os = "zkvm", feature = "bench"), cycle_tracker)]
    pub(crate) fn _apply_soft_confirmation_inner(
        &self,
        checkpoint: StateCheckpoint<C>,
        soft_batch: &mut SignedSoftConfirmationBatch,
        pre_state_root: &<C::Storage as Storage>::Root,
        current_spec: SpecId,
    ) -> (ApplySoftConfirmationResult, StateCheckpoint<C>) {
        match self.begin_soft_confirmation_inner(
            checkpoint,
            soft_batch,
            pre_state_root,
            current_spec,
        ) {
            (Ok(()), batch_workspace) => {
                // TODO: wait for txs here, apply_sov_txs can be called multiple times
                let (batch_workspace, tx_receipts) =
                    self.apply_sov_txs_inner(soft_batch.txs(), current_spec, batch_workspace);

                self.end_soft_confirmation_inner(soft_batch, tx_receipts, batch_workspace)
            }
            (Err(err), batch_workspace) => (Err(err), batch_workspace.revert()),
        }
    }

    // Stateless verification of transaction, such as signature check
    // Single malformed transaction results in sequencer slashing.
    fn verify_txs_stateless_soft(&self, txs: &[Vec<u8>]) -> Vec<TransactionAndRawHash<C>> {
        verify_txs_stateless(
            txs.iter()
                .map(|tx| RawTx { data: tx.clone() })
                .collect::<Vec<_>>(),
        )
        .expect("Sequencer must not include non-deserializable transaction.")
    }

    // Checks that runtime message can be decoded from transaction.
    // If a single message cannot be decoded, sequencer is slashed
    fn decode_txs(
        &self,
        txs: &[TransactionAndRawHash<C>],
    ) -> Result<Vec<<RT as DispatchCall>::Decodable>, SlashingReason> {
        let mut decoded_messages = Vec::with_capacity(txs.len());
        for TransactionAndRawHash { tx, raw_tx_hash } in txs {
            match RT::decode_call(tx.runtime_msg()) {
                Ok(msg) => decoded_messages.push(msg),
                Err(e) => {
                    native_error!("Tx 0x{} decoding error: {}", hex::encode(raw_tx_hash), e);
                    return Err(SlashingReason::InvalidTransactionEncoding);
                }
            }
        }
        Ok(decoded_messages)
    }
}

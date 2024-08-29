use std::marker::PhantomData;

use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::{
    native_debug, native_error, Context, DaSpec, DispatchCall, StateCheckpoint, WorkingSet,
};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmation;
use sov_rollup_interface::stf::{
    SoftConfirmationError, SoftConfirmationReceipt, TransactionReceipt,
};
// #[cfg(all(target_os = "zkvm", feature = "bench"))]
// use sov_zk_cycle_macros::cycle_tracker;
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

type ApplySoftConfirmationResult<Da> =
    Result<SoftConfirmationReceipt<TxEffect, Da>, SoftConfirmationError>;

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
        soft_confirmation_info: HookSoftConfirmationInfo,
        txs: Vec<Vec<u8>>,
        mut sc_workspace: WorkingSet<C>,
    ) -> (WorkingSet<C>, Vec<TransactionReceipt<TxEffect>>) {
        let txs = self.verify_txs_stateless_soft(txs);

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
                height: soft_confirmation_info.l2_height(),
                sequencer: tx.pub_key().clone(),
                current_spec: soft_confirmation_info.current_spec(),
                l1_fee_rate: soft_confirmation_info.l1_fee_rate(),
            };
            let ctx = match self
                .runtime
                .pre_dispatch_tx_hook(&tx, &mut sc_workspace, &hook)
            {
                Ok(verified_tx) => verified_tx,
                Err(e) => {
                    // Don't revert any state changes made by the pre_dispatch_hook even if the Tx is rejected.
                    // For example nonce for the relevant account is incremented.
                    native_error!("Stateful verification error - the sequencer included an invalid transaction: {}", e);
                    let receipt = TransactionReceipt {
                        tx_hash: raw_tx_hash,
                        body_to_save: None,
                        events: sc_workspace.take_events(),
                        receipt: TxEffect::Reverted,
                    };

                    tx_receipts.push(receipt);
                    continue;
                }
            };
            // Commit changes after pre_dispatch_tx_hook
            sc_workspace = sc_workspace.checkpoint().to_revertable();

            let tx_result = self.runtime.dispatch_call(msg, &mut sc_workspace, &ctx);

            let events = sc_workspace.take_events();
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
                    sc_workspace = sc_workspace.revert().to_revertable();
                    TxEffect::Reverted
                }
            };
            native_debug!("Tx {} effect: {:?}", hex::encode(raw_tx_hash), tx_effect);

            let receipt = TransactionReceipt {
                tx_hash: raw_tx_hash,
                // TODO: instead of re-serializing, we should just save the raw tx before decoding
                // https://github.com/chainwayxyz/citrea/issues/1045
                body_to_save: Some(borsh::to_vec(&tx).unwrap()),
                events,
                receipt: tx_effect,
            };

            tx_receipts.push(receipt);
            // We commit after events have been extracted into receipt.
            sc_workspace = sc_workspace.checkpoint().to_revertable();

            // TODO: `panic` will be covered in https://github.com/Sovereign-Labs/sovereign-sdk/issues/421
            // TODO: Check if we need to put this in end_soft_onfirmation, becuase I am not sure if we can call pre_dispatch again for new txs after this
            self.runtime
                .post_dispatch_tx_hook(&tx, &ctx, &mut sc_workspace)
                .expect("inconsistent state: error in post_dispatch_tx_hook");
        }
        (sc_workspace, tx_receipts)
    }

    /// Begins the inner processes of applying soft confirmation
    /// Module hooks are called here
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    pub fn begin_soft_confirmation_inner(
        &self,
        mut batch_workspace: WorkingSet<C>,
        soft_confirmation_info: &HookSoftConfirmationInfo,
    ) -> (Result<(), SoftConfirmationError>, WorkingSet<C>) {
        native_debug!(
            "Beginning soft confirmation #{} from sequencer: 0x{}",
            soft_confirmation_info.l2_height(),
            hex::encode(soft_confirmation_info.sequencer_pub_key())
        );

        // ApplySoftConfirmationHook: begin
        if let Err(e) = self
            .runtime
            .begin_soft_confirmation_hook(soft_confirmation_info, &mut batch_workspace)
        {
            native_error!(
                "Error: The batch was rejected by the 'begin_soft_confirmation_hook'. Skipping batch with error: {:?}",
                e
            );

            return (
                Err(e),
                // Reverted in apply_soft_confirmation and sequencer
                batch_workspace,
            );
        }

        // Write changes from begin_blob_hook
        batch_workspace = batch_workspace.checkpoint().to_revertable();

        (Ok(()), batch_workspace)
    }

    /// Ends the inner processes of applying soft confirmation
    /// Module hooks are called here
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    pub fn end_soft_confirmation_inner(
        &self,
        soft_confirmation: &mut SignedSoftConfirmation,
        tx_receipts: Vec<TransactionReceipt<TxEffect>>,
        mut batch_workspace: WorkingSet<C>,
    ) -> (ApplySoftConfirmationResult<Da>, StateCheckpoint<C>) {
        if let Err(e) = self
            .runtime
            .end_soft_confirmation_hook(&mut batch_workspace)
        {
            // TODO: will be covered in https://github.com/Sovereign-Labs/sovereign-sdk/issues/421
            native_error!("Failed on `end_soft_confirmation_hook`: {:?}", e);

            return (Err(e), batch_workspace.revert());
        };

        (
            Ok(SoftConfirmationReceipt {
                l2_height: soft_confirmation.l2_height(),
                hash: soft_confirmation.hash(),
                prev_hash: soft_confirmation.prev_hash(),
                tx_receipts,
                da_slot_height: soft_confirmation.da_slot_height(),
                da_slot_hash: soft_confirmation.da_slot_hash().into(),
                da_slot_txs_commitment: soft_confirmation.da_slot_txs_commitment().into(),
                soft_confirmation_signature: soft_confirmation.signature().to_vec(),
                pub_key: soft_confirmation.sequencer_pub_key().to_vec(),
                deposit_data: soft_confirmation.deposit_data().clone(),
                l1_fee_rate: soft_confirmation.l1_fee_rate(),
                timestamp: soft_confirmation.timestamp(),
            }),
            batch_workspace.checkpoint(),
        )
    }

    // Stateless verification of transaction, such as signature check
    // Single malformed transaction results in sequencer slashing.
    fn verify_txs_stateless_soft(&self, txs: Vec<Vec<u8>>) -> Vec<TransactionAndRawHash<C>> {
        verify_txs_stateless(
            txs.into_iter()
                .map(|tx| RawTx { data: tx })
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

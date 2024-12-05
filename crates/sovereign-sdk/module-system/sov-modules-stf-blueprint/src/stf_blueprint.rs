use std::marker::PhantomData;
use std::vec;

use borsh::BorshDeserialize;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{
    native_debug, native_error, Context, DaSpec, Spec, SpecId, StateCheckpoint, WorkingSet,
};
use sov_rollup_interface::digest::Digest;
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmation;
use sov_rollup_interface::stf::{
    SoftConfirmationError, SoftConfirmationHookError, SoftConfirmationReceipt,
    StateTransitionError, StateTransitionFunction, TransactionDigest, TransactionReceipt,
};
#[cfg(feature = "native")]
use tracing::instrument;

use crate::{Runtime, RuntimeTxHook, TxEffect};

/// An implementation of the
/// [`StateTransitionFunction`](sov_rollup_interface::stf::StateTransitionFunction)
/// that is specifically designed to work with the module-system.
pub struct StfBlueprint<C: Context, Da: DaSpec, RT: Runtime<C, Da>> {
    /// State storage used by the rollup.
    /// The runtime includes all the modules that the rollup supports.
    pub(crate) runtime: RT,
    phantom_context: PhantomData<C>,
    phantom_da: PhantomData<Da>,
}

type EndSoftConfirmationResult<Da> =
    Result<SoftConfirmationReceipt<TxEffect, Da>, SoftConfirmationHookError>;

impl<C, Da, RT> Default for StfBlueprint<C, Da, RT>
where
    C: Context,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<C, Da, RT> StfBlueprint<C, Da, RT>
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
            phantom_da: PhantomData,
        }
    }

    /// Applies sov txs to the state
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    pub fn apply_sov_txs_inner(
        &mut self,
        soft_confirmation_info: HookSoftConfirmationInfo,
        txs: &[Vec<u8>],
        txs_new: &[<Self as StateTransitionFunction<Da>>::Transaction],
        sc_workspace: &mut WorkingSet<C>,
    ) -> Result<Vec<TransactionReceipt<TxEffect>>, StateTransitionError> {
        // TODO: fix sov-tx related error handling

        let mut tx_receipts = Vec::with_capacity(txs.len());
        let txs: Vec<_> = if soft_confirmation_info.current_spec >= SpecId::Fork1 {
            txs_new
                .iter()
                .map(|tx| {
                    let digest = tx.compute_digest::<<C as Spec>::Hasher>();
                    let raw_tx_hash: [u8; 32] = digest.into();
                    (raw_tx_hash, tx.clone())
                })
                .collect()
        } else {
            let mut deserialized_txs = vec![];

            for raw_tx in txs {
                let raw_tx_hash = <C as Spec>::Hasher::digest(raw_tx).into();
                // Stateless verification of transaction, such as signature check
                // TODO: https://github.com/chainwayxyz/citrea/issues/1061
                let mut reader = std::io::Cursor::new(raw_tx);
                let tx = Transaction::<C>::deserialize_reader(&mut reader).map_err(|_| {
                    StateTransitionError::SoftConfirmationError(
                        SoftConfirmationError::NonSerializableSovTx,
                    )
                })?;
                deserialized_txs.push((raw_tx_hash, tx));
            }

            deserialized_txs
        };

        for (raw_tx_hash, tx) in txs {
            tx.verify().map_err(|_| {
                StateTransitionError::SoftConfirmationError(
                    SoftConfirmationError::InvalidSovTxSignature,
                )
            })?;
            // Checks that runtime message can be decoded from transaction.
            // If a single message cannot be decoded, sequencer is slashed
            let msg = RT::decode_call(tx.runtime_msg()).map_err(|_| {
                StateTransitionError::SoftConfirmationError(
                    SoftConfirmationError::SovTxCantBeRuntimeDecoded,
                )
            })?;

            // Dispatching transactions

            // Pre dispatch hook
            // TODO set the sequencer pubkey
            let hook = RuntimeTxHook {
                height: soft_confirmation_info.l2_height(),
                sequencer: tx.pub_key().clone(),
                current_spec: soft_confirmation_info.current_spec(),
                l1_fee_rate: soft_confirmation_info.l1_fee_rate(),
            };
            let ctx = self
                .runtime
                .pre_dispatch_tx_hook(&tx, sc_workspace, &hook)
                .map_err(StateTransitionError::HookError)?;
            // Commit changes after pre_dispatch_tx_hook
            // sc_workspace = sc_workspace.checkpoint().to_revertable();

            let _ = self
                .runtime
                .dispatch_call(msg, sc_workspace, &ctx)
                .map_err(StateTransitionError::ModuleCallError)?;

            let receipt = TransactionReceipt {
                tx_hash: raw_tx_hash,
                events: vec![],
                receipt: TxEffect::Successful,
            };

            tx_receipts.push(receipt);
            // We commit after events have been extracted into receipt.
            // sc_workspace = sc_workspace.checkpoint().to_revertable();

            self.runtime
                .post_dispatch_tx_hook(&tx, &ctx, sc_workspace)
                .map_err(StateTransitionError::HookError)?;
        }
        Ok(tx_receipts)
    }

    /// Begins the inner processes of applying soft confirmation
    /// Module hooks are called here
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    pub fn begin_soft_confirmation_inner(
        &mut self,
        mut batch_workspace: WorkingSet<C>,
        soft_confirmation_info: &HookSoftConfirmationInfo,
    ) -> Result<WorkingSet<C>, SoftConfirmationHookError> {
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
                "Error: The batch was rejected by the 'begin_soft_confirmation_hook'. Skipping batch with error: {:?}\nReverting batch workspace",
                e
            );
            batch_workspace.revert();
            return Err(e);
        }

        // Write changes from begin_soft_confirmation_hook
        batch_workspace = batch_workspace.checkpoint().to_revertable();

        Ok(batch_workspace)
    }

    /// Ends the inner processes of applying soft confirmation
    /// Module hooks are called here
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    pub fn end_soft_confirmation_inner(
        &mut self,
        current_spec: SpecId,
        pre_state_root: Vec<u8>,
        soft_confirmation: &mut SignedSoftConfirmation<
            <Self as StateTransitionFunction<Da>>::Transaction,
        >,
        tx_receipts: Vec<TransactionReceipt<TxEffect>>,
        mut batch_workspace: WorkingSet<C>,
    ) -> (EndSoftConfirmationResult<Da>, StateCheckpoint<C>) {
        let hook_soft_confirmation_info =
            HookSoftConfirmationInfo::new(soft_confirmation, pre_state_root, current_spec);

        if let Err(e) = self
            .runtime
            .end_soft_confirmation_hook(hook_soft_confirmation_info, &mut batch_workspace)
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
                deposit_data: soft_confirmation.deposit_data().to_vec(),
                l1_fee_rate: soft_confirmation.l1_fee_rate(),
                timestamp: soft_confirmation.timestamp(),
            }),
            batch_workspace.checkpoint(),
        )
    }
}

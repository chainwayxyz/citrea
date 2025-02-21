use std::marker::PhantomData;

use borsh::BorshDeserialize;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::transaction::{PreFork2Transaction, Transaction};
use sov_modules_api::{native_debug, native_error, Context, DaSpec, SpecId, WorkingSet};
use sov_rollup_interface::stf::{
    SoftConfirmationError, SoftConfirmationHookError, StateTransitionError,
};
#[cfg(feature = "native")]
use tracing::instrument;

use crate::{Runtime, RuntimeTxHook};

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
        soft_confirmation_info: &HookSoftConfirmationInfo,
        blobs: &[Vec<u8>],
        txs: &[Transaction],
        sc_workspace: &mut WorkingSet<C::Storage>,
    ) -> Result<(), StateTransitionError> {
        if soft_confirmation_info.current_spec >= SpecId::Kumquat {
            for tx in txs {
                self.apply_sov_tx_inner(soft_confirmation_info, tx, sc_workspace)?;
            }
        } else {
            for raw_tx in blobs {
                // Stateless verification of transaction, such as signature check
                let mut reader = std::io::Cursor::new(raw_tx);
                let tx =
                    PreFork2Transaction::<C>::deserialize_reader(&mut reader).map_err(|_| {
                        StateTransitionError::SoftConfirmationError(
                            SoftConfirmationError::NonSerializableSovTx,
                        )
                    })?;

                self.apply_sov_tx_inner(soft_confirmation_info, &tx.into(), sc_workspace)?;
            }
        };

        Ok(())
    }

    fn apply_sov_tx_inner(
        &mut self,
        soft_confirmation_info: &HookSoftConfirmationInfo,
        tx: &Transaction,
        sc_workspace: &mut WorkingSet<C::Storage>,
    ) -> Result<(), StateTransitionError> {
        let current_spec = soft_confirmation_info.current_spec();

        tx.verify(current_spec).map_err(|_| {
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
        let hook = RuntimeTxHook {
            height: soft_confirmation_info.l2_height(),
            current_spec: soft_confirmation_info.current_spec(),
            l1_fee_rate: soft_confirmation_info.l1_fee_rate(),
        };
        let ctx = self
            .runtime
            .pre_dispatch_tx_hook(tx, sc_workspace, &hook, current_spec)
            .map_err(StateTransitionError::HookError)?;

        let _ = self
            .runtime
            .dispatch_call(msg, sc_workspace, &ctx)
            .map_err(StateTransitionError::ModuleCallError)?;

        self.runtime
            .post_dispatch_tx_hook(tx, &ctx, sc_workspace, current_spec)
            .map_err(StateTransitionError::HookError)?;

        Ok(())
    }

    /// Begins the inner processes of applying soft confirmation
    /// Module hooks are called here
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    pub fn begin_soft_confirmation_inner(
        &mut self,
        working_set: &mut WorkingSet<C::Storage>,
        soft_confirmation_info: &HookSoftConfirmationInfo,
    ) -> Result<(), SoftConfirmationHookError> {
        native_debug!(
            "Beginning soft confirmation #{} from sequencer: 0x{}",
            soft_confirmation_info.l2_height(),
            hex::encode(soft_confirmation_info.sequencer_pub_key())
        );

        // ApplySoftConfirmationHook: begin
        self.runtime
            .begin_soft_confirmation_hook(soft_confirmation_info, working_set)
    }

    /// Ends the inner processes of applying soft confirmation
    /// Module hooks are called here
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    pub fn end_soft_confirmation_inner(
        &mut self,
        hook_soft_confirmation_info: HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), SoftConfirmationHookError> {
        if let Err(e) = self
            .runtime
            .end_soft_confirmation_hook(hook_soft_confirmation_info, working_set)
        {
            // TODO: will be covered in https://github.com/Sovereign-Labs/sovereign-sdk/issues/421
            native_error!("Failed on `end_soft_confirmation_hook`: {:?}", e);
            return Err(e);
        };

        Ok(())
    }
}

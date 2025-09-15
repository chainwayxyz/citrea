use std::marker::PhantomData;

use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::{native_debug, native_error, Context, DaSpec, WorkingSet};
use sov_rollup_interface::stf::{L2BlockError, L2BlockHookError, StateTransitionError};
use sov_rollup_interface::transaction::Transaction;
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
        l2_block_info: &HookL2BlockInfo,
        txs: &[Transaction],
        sc_workspace: &mut WorkingSet<C::Storage>,
    ) -> Result<(), StateTransitionError> {
        for tx in txs {
            self.apply_sov_tx_inner(l2_block_info, tx, sc_workspace)?;
        }

        Ok(())
    }

    fn apply_sov_tx_inner(
        &mut self,
        l2_block_info: &HookL2BlockInfo,
        tx: &Transaction,
        sc_workspace: &mut WorkingSet<C::Storage>,
    ) -> Result<(), StateTransitionError> {
        let current_spec = l2_block_info.current_spec();

        tx.verify()
            .map_err(|_| StateTransitionError::L2BlockError(L2BlockError::InvalidSovTxSignature))?;
        // Checks that runtime message can be decoded from transaction.
        // If a single message cannot be decoded, sequencer is slashed
        let msg = RT::decode_call(tx.runtime_msg()).map_err(|_| {
            StateTransitionError::L2BlockError(L2BlockError::SovTxCantBeRuntimeDecoded)
        })?;

        // Dispatching transactions

        // Pre dispatch hook
        let hook = RuntimeTxHook {
            height: l2_block_info.l2_height(),
            current_spec: l2_block_info.current_spec(),
            l1_fee_rate: l2_block_info.l1_fee_rate(),
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

    /// Begins the inner processes of applying l2 block
    /// Module hooks are called here
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    pub fn begin_l2_block_inner(
        &mut self,
        working_set: &mut WorkingSet<C::Storage>,
        l2_block_info: &HookL2BlockInfo,
    ) -> Result<(), L2BlockHookError> {
        native_debug!(
            "Beginning l2 block #{} from sequencer: 0x{}",
            l2_block_info.l2_height(),
            l2_block_info.sequencer_pub_key()
        );

        // ApplyL2BlockHook: begin
        self.runtime.begin_l2_block_hook(l2_block_info, working_set)
    }

    /// Ends the inner processes of applying l2 block
    /// Module hooks are called here
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all))]
    pub fn end_l2_block_inner(
        &mut self,
        hook_l2_block_info: HookL2BlockInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), L2BlockHookError> {
        if let Err(e) = self
            .runtime
            .end_l2_block_hook(hook_l2_block_info, working_set)
        {
            // TODO: will be covered in https://github.com/Sovereign-Labs/sovereign-sdk/issues/421
            native_error!("Failed on `end_l2_block_hook`: {:?}", e);
            return Err(e);
        };

        Ok(())
    }
}

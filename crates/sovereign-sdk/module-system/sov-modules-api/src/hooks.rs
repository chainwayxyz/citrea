use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_modules_core::{AccessoryWorkingSet, Context, Spec, Storage, WorkingSet};
use sov_rollup_interface::da::DaSpec;
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmation;
use sov_rollup_interface::spec::SpecId;
pub use sov_rollup_interface::stf::SoftConfirmationError;
use sov_rollup_interface::stf::SoftConfirmationHookError;

use crate::transaction::Transaction;

/// Hooks that execute within the `StateTransitionFunction::apply_blob` function for each processed transaction.
///
/// The arguments consist of expected concretely implemented associated types for the hooks. At
/// runtime, compatible implementations are selected and utilized by the system to construct its
/// setup procedures and define post-execution routines.
pub trait TxHooks {
    type Context: Context;
    type PreArg;
    type PreResult;

    /// Runs just before a transaction is dispatched to an appropriate module.
    fn pre_dispatch_tx_hook(
        &self,
        tx: &Transaction<Self::Context>,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
        arg: &Self::PreArg,
    ) -> Result<Self::PreResult, SoftConfirmationHookError>;

    /// Runs after the tx is dispatched to an appropriate module.
    /// IF this hook returns error rollup panics
    fn post_dispatch_tx_hook(
        &self,
        tx: &Transaction<Self::Context>,
        ctx: &Self::Context,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    ) -> Result<(), SoftConfirmationHookError>;
}

/// Hooks that are executed before and after a soft confirmation is processed.
pub trait ApplySoftConfirmationHooks<Da: DaSpec> {
    type Context: Context;
    type SoftConfirmationResult;

    /// Runs at the beginning of apply_soft_confirmation.
    /// If this hook returns Err, batch is not applied
    fn begin_soft_confirmation_hook(
        &mut self,
        soft_confirmation_info: &HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    ) -> Result<(), SoftConfirmationHookError>;

    /// Executes at the end of apply_blob and rewards or slashes the sequencer
    /// If this hook returns Err rollup panics
    fn end_soft_confirmation_hook(
        &mut self,
        soft_confirmation_info: HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    ) -> Result<(), SoftConfirmationHookError>;
}

/// Information about the soft confirmation block
/// Does not include txs because txs can be appended by the sequencer
#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Eq)]
pub struct HookSoftConfirmationInfo {
    /// L2 block height
    pub l2_height: u64,
    /// DA block this soft confirmation was given for
    pub da_slot_height: u64,
    /// DA block hash
    pub da_slot_hash: [u8; 32],
    /// DA block transactions commitment
    pub da_slot_txs_commitment: [u8; 32],
    /// Previous batch's pre state root
    pub pre_state_root: Vec<u8>,
    /// The current spec
    pub current_spec: SpecId,
    /// Public key of the sequencer
    pub pub_key: Vec<u8>,
    /// Deposit data from the L1 chain
    pub deposit_data: Vec<Vec<u8>>,
    /// L1 fee rate
    pub l1_fee_rate: u128,
    /// Timestamp
    pub timestamp: u64,
}

impl HookSoftConfirmationInfo {
    pub fn new<Tx: Clone>(
        signed_soft_confirmation: &SignedSoftConfirmation<Tx>,
        pre_state_root: Vec<u8>,
        current_spec: SpecId,
    ) -> Self {
        HookSoftConfirmationInfo {
            l2_height: signed_soft_confirmation.l2_height(),
            da_slot_height: signed_soft_confirmation.da_slot_height(),
            da_slot_hash: signed_soft_confirmation.da_slot_hash(),
            da_slot_txs_commitment: signed_soft_confirmation.da_slot_txs_commitment(),
            pre_state_root,
            current_spec,
            pub_key: signed_soft_confirmation.sequencer_pub_key().to_vec(),
            deposit_data: signed_soft_confirmation.deposit_data().to_vec(),
            l1_fee_rate: signed_soft_confirmation.l1_fee_rate(),
            timestamp: signed_soft_confirmation.timestamp(),
        }
    }
}

impl HookSoftConfirmationInfo {
    /// L2 block height
    pub fn l2_height(&self) -> u64 {
        self.l2_height
    }

    /// DA block to build on
    pub fn da_slot_hash(&self) -> [u8; 32] {
        self.da_slot_hash
    }

    /// DA block transactions commitment
    pub fn da_slot_txs_commitment(&self) -> [u8; 32] {
        self.da_slot_txs_commitment
    }

    /// Previous batch's pre state root
    pub fn pre_state_root(&self) -> Vec<u8> {
        self.pre_state_root.clone()
    }

    /// Active spec
    pub fn current_spec(&self) -> SpecId {
        self.current_spec
    }

    /// Public key of signer
    pub fn sequencer_pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    /// Borsh serialized data
    pub fn full_data(&mut self) -> Vec<u8> {
        borsh::to_vec(self).unwrap()
    }

    pub fn deposit_data(&self) -> Vec<Vec<u8>> {
        self.deposit_data.clone()
    }

    pub fn l1_fee_rate(&self) -> u128 {
        self.l1_fee_rate
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

/// Hooks that execute during the `StateTransitionFunction::begin_slot` and `end_slot` functions.
pub trait SlotHooks<Da: DaSpec> {
    type Context: Context;

    fn begin_slot_hook(
        &self,
        slot_header: &Da::BlockHeader,
        pre_state_root: &<<Self::Context as Spec>::Storage as Storage>::Root,
        working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>,
    );

    fn end_slot_hook(&self, working_set: &mut WorkingSet<<Self::Context as Spec>::Storage>);
}

pub trait FinalizeHook<Da: DaSpec> {
    type Context: Context;

    fn finalize_hook(
        &self,
        root_hash: &<<Self::Context as Spec>::Storage as Storage>::Root,
        accessory_working_set: &mut AccessoryWorkingSet<<Self::Context as Spec>::Storage>,
    );
}

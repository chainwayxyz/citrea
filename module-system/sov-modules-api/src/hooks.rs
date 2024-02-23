use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_modules_core::{AccessoryWorkingSet, Context, Spec, Storage, WorkingSet};
use sov_rollup_interface::da::{BlobReaderTrait, DaSpec};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmationBatch;

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
        working_set: &mut WorkingSet<Self::Context>,
        arg: &Self::PreArg,
    ) -> anyhow::Result<Self::PreResult>;

    /// Runs after the tx is dispatched to an appropriate module.
    /// IF this hook returns error rollup panics
    fn post_dispatch_tx_hook(
        &self,
        tx: &Transaction<Self::Context>,
        ctx: &Self::Context,
        working_set: &mut WorkingSet<Self::Context>,
    ) -> anyhow::Result<()>;
}

/// Hooks related to the Sequencer functionality.
/// In essence, the sequencer locks a bond at the beginning of the `StateTransitionFunction::apply_blob`,
/// and is rewarded once a blob of transactions is processed.
pub trait ApplyBlobHooks<B: BlobReaderTrait> {
    type Context: Context;
    type BlobResult;

    /// Runs at the beginning of apply_blob, locks the sequencer bond.
    /// If this hook returns Err, batch is not applied
    fn begin_blob_hook(
        &self,
        blob: &mut B,
        working_set: &mut WorkingSet<Self::Context>,
    ) -> anyhow::Result<()>;

    /// Executes at the end of apply_blob and rewards or slashes the sequencer
    /// If this hook returns Err rollup panics
    fn end_blob_hook(
        &self,
        result: Self::BlobResult,
        working_set: &mut WorkingSet<Self::Context>,
    ) -> anyhow::Result<()>;
}

/// Hooks that are executed before and after a soft confirmation is processed.
pub trait ApplySoftConfirmationHooks<Da: DaSpec> {
    type Context: Context;
    type SoftConfirmationResult;

    /// Runs at the beginning of apply_soft_confirmation.
    /// If this hook returns Err, batch is not applied
    fn begin_soft_confirmation_hook(
        &self,
        soft_batch: &mut HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<Self::Context>,
    ) -> anyhow::Result<()>;

    /// Executes at the end of apply_blob and rewards or slashes the sequencer
    /// If this hook returns Err rollup panics
    fn end_soft_confirmation_hook(
        &self,
        result: Self::SoftConfirmationResult,
        working_set: &mut WorkingSet<Self::Context>,
    ) -> anyhow::Result<()>;
}

/// Information about the soft confirmation block
/// Does not include txs because txs can be appended by the sequencer
#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Eq)]
pub struct HookSoftConfirmationInfo {
    /// DA block this soft confirmation was given for
    pub da_slot_height: u64,
    /// DA block hash
    pub da_slot_hash: [u8; 32],
    /// Previous batch's post state root
    pub pre_state_root: Vec<u8>,
    /// Public key of signer
    pub pub_key: Vec<u8>,
    /// L1 fee rate
    pub l1_fee_rate: u64,
}

impl From<SignedSoftConfirmationBatch> for HookSoftConfirmationInfo {
    fn from(signed_soft_confirmation_batch: SignedSoftConfirmationBatch) -> Self {
        HookSoftConfirmationInfo {
            da_slot_height: signed_soft_confirmation_batch.da_slot_height(),
            da_slot_hash: signed_soft_confirmation_batch.da_slot_hash(),
            pre_state_root: signed_soft_confirmation_batch.pre_state_root(),
            pub_key: signed_soft_confirmation_batch.sequencer_pub_key().to_vec(),
            l1_fee_rate: signed_soft_confirmation_batch.l1_fee_rate(),
        }
    }
}

impl From<HookSoftConfirmationInfo> for SignedSoftConfirmationBatch {
    fn from(val: HookSoftConfirmationInfo) -> Self {
        SignedSoftConfirmationBatch::new(
            [0u8; 32],
            val.da_slot_height,
            val.da_slot_hash(),
            val.pre_state_root(),
            val.l1_fee_rate,
            vec![],
            vec![],
            val.pub_key.clone(),
        )
    }
}

impl HookSoftConfirmationInfo {
    /// DA block to build on
    pub fn da_slot_hash(&self) -> [u8; 32] {
        self.da_slot_hash
    }

    /// Previous batch's post state root
    pub fn pre_state_root(&self) -> Vec<u8> {
        self.pre_state_root.clone()
    }

    /// Public key of signer
    pub fn sequencer_pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    /// Borsh serialized data
    pub fn full_data(&mut self) -> Vec<u8> {
        self.try_to_vec().unwrap()
    }

    pub fn l1_fee_rate(&self) -> u64 {
        self.l1_fee_rate
    }
}

/// Hooks that execute during the `StateTransitionFunction::begin_slot` and `end_slot` functions.
pub trait SlotHooks<Da: DaSpec> {
    type Context: Context;

    fn begin_slot_hook(
        &self,
        slot_header: &Da::BlockHeader,
        validity_condition: &Da::ValidityCondition,
        pre_state_root: &<<Self::Context as Spec>::Storage as Storage>::Root,
        working_set: &mut WorkingSet<Self::Context>,
    );

    fn end_slot_hook(&self, working_set: &mut WorkingSet<Self::Context>);
}

pub trait FinalizeHook<Da: DaSpec> {
    type Context: Context;

    fn finalize_hook(
        &self,
        root_hash: &<<Self::Context as Spec>::Storage as Storage>::Root,
        accessory_working_set: &mut AccessoryWorkingSet<Self::Context>,
    );
}

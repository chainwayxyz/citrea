use std::marker::PhantomData;

use sov_modules_api::hooks::SoftConfirmationError;
use sov_rollup_interface::da::DaSpec;
use sov_rollup_interface::fork::Fork;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::{
    BatchReceipt, SlotResult, SoftConfirmationResult, StateTransitionFunction,
};
use sov_rollup_interface::zk::{CumulativeStateDiff, ValidityCondition, Zkvm};

/// A mock implementation of the [`StateTransitionFunction`]
#[derive(PartialEq, Debug, Clone, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct MockStf<Cond> {
    phantom_data: PhantomData<Cond>,
}

impl<Vm: Zkvm, Cond: ValidityCondition, Da: DaSpec> StateTransitionFunction<Vm, Da>
    for MockStf<Cond>
{
    type StateRoot = [u8; 0];
    type GenesisParams = ();
    type PreState = ();
    type ChangeSet = ();
    type TxReceiptContents = ();
    type BatchReceiptContents = ();
    type Witness = ();
    type Condition = Cond;

    // Perform one-time initialization for the genesis block.
    fn init_chain(
        &self,
        _base_state: Self::PreState,
        _params: Self::GenesisParams,
    ) -> ([u8; 0], ()) {
        ([], ())
    }

    fn apply_slot<'a, I>(
        &self,
        _current_spec: SpecId,
        _pre_state_root: &[u8; 0],
        _base_state: Self::PreState,
        _witness: Self::Witness,
        _slot_header: &Da::BlockHeader,
        _validity_condition: &Da::ValidityCondition,
        _blobs: I,
    ) -> SlotResult<
        Self::StateRoot,
        Self::ChangeSet,
        Self::BatchReceiptContents,
        Self::TxReceiptContents,
        Self::Witness,
    >
    where
        I: IntoIterator<Item = &'a mut Da::BlobTransaction>,
    {
        SlotResult {
            state_root: [],
            change_set: (),
            batch_receipts: vec![BatchReceipt {
                hash: [0; 32],
                prev_hash: [0; 32],
                tx_receipts: vec![],
                phantom_data: PhantomData,
            }],
            witness: (),
            state_diff: vec![],
        }
    }

    fn apply_soft_confirmation(
        &self,
        _current_spec: SpecId,
        _sequencer_public_key: &[u8],
        _pre_state_root: &Self::StateRoot,
        _pre_state: Self::PreState,
        _witness: Self::Witness,
        _slot_header: &<Da as DaSpec>::BlockHeader,
        _validity_condition: &<Da as DaSpec>::ValidityCondition,
        _soft_confirmation: &mut sov_modules_api::SignedSoftConfirmationBatch,
    ) -> Result<
        SoftConfirmationResult<
            Self::StateRoot,
            Self::ChangeSet,
            Self::TxReceiptContents,
            Self::Witness,
            Da,
        >,
        SoftConfirmationError,
    > {
        todo!()
    }

    fn apply_soft_confirmations_from_sequencer_commitments(
        &self,
        _sequencer_public_key: &[u8],
        _sequencer_da_public_key: &[u8],
        _initial_state_root: &Self::StateRoot,
        _initial_batch_hash: [u8; 32],
        _pre_state: Self::PreState,
        _da_data: Vec<<Da as DaSpec>::BlobTransaction>,
        _sequencer_commitments_range: (u32, u32),
        _witnesses: std::collections::VecDeque<Vec<Self::Witness>>,
        _slot_headers: std::collections::VecDeque<Vec<<Da as DaSpec>::BlockHeader>>,
        _validity_condition: &<Da as DaSpec>::ValidityCondition,
        _soft_confirmations: std::collections::VecDeque<
            Vec<sov_modules_api::SignedSoftConfirmationBatch>,
        >,
        _preproven_commitment_indicies: Vec<usize>,
        _forks: Vec<Fork>,
    ) -> (Self::StateRoot, CumulativeStateDiff, SpecId) {
        todo!()
    }
}

#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
use std::marker::PhantomData;

use sha2::Digest;
use sov_rollup_interface::da::{BlobReaderTrait, DaSpec};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmationBatch;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::{BatchReceipt, SlotResult, StateTransitionFunction};
use sov_rollup_interface::zk::{CumulativeStateDiff, ValidityCondition, Zkvm};

/// An implementation of the [`StateTransitionFunction`]
/// that is specifically designed to check if someone knows a preimage of a specific hash.
#[derive(PartialEq, Debug, Clone, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct CheckHashPreimageStf<Cond> {
    phantom_data: PhantomData<Cond>,
}

/// Outcome of the apply_slot method.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ApplySlotResult {
    /// Incorrect hash preimage was posted on the DA.
    Failure,
    /// Correct hash preimage was posted on the DA.
    Success,
}

impl<Vm: Zkvm, Cond: ValidityCondition, Da: DaSpec> StateTransitionFunction<Vm, Da>
    for CheckHashPreimageStf<Cond>
{
    // Since our rollup is stateless, we don't need to consider the StateRoot.
    type StateRoot = [u8; 0];

    // This represents the initial configuration of the rollup, but it is not supported in this tutorial.
    type GenesisParams = ();
    type PreState = ();
    type ChangeSet = ();

    // We could incorporate the concept of a transaction into the rollup, but we leave it as an exercise for the reader.
    type TxReceiptContents = ();

    // This is the type that will be returned as a result of `apply_blob`.
    type BatchReceiptContents = ApplySlotResult;

    // This data is produced during actual batch execution or validated with proof during verification.
    // However, in this tutorial, we won't use it.
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
        blobs: I,
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
        let mut receipts = vec![];
        for blob in blobs {
            let data = blob.verified_data();

            // Check if the sender submitted the preimage of the hash.
            let hash = sha2::Sha256::digest(data).into();
            let prev_hash = sha2::Sha256::digest(data).into();
            let desired_hash = [
                102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8,
                151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37,
            ];

            let _result = if hash == desired_hash {
                ApplySlotResult::Success
            } else {
                ApplySlotResult::Failure
            };

            // Return the `BatchReceipt`
            receipts.push(BatchReceipt::<ApplySlotResult, _> {
                hash,
                prev_hash,
                tx_receipts: vec![],
                phantom_data: PhantomData,
            });
        }

        SlotResult {
            state_root: [],
            change_set: (),
            batch_receipts: receipts,
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
        _soft_confirmation: &mut SignedSoftConfirmationBatch,
    ) -> SlotResult<
        Self::StateRoot,
        Self::ChangeSet,
        Self::BatchReceiptContents,
        Self::TxReceiptContents,
        Self::Witness,
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
        _soft_confirmation: std::collections::VecDeque<Vec<SignedSoftConfirmationBatch>>,
        _preproven_commitment_indicies: Vec<usize>,
        _forks: Vec<(SpecId, u64)>,
    ) -> (Self::StateRoot, CumulativeStateDiff) {
        todo!()
    }
}

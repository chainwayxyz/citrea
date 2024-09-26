#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use borsh::BorshDeserialize;
use itertools::Itertools;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::hooks::{
    ApplyBlobHooks, ApplySoftConfirmationHooks, FinalizeHook, HookSoftConfirmationInfo, SlotHooks,
    TxHooks,
};
use sov_modules_api::{
    native_debug, native_warn, BasicAddress, BlobReaderTrait, Context, DaSpec, DispatchCall,
    Genesis, Signature, Spec, StateCheckpoint, UnsignedSoftConfirmation, WorkingSet, Zkvm,
};
use sov_rollup_interface::da::{DaDataBatchProof, SequencerCommitment};
use sov_rollup_interface::digest::Digest;
use sov_rollup_interface::fork::{Fork, ForkManager};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmation;
use sov_rollup_interface::spec::SpecId;
pub use sov_rollup_interface::stf::{BatchReceipt, TransactionReceipt};
use sov_rollup_interface::stf::{
    SlotResult, SoftConfirmationError, SoftConfirmationReceipt, SoftConfirmationResult,
    StateTransitionFunction,
};
use sov_rollup_interface::zk::CumulativeStateDiff;
use sov_state::Storage;

mod batch;
mod stf_blueprint;
mod tx_verifier;

pub use batch::Batch;
pub use stf_blueprint::StfBlueprint;
pub use tx_verifier::RawTx;

/// The tx hook for a blueprint runtime
pub struct RuntimeTxHook<C: Context> {
    /// Height to initialize the context
    pub height: u64,
    /// Sequencer public key
    pub sequencer: C::PublicKey,
    /// Current spec
    pub current_spec: SpecId,
    /// L1 fee rate
    pub l1_fee_rate: u128,
}

/// This trait has to be implemented by a runtime in order to be used in `StfBlueprint`.
///
/// The `TxHooks` implementation sets up a transaction context based on the height at which it is
/// to be executed.
pub trait Runtime<C: Context, Da: DaSpec>:
    DispatchCall<Context = C>
    + Genesis<Context = C, Config = Self::GenesisConfig>
    + TxHooks<Context = C, PreArg = RuntimeTxHook<C>, PreResult = C>
    + SlotHooks<Da, Context = C>
    + FinalizeHook<Da, Context = C>
    + ApplySoftConfirmationHooks<
        Da,
        Context = C,
        SoftConfirmationResult = SequencerOutcome<
            <<Da as DaSpec>::BlobTransaction as BlobReaderTrait>::Address,
        >,
    > + ApplyBlobHooks<
        Da::BlobTransaction,
        Context = C,
        BlobResult = SequencerOutcome<
            <<Da as DaSpec>::BlobTransaction as BlobReaderTrait>::Address,
        >,
    > + Default
{
    /// GenesisConfig type.
    type GenesisConfig: Send + Sync;

    #[cfg(feature = "native")]
    /// GenesisPaths type.
    type GenesisPaths: Send + Sync;

    #[cfg(feature = "native")]
    /// Default rpc methods.
    fn rpc_methods(storage: <C as Spec>::Storage) -> jsonrpsee::RpcModule<()>;

    #[cfg(feature = "native")]
    /// Reads genesis configs.
    fn genesis_config(
        genesis_paths: &Self::GenesisPaths,
    ) -> Result<Self::GenesisConfig, anyhow::Error>;
}

/// The receipts of all the transactions in a batch.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TxEffect {
    /// Batch was reverted.
    Reverted,
    /// Batch was processed successfully.
    Successful,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
/// Represents the different outcomes that can occur for a sequencer after batch processing.
pub enum SequencerOutcome<A: BasicAddress> {
    /// Sequencer receives reward amount in defined token and can withdraw its deposit
    Rewarded(u64),
    /// Sequencer loses its deposit and receives no reward
    Slashed {
        /// Reason why sequencer was slashed.
        reason: SlashingReason,
        #[serde(bound(deserialize = ""))]
        /// Sequencer address on DA.
        sequencer_da_address: A,
    },
    /// Batch was ignored, sequencer deposit left untouched.
    Ignored,
}

/// Genesis parameters for a blueprint
pub struct GenesisParams<RT> {
    /// The runtime genesis parameters
    pub runtime: RT,
}

/// Reason why sequencer was slashed.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SlashingReason {
    /// This status indicates problem with batch deserialization.
    InvalidBatchEncoding,
    /// Stateless verification failed, for example deserialized transactions have invalid signatures.
    StatelessVerificationFailed,
    /// This status indicates problem with transaction deserialization.
    InvalidTransactionEncoding,
}

/// Trait for soft confirmation handling
pub trait StfBlueprintTrait<C: Context, Da: DaSpec, Vm: Zkvm>:
    StateTransitionFunction<Vm, Da>
{
    /// Begin a soft confirmation
    #[allow(clippy::too_many_arguments)]
    fn begin_soft_confirmation(
        &mut self,
        sequencer_public_key: &[u8],
        pre_state: Self::PreState,
        witness: <<C as Spec>::Storage as Storage>::Witness,
        slot_header: &<Da as DaSpec>::BlockHeader,
        soft_confirmation_info: &HookSoftConfirmationInfo,
    ) -> (Result<(), SoftConfirmationError>, WorkingSet<C>);

    /// Apply soft confirmation transactions
    fn apply_soft_confirmation_txs(
        &mut self,
        soft_confirmation: HookSoftConfirmationInfo,
        txs: Vec<Vec<u8>>,
        batch_workspace: WorkingSet<C>,
    ) -> (WorkingSet<C>, Vec<TransactionReceipt<TxEffect>>);

    /// End a soft confirmation
    fn end_soft_confirmation(
        &mut self,
        current_spec: SpecId,
        pre_state_root: Vec<u8>,
        sequencer_public_key: &[u8],
        soft_confirmation: &mut SignedSoftConfirmation,
        tx_receipts: Vec<TransactionReceipt<TxEffect>>,
        batch_workspace: WorkingSet<C>,
    ) -> (
        Result<SoftConfirmationReceipt<TxEffect, Da>, SoftConfirmationError>,
        StateCheckpoint<C>,
    );

    /// Finalizes a soft confirmation
    fn finalize_soft_confirmation(
        &self,
        current_spec: SpecId,
        sc_receipt: SoftConfirmationReceipt<TxEffect, Da>,
        checkpoint: StateCheckpoint<C>,
        pre_state: Self::PreState,
        soft_confirmation: &mut SignedSoftConfirmation,
    ) -> SoftConfirmationResult<
        Self::StateRoot,
        Self::ChangeSet,
        Self::TxReceiptContents,
        Self::Witness,
        Da,
    >;
}

impl<C, RT, Vm, Da> StfBlueprintTrait<C, Da, Vm> for StfBlueprint<C, Da, Vm, RT>
where
    C: Context,
    Vm: Zkvm,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    fn begin_soft_confirmation(
        &mut self,
        sequencer_public_key: &[u8],
        pre_state: <C>::Storage,
        witness: <<C as Spec>::Storage as Storage>::Witness,
        slot_header: &<Da as DaSpec>::BlockHeader,
        soft_confirmation_info: &HookSoftConfirmationInfo,
    ) -> (Result<(), SoftConfirmationError>, WorkingSet<C>) {
        native_debug!("Applying soft confirmation in STF Blueprint");

        let checkpoint = StateCheckpoint::with_witness(pre_state, witness);
        let batch_workspace = checkpoint.to_revertable();

        // check if soft confirmation is coming from our sequencer
        if soft_confirmation_info.sequencer_pub_key() != sequencer_public_key {
            return (
                Err(SoftConfirmationError::SequencerPublicKeyMismatch),
                batch_workspace,
            );
        };

        // then verify da hashes match
        if soft_confirmation_info.da_slot_hash() != slot_header.hash().into() {
            return (Err(SoftConfirmationError::InvalidDaHash), batch_workspace);
        }

        // then verify da transactions commitment match
        if soft_confirmation_info.da_slot_txs_commitment() != slot_header.txs_commitment().into() {
            return (
                Err(SoftConfirmationError::InvalidDaTxsCommitment),
                batch_workspace,
            );
        }

        self.begin_soft_confirmation_inner(batch_workspace, soft_confirmation_info)
    }

    fn apply_soft_confirmation_txs(
        &mut self,
        soft_confirmation_info: HookSoftConfirmationInfo,
        txs: Vec<Vec<u8>>,
        batch_workspace: WorkingSet<C>,
    ) -> (WorkingSet<C>, Vec<TransactionReceipt<TxEffect>>) {
        self.apply_sov_txs_inner(soft_confirmation_info, txs, batch_workspace)
    }

    fn end_soft_confirmation(
        &mut self,
        current_spec: SpecId,
        pre_state_root: Vec<u8>,
        sequencer_public_key: &[u8],
        soft_confirmation: &mut SignedSoftConfirmation,
        tx_receipts: Vec<TransactionReceipt<TxEffect>>,
        batch_workspace: WorkingSet<C>,
    ) -> (
        Result<SoftConfirmationReceipt<TxEffect, Da>, SoftConfirmationError>,
        StateCheckpoint<C>,
    ) {
        let unsigned = UnsignedSoftConfirmation::new(
            soft_confirmation.l2_height(),
            soft_confirmation.da_slot_height(),
            soft_confirmation.da_slot_hash(),
            soft_confirmation.da_slot_txs_commitment(),
            soft_confirmation.txs(),
            soft_confirmation.deposit_data(),
            soft_confirmation.l1_fee_rate(),
            soft_confirmation.timestamp(),
        );

        let unsigned_raw = borsh::to_vec(&unsigned).unwrap();

        // check the claimed hash
        if soft_confirmation.hash()
            != Into::<[u8; 32]>::into(<C as Spec>::Hasher::digest(unsigned_raw))
        {
            return (
                Err(SoftConfirmationError::InvalidSoftConfirmationHash),
                batch_workspace.revert(),
            );
        }

        // verify signature
        if verify_soft_confirmation_signature::<C>(
            unsigned,
            soft_confirmation.signature_as_ref(),
            sequencer_public_key,
        )
        .is_err()
        {
            return (
                Err(SoftConfirmationError::InvalidSoftConfirmationSignature),
                batch_workspace.revert(),
            );
        }

        self.end_soft_confirmation_inner(
            current_spec,
            pre_state_root,
            soft_confirmation,
            tx_receipts,
            batch_workspace,
        )
    }

    fn finalize_soft_confirmation(
        &self,
        _current_spec: SpecId,
        sc_receipt: SoftConfirmationReceipt<TxEffect, Da>,
        checkpoint: StateCheckpoint<C>,
        pre_state: Self::PreState,
        soft_confirmation: &mut SignedSoftConfirmation,
    ) -> SoftConfirmationResult<
        <C::Storage as Storage>::Root,
        C::Storage,
        TxEffect,
        <<C as Spec>::Storage as Storage>::Witness,
        Da,
    > {
        native_debug!(
            "soft confirmation with hash: {:?} from sequencer {:?} has been applied with #{} transactions.",
            soft_confirmation.hash(),
            soft_confirmation.sequencer_pub_key(),
            sc_receipt.tx_receipts.len(),
        );

        #[cfg(feature = "native")]
        for (i, tx_receipt) in sc_receipt.tx_receipts.iter().enumerate() {
            native_debug!(
                "tx #{} hash: 0x{} result {:?}",
                i,
                hex::encode(tx_receipt.tx_hash),
                tx_receipt.receipt
            );
        }

        let (state_root, witness, storage, state_diff) = {
            let working_set = checkpoint.to_revertable();
            // Save checkpoint
            let mut checkpoint = working_set.checkpoint();

            let (cache_log, mut witness) = checkpoint.freeze();

            let (root_hash, state_update, state_diff) = pre_state
                .compute_state_update(cache_log, &mut witness)
                .expect("jellyfish merkle tree update must succeed");

            let mut working_set = checkpoint.to_revertable();

            self.runtime
                .finalize_hook(&root_hash, &mut working_set.accessory_state());

            let mut checkpoint = working_set.checkpoint();
            let accessory_log = checkpoint.freeze_non_provable();

            pre_state.commit(&state_update, &accessory_log);

            (root_hash, witness, pre_state, state_diff)
        };

        SoftConfirmationResult {
            state_root,
            change_set: storage,
            witness,
            state_diff,
            soft_confirmation_receipt: sc_receipt,
        }
    }
}

impl<C, RT, Vm, Da> StateTransitionFunction<Vm, Da> for StfBlueprint<C, Da, Vm, RT>
where
    C: Context,
    Da: DaSpec,
    Vm: Zkvm,
    RT: Runtime<C, Da>,
{
    type StateRoot = <C::Storage as Storage>::Root;

    type GenesisParams = GenesisParams<<RT as Genesis>::Config>;
    type PreState = C::Storage;
    type ChangeSet = C::Storage;

    type TxReceiptContents = TxEffect;

    type BatchReceiptContents = ();
    // SequencerOutcome<<Da::BlobTransaction as BlobReaderTrait>::Address>;

    type Witness = <<C as Spec>::Storage as Storage>::Witness;

    type Condition = Da::ValidityCondition;

    fn init_chain(
        &self,
        pre_state: Self::PreState,
        params: Self::GenesisParams,
    ) -> (Self::StateRoot, Self::ChangeSet) {
        let mut working_set = StateCheckpoint::new(pre_state.clone()).to_revertable();

        self.runtime
            .genesis(&params.runtime, &mut working_set)
            .expect("Runtime initialization must succeed");

        let mut checkpoint = working_set.checkpoint();
        let (log, mut witness) = checkpoint.freeze();

        let (genesis_hash, state_update, _) = pre_state
            .compute_state_update(log, &mut witness)
            .expect("Storage update must succeed");

        let mut working_set = checkpoint.to_revertable();

        self.runtime
            .finalize_hook(&genesis_hash, &mut working_set.accessory_state());

        let accessory_log = working_set.checkpoint().freeze_non_provable();

        // TODO: Commit here for now, but probably this can be done outside of STF
        // TODO: Commit is fine
        pre_state.commit(&state_update, &accessory_log);

        (genesis_hash, pre_state)
    }

    fn apply_slot<'a, I>(
        &self,
        _current_spec: SpecId,
        _pre_state_root: &Self::StateRoot,
        _pre_state: Self::PreState,
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
        unimplemented!();
    }

    fn apply_soft_confirmation(
        &mut self,
        current_spec: SpecId,
        sequencer_public_key: &[u8],
        pre_state_root: &Self::StateRoot,
        pre_state: Self::PreState,
        witness: Self::Witness,
        slot_header: &<Da as DaSpec>::BlockHeader,
        _validity_condition: &<Da as DaSpec>::ValidityCondition,
        soft_confirmation: &mut SignedSoftConfirmation,
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
        let soft_confirmation_info = HookSoftConfirmationInfo::new(
            soft_confirmation.clone(),
            pre_state_root.as_ref().to_vec(),
            current_spec,
        );

        match self.begin_soft_confirmation(
            sequencer_public_key,
            pre_state.clone(),
            witness,
            slot_header,
            &soft_confirmation_info,
        ) {
            (Ok(()), batch_workspace) => {
                let (batch_workspace, tx_receipts) = self.apply_soft_confirmation_txs(
                    soft_confirmation_info,
                    soft_confirmation.txs(),
                    batch_workspace,
                );

                match self.end_soft_confirmation(
                    current_spec,
                    pre_state_root.as_ref().to_vec(),
                    sequencer_public_key,
                    soft_confirmation,
                    tx_receipts,
                    batch_workspace,
                ) {
                    (Ok(batch_receipt), checkpoint) => Ok(self.finalize_soft_confirmation(
                        current_spec,
                        batch_receipt,
                        checkpoint,
                        pre_state,
                        soft_confirmation,
                    )),
                    (Err(err), _checkpoint) => {
                        native_warn!(
                            "Error applying soft confirmation: {:?} \n reverting batch workspace",
                            err
                        );
                        Err(err)
                    }
                }
            }
            (Err(err), batch_workspace) => {
                native_warn!(
                    "Error applying soft confirmation: {:?} \n reverting batch workspace",
                    err
                );
                batch_workspace.revert();
                Err(err)
            }
        }
    }

    fn apply_soft_confirmations_from_sequencer_commitments(
        &mut self,
        sequencer_public_key: &[u8],
        sequencer_da_public_key: &[u8],
        initial_state_root: &Self::StateRoot,
        initial_batch_hash: [u8; 32],
        pre_state: Self::PreState,
        da_data: Vec<<Da as DaSpec>::BlobTransaction>,
        sequencer_commitments_range: (u32, u32),
        witnesses: std::collections::VecDeque<Vec<Self::Witness>>,
        slot_headers: std::collections::VecDeque<Vec<<Da as DaSpec>::BlockHeader>>,
        validity_condition: &<Da as DaSpec>::ValidityCondition,
        soft_confirmations: std::collections::VecDeque<Vec<SignedSoftConfirmation>>,
        mut preproven_commitment_indicies: Vec<usize>,
        forks: Vec<Fork>,
    ) -> (Self::StateRoot, CumulativeStateDiff, SpecId) {
        let mut state_diff = CumulativeStateDiff::default();

        // First extract all sequencer commitments
        // Ignore broken DaData and zk proofs. Also ignore ForcedTransaction's (will be implemented in the future).
        let mut sequencer_commitments: Vec<SequencerCommitment> = vec![];
        for blob in da_data {
            if blob.sender().as_ref() == sequencer_da_public_key {
                let da_data = DaDataBatchProof::try_from_slice(blob.verified_data());

                if let Ok(DaDataBatchProof::SequencerCommitment(commitment)) = da_data {
                    sequencer_commitments.push(commitment);
                }
            }
        }

        // A breakdown of why we sort the sequencer commitments, and why we need fields
        // `StateTransitionData::preproven_commitments` and `StateTransitionData::sequencer_commitment_range`:
        //
        // There is a chance of your "relevant transaction" being replayed on da layer, if the da layer does not have
        // a publickey-nonce check. To prevent from these attacks stopping our proving, we need to have a way to input the
        // the commitments we will ignore. This does not break any trust assumptions, as the zk circuit checks the
        // state transitions. So the prover can not leave out any commitments, beacuse it would break the state root checks
        // done by the zk circuit.
        //
        // If there is limitations on da on for the size of a single transaction (all blockchains have this), then
        // it's a good idea to allow proving of a single sequencer commitment at a time. Because more sequencer commmitments being
        // processed means there will be a bigger state diff. But sometimes it's efficient to
        // prove multiple commitments at a time. So we need to have a way to input the range of commitments we are proving.
        //
        // Now, why do we sort?
        //
        // Again, if the da layer doesn't have a publickey-nonce relation, there is a chance of sequencer commitment #10
        // landing on the da layer before sequencer commitment #9. If DA layer ordering is enforced in the zk circuit,
        // then this will break your rollup. So we need to sort the commitments by their l2_start_block_number, or something else.
        //
        // As long as the zk circuit and the prover (the entity providing the zk circuit inputs) are in agreement on the
        // ordering, the range of commitments, and which commitments to ignore, the zk circuit will be able to verify the state transition.
        //
        // Again, since the zk circuit verify the state transition, the prover can not leave out any commitments or change the ordering of
        // rollup state transitions.
        sequencer_commitments.sort();

        // TODO: filter in a better looking way maybe?
        // The preproven indicies are sorted by the prover when originally passed.
        // Therefore, we pass the commitments sequentially to make sure that the current
        // commitment index is not at the beginning of the list of preproven indicies.
        let mut filtered = vec![];
        for (index, sequencer_commitment) in sequencer_commitments.into_iter().enumerate() {
            if let Some(exclude_index) = preproven_commitment_indicies.first() {
                if index == *exclude_index {
                    preproven_commitment_indicies.remove(0);
                    continue;
                }
            }
            filtered.push(sequencer_commitment);
        }
        sequencer_commitments = filtered;

        // Then verify these soft confirmations.
        let mut current_state_root = initial_state_root.clone();
        let mut previous_batch_hash = initial_batch_hash;
        let mut last_commitment_end_height: Option<u64> = None;

        let mut fork_manager = ForkManager::new(forks, sequencer_commitments_range.0 as u64);

        // should panic if number of sequencer commitments, soft confirmations, slot headers and witnesses don't match
        for (((sequencer_commitment, soft_confirmations), da_block_headers), witnesses) in
            sequencer_commitments
                .into_iter()
                .skip(sequencer_commitments_range.0 as usize)
                .take(
                    sequencer_commitments_range.1 as usize - sequencer_commitments_range.0 as usize
                        + 1,
                )
                .zip_eq(soft_confirmations)
                .zip_eq(slot_headers)
                .zip_eq(witnesses)
        {
            // if the commitment is not sequential, then the proof is invalid.
            if let Some(end_height) = last_commitment_end_height {
                assert_eq!(
                    end_height + 1,
                    sequencer_commitment.l2_start_block_number,
                    "Sequencer commitments must be sequential"
                );

                last_commitment_end_height = Some(sequencer_commitment.l2_end_block_number);
            } else {
                last_commitment_end_height = Some(sequencer_commitment.l2_end_block_number);
            }

            // we must verify given DA headers match the commitments
            let mut index_headers = 0;
            let mut index_soft_confirmation = 0;
            let mut current_da_height = da_block_headers[index_headers].height();

            assert_eq!(
                soft_confirmations[index_soft_confirmation].prev_hash(),
                previous_batch_hash,
                "Soft confirmation previous hash must match the hash of the block before"
            );

            assert_eq!(
                soft_confirmations[index_soft_confirmation].da_slot_hash(),
                da_block_headers[index_headers].hash().into(),
                "Soft confirmation DA slot hash must match DA block header hash"
            );

            assert_eq!(
                soft_confirmations[index_soft_confirmation].da_slot_height(),
                da_block_headers[index_headers].height(),
                "Soft confirmation DA slot height must match DA block header height"
            );

            previous_batch_hash = soft_confirmations[index_soft_confirmation].hash();
            index_soft_confirmation += 1;

            while index_soft_confirmation < soft_confirmations.len() {
                // the soft confirmations DA hash must equal to da hash in index_headers
                // if it's not matching, and if it's not matching the next one, then state transition is invalid.

                if soft_confirmations[index_soft_confirmation].da_slot_hash()
                    == da_block_headers[index_headers].hash().into()
                {
                    assert_eq!(
                        soft_confirmations[index_soft_confirmation].da_slot_height(),
                        da_block_headers[index_headers].height(),
                        "Soft confirmation DA slot height must match DA block header height"
                    );

                    assert_eq!(
                        soft_confirmations[index_soft_confirmation].prev_hash(),
                        previous_batch_hash,
                        "Soft confirmation previous hash must match the hash of the block before"
                    );

                    previous_batch_hash = soft_confirmations[index_soft_confirmation].hash();
                    index_soft_confirmation += 1;
                } else {
                    index_headers += 1;

                    // this can also be done in soft confirmation rule enforcer?
                    assert_eq!(
                        da_block_headers[index_headers].height(),
                        current_da_height + 1,
                        "DA block headers must be in order"
                    );

                    assert_eq!(
                        da_block_headers[index_headers - 1].hash(),
                        da_block_headers[index_headers].prev_hash(),
                        "DA block headers must be in order"
                    );

                    current_da_height += 1;

                    // if the next one is not matching, then the state transition is invalid.
                    assert_eq!(
                        soft_confirmations[index_soft_confirmation].da_slot_hash(),
                        da_block_headers[index_headers].hash().into(),
                        "Soft confirmation DA slot hash must match DA block header hash"
                    );

                    assert_eq!(
                        soft_confirmations[index_soft_confirmation].da_slot_height(),
                        da_block_headers[index_headers].height(),
                        "Soft confirmation DA slot height must match DA block header height"
                    );

                    assert_eq!(
                        soft_confirmations[index_soft_confirmation].prev_hash(),
                        previous_batch_hash,
                        "Soft confirmation previous hash must match the hash of the block before"
                    );

                    previous_batch_hash = soft_confirmations[index_soft_confirmation].hash();
                    index_soft_confirmation += 1;
                }
            }

            // final da header was checked against
            assert_eq!(
                index_headers,
                da_block_headers.len() - 1,
                "All DA headers must be checked"
            );

            // now verify the claimed merkle root of soft confirmation hashes
            let mut soft_confirmation_hashes = vec![];

            for soft_confirmation in soft_confirmations.iter() {
                // given hashes will be checked inside apply_soft_confirmation.
                // so use the claimed hash for now.
                soft_confirmation_hashes.push(soft_confirmation.hash());
            }

            let calculated_root =
                MerkleTree::<Sha256>::from_leaves(soft_confirmation_hashes.as_slice()).root();

            assert_eq!(
                calculated_root,
                Some(sequencer_commitment.merkle_root),
                "Invalid merkle root"
            );

            let mut da_block_headers_iter = da_block_headers.into_iter().peekable();
            let mut da_block_header = da_block_headers_iter.next().unwrap();

            let mut l2_height = sequencer_commitment.l2_start_block_number;

            // now that we verified the claimed root, we can apply the soft confirmations
            // should panic if the number of witnesses and soft confirmations don't match
            for (mut soft_confirmation, witness) in soft_confirmations.into_iter().zip_eq(witnesses)
            {
                if soft_confirmation.da_slot_height() != da_block_header.height() {
                    da_block_header = da_block_headers_iter.next().unwrap();
                }

                assert_eq!(
                    soft_confirmation.l2_height(),
                    l2_height,
                    "Soft confirmation heights not sequential"
                );

                let result = self
                    .apply_soft_confirmation(
                        fork_manager.active_fork().spec_id,
                        sequencer_public_key,
                        &current_state_root,
                        pre_state.clone(),
                        witness,
                        &da_block_header,
                        validity_condition,
                        &mut soft_confirmation,
                    )
                    // TODO: this can be just ignoring the failing seq. com.
                    // We can count a failed soft confirmation as a valid state transition.
                    // for now we don't allow "broken" seq. com.s
                    .expect("Soft confirmation must succeed");

                current_state_root = result.state_root;
                state_diff.extend(result.state_diff);

                // Notify fork manager about the block so that the next spec / fork
                // is transitioned into if criteria is met.
                if let Err(e) = fork_manager.register_block(l2_height) {
                    panic!("Fork transition failed {}", e);
                }
                l2_height += 1;
            }
            assert_eq!(sequencer_commitment.l2_end_block_number, l2_height - 1);
        }

        (
            current_state_root,
            state_diff,
            fork_manager.active_fork().spec_id,
        )
    }
}

fn verify_soft_confirmation_signature<C: Context>(
    unsigned_soft_confirmation: UnsignedSoftConfirmation,
    signature: &[u8],
    sequencer_public_key: &[u8],
) -> Result<(), anyhow::Error> {
    let message = borsh::to_vec(&unsigned_soft_confirmation).unwrap();

    let signature = C::Signature::try_from(signature)?;

    // TODO: if verify function is modified to take the claimed hash in signed soft confirmation
    // we wouldn't need to hash the thing twice
    signature.verify(
        &C::PublicKey::try_from(sequencer_public_key)?,
        message.as_slice(),
    )?;

    Ok(())
}

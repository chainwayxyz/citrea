#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

mod batch;
mod stf_blueprint;
mod tx_verifier;

pub use batch::Batch;
use borsh::{BorshDeserialize, BorshSerialize};
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::hooks::{
    ApplyBlobHooks, ApplySoftConfirmationError, ApplySoftConfirmationHooks, FinalizeHook,
    SlotHooks, TxHooks,
};
use sov_modules_api::{
    BasicAddress, BlobReaderTrait, Context, DaSpec, DispatchCall, Genesis, Signature, Spec,
    StateCheckpoint, StateDiff, UnsignedSoftConfirmationBatch, WorkingSet, Zkvm,
};
use sov_rollup_interface::da::{DaData, SequencerCommitment};
use sov_rollup_interface::digest::Digest;
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmationBatch;
pub use sov_rollup_interface::stf::{BatchReceipt, TransactionReceipt};
use sov_rollup_interface::stf::{SlotResult, StateTransitionFunction};
use sov_state::Storage;
#[cfg(all(target_os = "zkvm", feature = "bench"))]
use sov_zk_cycle_macros::cycle_tracker;
pub use stf_blueprint::StfBlueprint;
use tracing::{debug, info, warn};
pub use tx_verifier::RawTx;

/// The tx hook for a blueprint runtime
pub struct RuntimeTxHook<C: Context> {
    /// Height to initialize the context
    pub height: u64,
    /// Sequencer public key
    pub sequencer: C::PublicKey,
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
    /// Begin a soft batch
    fn begin_soft_batch(
        &self,
        sequencer_public_key: &[u8],
        pre_state_root: &Self::StateRoot,
        pre_state: Self::PreState,
        witness: <<C as Spec>::Storage as Storage>::Witness,
        slot_header: &<Da as DaSpec>::BlockHeader,
        soft_batch: &mut SignedSoftConfirmationBatch,
    ) -> (Result<(), ApplySoftConfirmationError>, WorkingSet<C>);

    /// Apply soft batch transactions
    fn apply_soft_batch_txs(
        &self,
        txs: Vec<Vec<u8>>,
        batch_workspace: WorkingSet<C>,
    ) -> (WorkingSet<C>, Vec<TransactionReceipt<TxEffect>>);

    /// End a soft batch
    fn end_soft_batch(
        &self,
        sequencer_public_key: &[u8],
        soft_batch: &mut SignedSoftConfirmationBatch,
        tx_receipts: Vec<TransactionReceipt<TxEffect>>,
        batch_workspace: WorkingSet<C>,
    ) -> (BatchReceipt<(), TxEffect>, StateCheckpoint<C>);

    /// Finalizes a soft batch
    fn finalize_soft_batch(
        &self,
        batch_receipt: BatchReceipt<(), TxEffect>,
        checkpoint: StateCheckpoint<C>,
        pre_state: Self::PreState,
        soft_batch: &mut SignedSoftConfirmationBatch,
    ) -> SlotResult<
        Self::StateRoot,
        Self::ChangeSet,
        Self::BatchReceiptContents,
        Self::TxReceiptContents,
        Self::Witness,
    >;
}

impl<C, RT, Vm, Da> StfBlueprintTrait<C, Da, Vm> for StfBlueprint<C, Da, Vm, RT>
where
    C: Context,
    Vm: Zkvm,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    fn begin_soft_batch(
        &self,
        sequencer_public_key: &[u8],
        pre_state_root: &<C::Storage as Storage>::Root,
        pre_state: <C>::Storage,
        witness: <<C as Spec>::Storage as Storage>::Witness,
        slot_header: &<Da as DaSpec>::BlockHeader,
        soft_batch: &mut SignedSoftConfirmationBatch,
    ) -> (Result<(), ApplySoftConfirmationError>, WorkingSet<C>) {
        debug!("Applying soft batch in STF Blueprint");

        // check if soft confirmation is coming from our sequencer
        assert_eq!(
            soft_batch.sequencer_pub_key(),
            sequencer_public_key,
            "Sequencer public key must match"
        );

        // then verify da hashes match
        assert_eq!(
            soft_batch.da_slot_hash(),
            slot_header.hash().into(),
            "DA slot hashes must match"
        );

        // then verify da transactions commitment match
        assert_eq!(
            soft_batch.da_slot_txs_commitment(),
            slot_header.txs_commitment().into(),
            "DA slot hashes must match"
        );

        // then verify pre state root matches
        assert_eq!(
            soft_batch.pre_state_root(),
            pre_state_root.as_ref(),
            "pre state roots must match"
        );

        let checkpoint = StateCheckpoint::with_witness(pre_state, witness);

        self.begin_soft_confirmation_inner(checkpoint, soft_batch)
    }

    fn apply_soft_batch_txs(
        &self,
        txs: Vec<Vec<u8>>,
        batch_workspace: WorkingSet<C>,
    ) -> (WorkingSet<C>, Vec<TransactionReceipt<TxEffect>>) {
        self.apply_sov_txs_inner(txs, batch_workspace)
    }

    fn end_soft_batch(
        &self,
        sequencer_public_key: &[u8],
        soft_batch: &mut SignedSoftConfirmationBatch,
        tx_receipts: Vec<TransactionReceipt<TxEffect>>,
        batch_workspace: WorkingSet<C>,
    ) -> (BatchReceipt<(), TxEffect>, StateCheckpoint<C>) {
        let unsigned = UnsignedSoftConfirmationBatch::new(
            soft_batch.da_slot_height(),
            soft_batch.da_slot_hash(),
            soft_batch.da_slot_txs_commitment(),
            soft_batch.pre_state_root(),
            soft_batch.txs(),
            soft_batch.deposit_data(),
            soft_batch.l1_fee_rate(),
            soft_batch.timestamp(),
        );

        let unsigned_raw = unsigned.try_to_vec().unwrap();

        // check the claimed hash
        assert_eq!(
            soft_batch.hash(),
            Into::<[u8; 32]>::into(<C as Spec>::Hasher::digest(unsigned_raw)),
            "Soft confirmation hashes must match"
        );

        // verify signature
        assert!(
            verify_soft_batch_signature::<C>(
                unsigned,
                soft_batch.signature().as_slice(),
                sequencer_public_key
            )
            .is_ok(),
            "Signature verification must succeed"
        );

        let (apply_soft_batch_result, checkpoint) =
            self.end_soft_confirmation_inner(soft_batch, tx_receipts, batch_workspace);

        (apply_soft_batch_result.unwrap(), checkpoint)
    }

    fn finalize_soft_batch(
        &self,
        batch_receipt: BatchReceipt<(), TxEffect>,
        checkpoint: StateCheckpoint<C>,
        pre_state: Self::PreState,
        soft_batch: &mut SignedSoftConfirmationBatch,
    ) -> SlotResult<
        <C::Storage as Storage>::Root,
        C::Storage,
        (),
        TxEffect,
        <<C as Spec>::Storage as Storage>::Witness,
    > {
        info!(
            "soft batch  with hash: {:?} from sequencer {:?} has been applied with #{} transactions.",
            soft_batch.hash(),
            soft_batch.sequencer_pub_key(),
            batch_receipt.tx_receipts.len(),
        );

        let mut batch_receipts = vec![];

        for (i, tx_receipt) in batch_receipt.tx_receipts.iter().enumerate() {
            info!(
                "tx #{} hash: 0x{} result {:?}",
                i,
                hex::encode(tx_receipt.tx_hash),
                tx_receipt.receipt
            );
        }
        batch_receipts.push(batch_receipt);

        let (state_root, witness, storage, state_diff) = {
            let working_set = checkpoint.to_revertable();
            // Save checkpoint
            let mut checkpoint = working_set.checkpoint();

            let (cache_log, witness) = checkpoint.freeze();

            let (root_hash, state_update, state_diff) = pre_state
                .compute_state_update(cache_log, &witness)
                .expect("jellyfish merkle tree update must succeed");

            let mut working_set = checkpoint.to_revertable();

            self.runtime
                .finalize_hook(&root_hash, &mut working_set.accessory_state());

            let mut checkpoint = working_set.checkpoint();
            let accessory_log = checkpoint.freeze_non_provable();

            pre_state.commit(&state_update, &accessory_log);

            (root_hash, witness, pre_state, state_diff)
        };

        SlotResult {
            state_root,
            change_set: storage,
            batch_receipts,
            witness,
            state_diff,
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
        let (log, witness) = checkpoint.freeze();

        let (genesis_hash, state_update, _) = pre_state
            .compute_state_update(log, &witness)
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

    fn apply_soft_batch(
        &self,
        sequencer_public_key: &[u8],
        pre_state_root: &Self::StateRoot,
        pre_state: Self::PreState,
        witness: Self::Witness,
        slot_header: &<Da as DaSpec>::BlockHeader,
        _validity_condition: &<Da as DaSpec>::ValidityCondition,
        soft_batch: &mut SignedSoftConfirmationBatch,
    ) -> SlotResult<
        Self::StateRoot,
        Self::ChangeSet,
        Self::BatchReceiptContents,
        Self::TxReceiptContents,
        Self::Witness,
    > {
        match self.begin_soft_batch(
            sequencer_public_key,
            pre_state_root,
            pre_state.clone(),
            witness,
            slot_header,
            soft_batch,
        ) {
            (Ok(()), batch_workspace) => {
                let (batch_workspace, tx_receipts) =
                    self.apply_soft_batch_txs(soft_batch.txs(), batch_workspace);

                let (batch_receipt, checkpoint) = self.end_soft_batch(
                    sequencer_public_key,
                    soft_batch,
                    tx_receipts,
                    batch_workspace,
                );

                self.finalize_soft_batch(batch_receipt, checkpoint, pre_state, soft_batch)
            }
            (Err(err), batch_workspace) => {
                warn!(
                    "Error applying soft batch: {:?} \n reverting batch workspace",
                    err
                );
                batch_workspace.revert();
                SlotResult {
                    state_root: pre_state_root.clone(),
                    change_set: pre_state, // should be empty
                    batch_receipts: vec![],
                    witness: <<C as Spec>::Storage as Storage>::Witness::default(),
                    state_diff: vec![],
                }
            }
        }
    }

    fn apply_soft_confirmations_from_sequencer_commitments(
        &self,
        sequencer_public_key: &[u8],
        sequencer_da_public_key: &[u8],
        initial_state_root: &Self::StateRoot,
        pre_state: Self::PreState,
        mut da_data: Vec<<Da as DaSpec>::BlobTransaction>,
        mut witnesses: std::collections::VecDeque<Vec<Self::Witness>>,
        mut slot_headers: std::collections::VecDeque<Vec<<Da as DaSpec>::BlockHeader>>,
        validity_condition: &<Da as DaSpec>::ValidityCondition,
        mut soft_confirmations: std::collections::VecDeque<Vec<SignedSoftConfirmationBatch>>,
    ) -> (
        Self::StateRoot,
        StateDiff, // state diff
    ) {
        let mut state_diff = vec![];

        // First extract all sequencer commitments
        // Ignore broken DaData and zk proofs. Also ignore ForcedTransaction's (will be implemented in the future).
        let mut sequencer_commitments: Vec<SequencerCommitment> = vec![];
        for blob in da_data.iter_mut() {
            // TODO: get sequencer da pub key
            if blob.sender().as_ref() == sequencer_da_public_key {
                let da_data = DaData::try_from_slice(blob.verified_data());

                if let Ok(DaData::SequencerCommitment(commitment)) = da_data {
                    sequencer_commitments.push(commitment);
                }
            }
        }

        // Then verify these soft confirmations.

        let mut current_state_root = initial_state_root.clone();

        for sequencer_commitment in sequencer_commitments.iter() {
            // should panic if number of sequencer commitments and soft confirmations don't match
            let mut soft_confirmations = soft_confirmations.pop_front().unwrap();

            // should panic if number of sequencer commitments and set of DA block headers don't match
            let da_block_headers = slot_headers.pop_front().unwrap();

            // should panic if number of sequencer commitments and set of witnesses don't match
            let witnesses = witnesses.pop_front().unwrap();

            // we must verify given DA headers match the commitments
            let mut index_headers = 0;
            let mut index_soft_confirmation = 0;
            let mut current_da_height = da_block_headers[index_headers].height();

            assert_eq!(
                soft_confirmations[index_soft_confirmation].da_slot_hash(),
                da_block_headers[index_headers].hash().into()
            );

            assert_eq!(
                soft_confirmations[index_soft_confirmation].da_slot_height(),
                da_block_headers[index_headers].height()
            );

            index_soft_confirmation += 1;

            // TODO: check for no da block height jump
            while index_soft_confirmation < soft_confirmations.len() {
                // the soft confirmations DA hash must equal to da hash in index_headers
                // if it's not matching, and if it's not matching the next one, then state transition is invalid.

                if soft_confirmations[index_soft_confirmation].da_slot_hash()
                    == da_block_headers[index_headers].hash().into()
                {
                    assert_eq!(
                        soft_confirmations[index_soft_confirmation].da_slot_height(),
                        da_block_headers[index_headers].height()
                    );

                    index_soft_confirmation += 1;
                } else {
                    index_headers += 1;

                    // this can also be done in soft confirmation rule enforcer?
                    assert_eq!(
                        da_block_headers[index_headers].height(),
                        current_da_height + 1
                    );

                    current_da_height += 1;

                    // if the next one is not matching, then the state transition is invalid.
                    assert_eq!(
                        soft_confirmations[index_soft_confirmation].da_slot_hash(),
                        da_block_headers[index_headers].hash().into()
                    );

                    assert_eq!(
                        soft_confirmations[index_soft_confirmation].da_slot_height(),
                        da_block_headers[index_headers].height()
                    );

                    index_soft_confirmation += 1;
                }
            }

            // final da header was checked against
            assert_eq!(index_headers, da_block_headers.len() - 1);

            // now verify the claimed merkle root of soft confirmation hashes
            let mut soft_confirmation_hashes = vec![];

            for soft_confirmation in soft_confirmations.iter() {
                // given hashes will be checked inside apply_soft_confirmation.
                // so use the claimed hash for now.
                soft_confirmation_hashes.push(soft_confirmation.hash());
            }

            let calculated_root =
                MerkleTree::<Sha256>::from_leaves(soft_confirmation_hashes.as_slice()).root();

            assert_eq!(calculated_root, Some(sequencer_commitment.merkle_root));

            let mut witness_iter = witnesses.into_iter();
            let mut da_block_headers_iter = da_block_headers.into_iter().peekable();
            let mut da_block_header = da_block_headers_iter.next().unwrap();
            // now that we verified the claimed root, we can apply the soft confirmations
            for soft_confirmation in soft_confirmations.iter_mut() {
                if soft_confirmation.da_slot_height() != da_block_header.height() {
                    da_block_header = da_block_headers_iter.next().unwrap();
                }

                let result = self.apply_soft_batch(
                    sequencer_public_key,
                    &current_state_root,
                    // TODO: either somehow commit to the prestate after each soft confirmation and pass the correct prestate here, or run every soft confirmation all at once.
                    pre_state.clone(),
                    witness_iter.next().unwrap(), // should panic if the number of witnesses and soft confirmations don't match
                    &da_block_header,
                    validity_condition,
                    soft_confirmation,
                );

                current_state_root = result.state_root;
                state_diff.extend(result.state_diff);
            }
        }

        // TODO: implement state diff extraction
        (current_state_root, state_diff)
    }
}

fn verify_soft_batch_signature<C: Context>(
    unsigned_soft_confirmation: UnsignedSoftConfirmationBatch,
    signature: &[u8],
    sequencer_public_key: &[u8],
) -> Result<(), anyhow::Error> {
    let message = unsigned_soft_confirmation.try_to_vec().unwrap();

    let signature = C::Signature::try_from(signature)?;

    // TODO: if verify function is modified to take the claimed hash in signed soft confirmation
    // we wouldn't need to hash the thing twice
    signature.verify(
        &C::PublicKey::try_from(sequencer_public_key)?,
        message.as_slice(),
    )?;

    Ok(())
}

#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

mod batch;
pub mod kernels;
mod stf_blueprint;
mod tx_verifier;

pub use batch::Batch;
use borsh::BorshSerialize;
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::hooks::{
    ApplyBlobHooks, ApplySoftConfirmationHooks, FinalizeHook, SlotHooks, TxHooks,
};
use sov_modules_api::runtime::capabilities::{Kernel, KernelSlotHooks};
use sov_modules_api::{
    BasicAddress, BlobReaderTrait, Context, DaSpec, DispatchCall, Genesis, Signature, Spec,
    StateCheckpoint, UnsignedSoftConfirmationBatch, WorkingSet, Zkvm,
};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmationBatch;
pub use sov_rollup_interface::stf::{BatchReceipt, TransactionReceipt};
use sov_rollup_interface::stf::{SlotResult, StateTransitionFunction};
use sov_state::storage::KernelWorkingSet;
use sov_state::Storage;
#[cfg(all(target_os = "zkvm", feature = "bench"))]
use sov_zk_cycle_macros::cycle_tracker;
pub use stf_blueprint::StfBlueprint;
use tracing::{debug, info};
pub use tx_verifier::RawTx;

pub use crate::stf_blueprint::ApplySoftConfirmationError;

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
pub struct GenesisParams<RT, K> {
    /// The runtime genesis parameters
    pub runtime: RT,
    /// The kernel's genesis parameters
    pub kernel: K,
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
    ) -> (u64, WorkingSet<C>, Vec<TransactionReceipt<TxEffect>>);

    /// End a soft batch
    fn end_soft_batch(
        &self,
        sequencer_public_key: &[u8],
        soft_batch: &mut SignedSoftConfirmationBatch,
        sequencer_reward: u64,
        tx_receipts: Vec<TransactionReceipt<TxEffect>>,
        batch_workspace: WorkingSet<C>,
        pre_state: Self::PreState,
    ) -> SlotResult<
        Self::StateRoot,
        Self::ChangeSet,
        Self::BatchReceiptContents,
        Self::TxReceiptContents,
        Self::Witness,
    >;
}

impl<C, RT, Vm, Da, K> StfBlueprintTrait<C, Da, Vm> for StfBlueprint<C, Da, Vm, RT, K>
where
    C: Context,
    Vm: Zkvm,
    Da: DaSpec,
    RT: Runtime<C, Da>,
    K: KernelSlotHooks<C, Da>,
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

        // then verify pre state root matches
        assert_eq!(
            soft_batch.pre_state_root(),
            pre_state_root.as_ref(),
            "pre state roots must match"
        );

        let checkpoint = StateCheckpoint::with_witness(pre_state.clone(), witness);

        self.begin_soft_confirmation_inner(checkpoint, soft_batch)
    }

    fn apply_soft_batch_txs(
        &self,
        txs: Vec<Vec<u8>>,
        batch_workspace: WorkingSet<C>,
    ) -> (u64, WorkingSet<C>, Vec<TransactionReceipt<TxEffect>>) {
        self.apply_sov_txs_inner(txs, batch_workspace)
    }

    fn end_soft_batch(
        &self,
        sequencer_public_key: &[u8],
        soft_batch: &mut SignedSoftConfirmationBatch,
        sequencer_reward: u64,
        tx_receipts: Vec<TransactionReceipt<TxEffect>>,
        batch_workspace: WorkingSet<C>,
        pre_state: <C>::Storage,
    ) -> SlotResult<
        <C::Storage as Storage>::Root,
        C::Storage,
        (),
        TxEffect,
        <<C as Spec>::Storage as Storage>::Witness,
    > {
        // verify signature
        assert!(
            verify_soft_batch_signature::<C>(soft_batch, sequencer_public_key).is_ok(),
            "Signature verification must succeed"
        );

        let (apply_soft_batch_result, checkpoint) = self.end_soft_confirmation_inner(
            soft_batch,
            sequencer_reward,
            tx_receipts,
            batch_workspace,
        );

        let batch_receipt = apply_soft_batch_result.unwrap();
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

        let (state_root, witness, storage) = {
            let working_set = checkpoint.to_revertable();
            // Save checkpoint
            let mut checkpoint = working_set.checkpoint();

            let (cache_log, witness) = checkpoint.freeze();

            let (root_hash, state_update) = pre_state
                .compute_state_update(cache_log, &witness)
                .expect("jellyfish merkle tree update must succeed");

            let mut working_set = checkpoint.to_revertable();

            self.runtime
                .finalize_hook(&root_hash, &mut working_set.accessory_state());

            let mut checkpoint = working_set.checkpoint();
            let accessory_log = checkpoint.freeze_non_provable();

            pre_state.commit(&state_update, &accessory_log);

            (root_hash, witness, pre_state)
        };

        SlotResult {
            state_root,
            change_set: storage,
            batch_receipts,
            witness,
        }
    }
}

impl<C, RT, Vm, Da, K> StfBlueprint<C, Da, Vm, RT, K>
where
    C: Context,
    Vm: Zkvm,
    Da: DaSpec,
    RT: Runtime<C, Da>,
    K: KernelSlotHooks<C, Da>,
{
    #[cfg_attr(all(target_os = "zkvm", feature = "bench"), cycle_tracker)]
    fn begin_slot(
        &self,
        state_checkpoint: StateCheckpoint<C>,
        slot_header: &Da::BlockHeader,
        validity_condition: &Da::ValidityCondition,
        pre_state_root: &<C::Storage as Storage>::Root,
    ) -> StateCheckpoint<C> {
        let mut working_set = state_checkpoint.to_revertable();
        self.kernel.begin_slot_hook(
            slot_header,
            validity_condition,
            pre_state_root,
            &mut working_set,
        );

        self.runtime.begin_slot_hook(
            slot_header,
            validity_condition,
            pre_state_root,
            &mut working_set,
        );

        working_set.checkpoint()
    }

    #[cfg_attr(all(target_os = "zkvm", feature = "bench"), cycle_tracker)]
    fn end_slot(
        &self,
        storage: C::Storage,
        checkpoint: StateCheckpoint<C>,
    ) -> (
        <<C as Spec>::Storage as Storage>::Root,
        <<C as Spec>::Storage as Storage>::Witness,
        C::Storage,
    ) {
        // Run end end_slot_hook
        let mut working_set = checkpoint.to_revertable();
        self.runtime.end_slot_hook(&mut working_set);
        // Save checkpoint
        let mut checkpoint = working_set.checkpoint();

        let (cache_log, witness) = checkpoint.freeze();

        let (root_hash, state_update) = storage
            .compute_state_update(cache_log, &witness)
            .expect("jellyfish merkle tree update must succeed");

        let mut working_set = checkpoint.to_revertable();

        self.runtime
            .finalize_hook(&root_hash, &mut working_set.accessory_state());

        let mut checkpoint = working_set.checkpoint();
        let accessory_log = checkpoint.freeze_non_provable();

        storage.commit(&state_update, &accessory_log);

        (root_hash, witness, storage)
    }
}

impl<C, RT, Vm, Da, K> StateTransitionFunction<Vm, Da> for StfBlueprint<C, Da, Vm, RT, K>
where
    C: Context,
    Da: DaSpec,
    Vm: Zkvm,
    RT: Runtime<C, Da>,
    K: KernelSlotHooks<C, Da>,
{
    type StateRoot = <C::Storage as Storage>::Root;

    type GenesisParams =
        GenesisParams<<RT as Genesis>::Config, <K as Kernel<C, Da>>::GenesisConfig>;
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

        self.kernel
            .genesis(&params.kernel, &mut working_set)
            .expect("Kernel initialization must succeed");
        self.runtime
            .genesis(&params.runtime, &mut working_set)
            .expect("Runtime initialization must succeed");

        let mut checkpoint = working_set.checkpoint();
        let (log, witness) = checkpoint.freeze();

        let (genesis_hash, state_update) = pre_state
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
        pre_state_root: &Self::StateRoot,
        pre_state: Self::PreState,
        witness: Self::Witness,
        slot_header: &Da::BlockHeader,
        validity_condition: &Da::ValidityCondition,
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
        let checkpoint = StateCheckpoint::with_witness(pre_state.clone(), witness);
        let checkpoint =
            self.begin_slot(checkpoint, slot_header, validity_condition, pre_state_root);

        // Initialize batch workspace
        let mut batch_workspace = checkpoint.to_revertable();
        let mut kernel_working_set =
            KernelWorkingSet::from_kernel(&self.kernel, &mut batch_workspace);
        let selected_blobs = self
            .kernel
            .get_blobs_for_this_slot(blobs, &mut kernel_working_set)
            .expect("blob selection must succeed, probably serialization failed");

        info!(
            "Selected {} blob(s) for execution in current slot",
            selected_blobs.len()
        );

        let mut checkpoint = batch_workspace.checkpoint();

        let mut batch_receipts = vec![];

        for (blob_idx, mut blob) in selected_blobs.into_iter().enumerate() {
            let (apply_blob_result, checkpoint_after_blob) =
                self.apply_blob(checkpoint, blob.as_mut_ref());
            checkpoint = checkpoint_after_blob;
            let batch_receipt = apply_blob_result.unwrap_or_else(Into::into);
            info!(
                "blob #{} from sequencer {} with blob_hash 0x{} has been applied with #{} transactions, sequencer outcome {:?}",
                blob_idx,
                blob.as_mut_ref().sender(),
                hex::encode(batch_receipt.batch_hash),
                batch_receipt.tx_receipts.len(),
                batch_receipt.inner
            );
            for (i, tx_receipt) in batch_receipt.tx_receipts.iter().enumerate() {
                info!(
                    "tx #{} hash: 0x{} result {:?}",
                    i,
                    hex::encode(tx_receipt.tx_hash),
                    tx_receipt.receipt
                );
            }
            batch_receipts.push(BatchReceipt {
                batch_hash: batch_receipt.batch_hash,
                tx_receipts: batch_receipt.tx_receipts,
                inner: (),
            });
        }

        let (state_root, witness, storage) = self.end_slot(pre_state, checkpoint);
        SlotResult {
            state_root,
            change_set: storage,
            batch_receipts,
            witness,
        }
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
                let (sequencer_reward, batch_workspace, tx_receipts) =
                    self.apply_soft_batch_txs(soft_batch.txs.clone(), batch_workspace);

                self.end_soft_batch(
                    sequencer_public_key,
                    soft_batch,
                    sequencer_reward,
                    tx_receipts,
                    batch_workspace,
                    pre_state,
                )
            }
            (
                Err(ApplySoftConfirmationError::TooManySoftConfirmationsOnDaSlot {
                    hash,
                    sequencer_pub_key,
                }),
                batch_workspace,
            ) => {
                info!(
                    "Too many soft confirmations on da slot with hash: {:?} from sequencer {:?}",
                    hash, sequencer_pub_key
                );
                batch_workspace.revert();
                SlotResult {
                    state_root: pre_state_root.clone(),
                    change_set: pre_state, // should be empty
                    batch_receipts: vec![],
                    witness: <<C as Spec>::Storage as Storage>::Witness::default(),
                }
            }
        }
        // debug!("Applying soft batch in STF Blueprint");

        // // check if soft confirmation is coming from our sequencer
        // assert_eq!(
        //     soft_batch.sequencer_pub_key(),
        //     sequencer_public_key,
        //     "Sequencer public key must match"
        // );

        // // verify signature
        // assert!(
        //     verify_soft_batch_signature::<C>(soft_batch, sequencer_public_key).is_ok(),
        //     "Signature verification must succeed"
        // );

        // // then verify da hashes match
        // assert_eq!(
        //     soft_batch.da_slot_hash(),
        //     slot_header.hash().into(),
        //     "DA slot hashes must match"
        // );

        // // then verify pre state root matches
        // assert_eq!(
        //     soft_batch.pre_state_root(),
        //     pre_state_root.as_ref(),
        //     "pre state roots must match"
        // );

        // let checkpoint = StateCheckpoint::with_witness(pre_state.clone(), witness);

        // let mut batch_receipts = vec![];

        // let (apply_soft_batch_result, checkpoint) =
        //     self.apply_soft_confirmation_inner(checkpoint, &mut soft_batch.clone());
        // if let Err(ApplyBatchError::Ignored(_root_hash)) = apply_soft_batch_result {
        //     return SlotResult {
        //         state_root: pre_state_root.clone(),
        //         change_set: pre_state, // should be empty
        //         batch_receipts,
        //         witness: <<C as Spec>::Storage as Storage>::Witness::default(),
        //     };
        // }
        // let batch_receipt = apply_soft_batch_result.unwrap_or_else(Into::into);
        // info!(
        //     "soft batch  with hash: {:?} from sequencer {:?} has been applied with #{} transactions.",
        //     soft_batch.hash(),
        //     soft_batch.sequencer_pub_key(),
        //     batch_receipt.tx_receipts.len(),
        // );
        // for (i, tx_receipt) in batch_receipt.tx_receipts.iter().enumerate() {
        //     info!(
        //         "tx #{} hash: 0x{} result {:?}",
        //         i,
        //         hex::encode(tx_receipt.tx_hash),
        //         tx_receipt.receipt
        //     );
        // }
        // batch_receipts.push(batch_receipt);

        // let (state_root, witness, storage) = {
        //     let working_set = checkpoint.to_revertable();
        //     // Save checkpoint
        //     let mut checkpoint = working_set.checkpoint();

        //     let (cache_log, witness) = checkpoint.freeze();

        //     let (root_hash, state_update) = pre_state
        //         .compute_state_update(cache_log, &witness)
        //         .expect("jellyfish merkle tree update must succeed");

        //     let mut working_set = checkpoint.to_revertable();

        //     self.runtime
        //         .finalize_hook(&root_hash, &mut working_set.accessory_state());

        //     let mut checkpoint = working_set.checkpoint();
        //     let accessory_log = checkpoint.freeze_non_provable();

        //     pre_state.commit(&state_update, &accessory_log);

        //     (root_hash, witness, pre_state)
        // };

        // SlotResult {
        //     state_root,
        //     change_set: storage,
        //     batch_receipts,
        //     witness,
        // }
    }
}

fn verify_soft_batch_signature<C: Context>(
    soft_batch: &SignedSoftConfirmationBatch,
    sequencer_public_key: &[u8],
) -> Result<(), anyhow::Error> {
    let unsigned = UnsignedSoftConfirmationBatch {
        da_slot_height: soft_batch.da_slot_height,
        da_slot_hash: soft_batch.da_slot_hash,
        pre_state_root: soft_batch.pre_state_root.clone(),
        txs: soft_batch.txs.clone(),
        l1_fee_rate: soft_batch.l1_fee_rate,
    };

    let message = unsigned.try_to_vec().unwrap();

    let signature = C::Signature::try_from(soft_batch.signature.as_slice())?;
    signature.verify(
        &C::PublicKey::try_from(sequencer_public_key)?,
        message.as_slice(),
    )?;

    Ok(())
}

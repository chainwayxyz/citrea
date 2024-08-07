use anyhow::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_rollup_interface::da::{DaSpec, SequencerCommitment};
use sov_rollup_interface::services::da::SlotData;
use sov_rollup_interface::stf::{Event, SoftBatchReceipt, StateDiff};
use sov_rollup_interface::zk::Proof;
use sov_schema_db::SchemaBatch;

use super::{ItemNumbers, SlotCommit};
use crate::schema::types::{
    BatchNumber, EventNumber, L2HeightRange, SlotNumber, StoredBatch, StoredSlot, StoredSoftBatch,
    StoredStateTransition, StoredTransaction, TxNumber,
};

/// Shared ledger operations
pub trait SharedLedgerOps {
    /// Put soft batch to db
    fn put_soft_batch(
        &self,
        batch: &StoredSoftBatch,
        batch_number: &BatchNumber,
        schema_batch: &mut SchemaBatch,
    ) -> Result<()>;

    /// Put batch to db
    fn put_batch(
        &self,
        batch: &StoredBatch,
        batch_number: &BatchNumber,
        schema_batch: &mut SchemaBatch,
    ) -> Result<()>;

    /// Put transaction to db
    fn put_transaction(
        &self,
        tx: &StoredTransaction,
        tx_number: &TxNumber,
        schema_batch: &mut SchemaBatch,
    ) -> Result<()>;

    /// Put event to db
    fn put_event(
        &self,
        event: &Event,
        event_number: &EventNumber,
        tx_number: TxNumber,
        schema_batch: &mut SchemaBatch,
    ) -> Result<()>;

    /// Commits a soft batch to the database by inserting its transactions and batches before
    fn commit_soft_batch<B: Serialize, T: Serialize, DS: DaSpec>(
        &self,
        batch_receipt: SoftBatchReceipt<B, T, DS>,
        include_tx_body: bool,
    ) -> Result<()>;

    /// Records the L2 height that was created as a soft confirmaiton of an L1 height
    fn extend_l2_range_of_l1_slot(
        &self,
        l1_height: SlotNumber,
        l2_height: BatchNumber,
    ) -> Result<()>;

    /// Get the next slot, block, transaction, and event numbers
    fn get_next_items_numbers(&self) -> ItemNumbers;

    /// Gets all slots with numbers `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    fn _get_slot_range(&self, range: &std::ops::Range<SlotNumber>) -> Result<Vec<StoredSlot>>;

    /// Gets all batches with numbers `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    fn get_batch_range(&self, range: &std::ops::Range<BatchNumber>) -> Result<Vec<StoredBatch>>;

    /// Gets l1 height of l1 hash
    fn get_state_diff(&self) -> Result<StateDiff>;

    /// Sets l1 height of l1 hash
    fn set_l1_height_of_l1_hash(&self, hash: [u8; 32], height: u64) -> Result<()>;

    /// Saves a soft confirmation status for a given L1 height
    fn put_soft_confirmation_status(
        &self,
        height: BatchNumber,
        status: sov_rollup_interface::rpc::SoftConfirmationStatus,
    ) -> Result<()>;

    /// Gets the commitments in the da slot with given height if any
    /// Adds the new coming commitment info
    fn update_commitments_on_da_slot(
        &self,
        height: u64,
        commitment: SequencerCommitment,
    ) -> Result<()>;

    /// Set the genesis state root
    fn set_l2_genesis_state_root<StateRoot: Serialize>(
        &self,
        state_root: &StateRoot,
    ) -> anyhow::Result<()>;

    /// Get the most recent committed soft batch, if any
    fn get_head_soft_batch(&self) -> Result<Option<(BatchNumber, StoredSoftBatch)>>;

    /// Gets all soft confirmations with numbers `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    fn get_soft_batch_range(
        &self,
        range: &std::ops::Range<BatchNumber>,
    ) -> Result<Vec<StoredSoftBatch>>;

    /// Gets all soft confirmations by numbers
    fn get_soft_batch_by_number(&self, number: &BatchNumber) -> Result<Option<StoredSoftBatch>>;
}

/// Node ledger operations
pub trait NodeLedgerOps: SharedLedgerOps {
    /// Stores proof related data on disk, accessible via l1 slot height
    fn update_verified_proof_data(
        &self,
        l1_height: u64,
        proof: Proof,
        state_transition: StoredStateTransition,
    ) -> Result<()>;

    /// Get the most recent committed slot, if any
    fn get_head_slot(&self) -> Result<Option<(SlotNumber, StoredSlot)>>;

    /// Gets all transactions with numbers `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    fn get_tx_range(&self, range: &std::ops::Range<TxNumber>) -> Result<Vec<StoredTransaction>>;

    /// Gets the commitments in the da slot with given height if any
    fn get_commitments_on_da_slot(&self, height: u64) -> Result<Option<Vec<SequencerCommitment>>>;

    /// Gets l1 height of l1 hash
    fn get_l1_height_of_l1_hash(&self, hash: [u8; 32]) -> Result<Option<u64>>;
}

/// Prover ledger operations
pub trait ProverLedgerOps: SharedLedgerOps {
    /// Get the state root by L2 height
    fn get_l2_state_root<StateRoot: DeserializeOwned>(
        &self,
        l2_height: u64,
    ) -> anyhow::Result<Option<StateRoot>>;

    /// Get the last scanned slot by the prover
    fn get_prover_last_scanned_l1_height(&self) -> Result<Option<SlotNumber>>;

    /// Set the last scanned slot by the prover
    /// Called by the prover.
    fn set_prover_last_scanned_l1_height(&self, l1_height: SlotNumber) -> Result<()>;

    /// Get the witness by L2 height
    fn get_l2_witness<Witness: DeserializeOwned>(&self, l2_height: u64) -> Result<Option<Witness>>;

    /// Stores proof related data on disk, accessible via l1 slot height
    fn put_proof_data(
        &self,
        l1_height: u64,
        l1_tx_id: [u8; 32],
        proof: Proof,
        state_transition: StoredStateTransition,
    ) -> Result<()>;

    /// Set the witness by L2 height
    fn set_l2_witness<Witness: Serialize>(&self, l2_height: u64, witness: &Witness) -> Result<()>;
}

/// Sequencer ledger operations
pub trait SequencerLedgerOps: SharedLedgerOps {
    /// Put slots
    fn put_slot(
        &self,
        slot: &StoredSlot,
        slot_number: &SlotNumber,
        schema_batch: &mut SchemaBatch,
    ) -> Result<()>;

    /// Commits a slot to the database by inserting its events, transactions, and batches before
    /// inserting the slot metadata.
    fn commit_slot<S: SlotData, B: Serialize, T: Serialize>(
        &self,
        data_to_commit: SlotCommit<S, B, T>,
    ) -> Result<()>;

    /// Used by the sequencer to record that it has committed to soft confirmations on a given L2 height
    fn set_last_sequencer_commitment_l2_height(&self, l2_height: BatchNumber) -> Result<()>;

    /// Gets all pending commitments' l2 ranges.
    /// Returns start-end L2 heights.
    fn get_pending_commitments_l2_range(&self) -> Result<Vec<L2HeightRange>>;

    /// Put a pending commitment l2 range
    fn put_pending_commitment_l2_range(&self, l2_range: &L2HeightRange) -> Result<()>;

    /// Delete a pending commitment l2 range
    fn delete_pending_commitment_l2_range(&self, l2_range: &L2HeightRange) -> Result<()>;

    /// Sets the latest state diff
    fn set_state_diff(&self, state_diff: StateDiff) -> Result<()>;

    /// Get the most recent committed batch
    /// Returns L2 height.
    fn get_last_sequencer_commitment_l2_height(&self) -> anyhow::Result<Option<BatchNumber>>;

    /// Get the most recent commitment's l1 height
    fn get_l1_height_of_last_commitment(&self) -> anyhow::Result<Option<SlotNumber>>;
}

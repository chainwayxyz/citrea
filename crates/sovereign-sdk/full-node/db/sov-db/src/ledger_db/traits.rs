use anyhow::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_rollup_interface::da::{DaSpec, SequencerCommitment};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::{Event, SoftConfirmationReceipt, StateDiff};
use sov_rollup_interface::zk::Proof;
use sov_schema_db::SchemaBatch;

use super::ItemNumbers;
use crate::schema::types::{
    BatchNumber, EventNumber, L2HeightRange, SlotNumber, StoredSlot, StoredSoftConfirmation,
    StoredStateTransition, StoredTransaction, TxNumber,
};

/// Shared ledger operations
pub trait SharedLedgerOps {
    /// Put soft confirmation to db
    fn put_soft_confirmation(
        &self,
        batch: &StoredSoftConfirmation,
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

    /// Commits a soft confirmation to the database by inserting its transactions and batches before
    fn commit_soft_confirmation<B: Serialize, T: Serialize, DS: DaSpec>(
        &self,
        batch_receipt: SoftConfirmationReceipt<B, T, DS>,
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

    /// Gets l1 height of l1 hash
    fn get_state_diff(&self) -> Result<StateDiff>;

    /// Sets l1 height of l1 hash
    fn set_l1_height_of_l1_hash(&self, hash: [u8; 32], height: u64) -> Result<()>;

    /// Gets l1 height of l1 hash
    fn get_l1_height_of_l1_hash(&self, hash: [u8; 32]) -> Result<Option<u64>>;

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

    /// Get the most recent committed soft confirmation, if any
    fn get_head_soft_confirmation(&self) -> Result<Option<(BatchNumber, StoredSoftConfirmation)>>;

    /// Gets all soft confirmations with numbers `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    fn get_soft_confirmation_range(
        &self,
        range: &std::ops::Range<BatchNumber>,
    ) -> Result<Vec<StoredSoftConfirmation>>;

    /// Gets all soft confirmations by numbers

    fn get_soft_confirmation_by_number(
        &self,
        number: &BatchNumber,
    ) -> Result<Option<StoredSoftConfirmation>>;

    /// Gets the currently active fork
    fn get_active_fork(&self) -> Result<SpecId, anyhow::Error>;

    /// Used by the sequencer to record that it has committed to soft confirmations on a given L2 height
    fn set_last_commitment_l2_height(&self, l2_height: BatchNumber) -> Result<()>;

    /// Get the most recent committed batch
    /// Returns L2 height.
    fn get_last_commitment_l2_height(&self) -> anyhow::Result<Option<BatchNumber>>;
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
}

/// Prover ledger operations
pub trait ProverLedgerOps: SharedLedgerOps + Send + Sync {
    /// Get the state root by L2 height
    fn get_l2_state_root<StateRoot: DeserializeOwned>(
        &self,
        l2_height: u64,
    ) -> anyhow::Result<Option<StateRoot>>;

    /// Get the last scanned slot by the prover
    fn get_last_scanned_l1_height(&self) -> Result<Option<SlotNumber>>;

    /// Set the last scanned slot by the prover
    /// Called by the prover.
    fn set_last_scanned_l1_height(&self, l1_height: SlotNumber) -> Result<()>;

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

    /// Save a specific L2 range state diff
    fn set_l2_state_diff(&self, l2_height: BatchNumber, state_diff: StateDiff) -> Result<()>;

    /// Returns an L2 state diff
    fn get_l2_state_diff(&self, l2_height: BatchNumber) -> Result<Option<StateDiff>>;
}

/// Ledger operations for the prover service
pub trait ProvingServiceLedgerOps: ProverLedgerOps + SharedLedgerOps + Send + Sync {
    /// Gets all pending sessions and step numbers
    fn get_pending_proving_sessions(&self) -> Result<Vec<Vec<u8>>>;

    /// Adds a pending proving session
    fn add_pending_proving_session(&self, session: Vec<u8>) -> Result<()>;

    /// Removes a pending proving session
    fn remove_pending_proving_session(&self, session: Vec<u8>) -> Result<()>;

    /// Clears all pending proving sessions
    fn clear_pending_proving_sessions(&self) -> Result<()>;
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

    /// Get the most recent commitment's l1 height
    fn get_l1_height_of_last_commitment(&self) -> anyhow::Result<Option<SlotNumber>>;

    /// Insert mempool transaction
    fn insert_mempool_tx(&self, tx_hash: Vec<u8>, tx: Vec<u8>) -> anyhow::Result<()>;

    /// Insert mempool transaction
    fn remove_mempool_txs(&self, tx_hashes: Vec<Vec<u8>>) -> anyhow::Result<()>;

    /// Fetch mempool transactions
    fn get_mempool_txs(&self) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>>;
}

use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use sov_rollup_interface::block::L2Block;
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::stf::StateDiff;
use sov_rollup_interface::zk::{Proof, StorageRootHash};
use sov_schema_db::SchemaIterator;
use uuid::Uuid;

use crate::schema::tables::{PendingProofs, PendingSequencerCommitments};
use crate::schema::types::batch_proof::{StoredBatchProof, StoredBatchProofOutput};
use crate::schema::types::job_status::JobStatus;
use crate::schema::types::l2_block::StoredL2Block;
use crate::schema::types::light_client_proof::{
    StoredLightClientProof, StoredLightClientProofOutput,
};
use crate::schema::types::{
    BonsaiSession, L2BlockNumber, L2HeightAndIndex, L2HeightRange, L2HeightStatus, SlotNumber,
};

/// Shared ledger operations
pub trait SharedLedgerOps {
    /// Return DB path
    fn path(&self) -> &Path;

    /// Returns the inner DB instance
    fn inner(&self) -> Arc<sov_schema_db::DB>;

    /// Commits a l2 block to the database by inserting its transactions and batches before
    fn commit_l2_block(
        &self,
        l2_block: L2Block,
        tx_hashes: Vec<[u8; 32]>,
        tx_bodies: Option<Vec<Vec<u8>>>,
    ) -> Result<()>;

    /// Records the L2 height that was created as a l2 block of an L1 height
    fn extend_l2_range_of_l1_slot(
        &self,
        l1_height: SlotNumber,
        l2_height: L2BlockNumber,
    ) -> Result<()>;

    /// Sets l1 height of l1 hash
    fn set_l1_height_of_l1_hash(&self, hash: [u8; 32], height: u64) -> Result<()>;

    /// Gets l1 height of l1 hash
    fn get_l1_height_of_l1_hash(&self, hash: [u8; 32]) -> Result<Option<u64>>;

    /// Gets the commitments in the da slot with given height if any
    /// Adds the new coming commitment info
    fn update_commitments_on_da_slot(
        &self,
        height: u64,
        commitment: SequencerCommitment,
    ) -> Result<()>;

    /// Set the genesis state root
    fn set_l2_genesis_state_root(&self, state_root: &StorageRootHash) -> anyhow::Result<()>;

    /// Gets the L2 genesis state root
    fn get_l2_state_root(&self, l2_height: u64) -> anyhow::Result<Option<StorageRootHash>>;

    /// Get the most recent committed l2 block, if any
    fn get_head_l2_block(&self) -> Result<Option<(L2BlockNumber, StoredL2Block)>>;

    /// Get the most recent committed l2 block height, if any
    fn get_head_l2_block_height(&self) -> Result<Option<u64>>;

    /// Gets all l2 blocks with numbers `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    fn get_l2_block_range(
        &self,
        range: &std::ops::RangeInclusive<L2BlockNumber>,
    ) -> Result<Vec<StoredL2Block>>;

    /// Gets all l2 blocks by numbers
    fn get_l2_block_by_number(&self, number: &L2BlockNumber) -> Result<Option<StoredL2Block>>;

    /// Get the most recent committed batch
    /// Returns last sequencer commitment.
    fn get_last_commitment(&self) -> anyhow::Result<Option<SequencerCommitment>>;

    /// Get the last scanned slot
    fn get_last_scanned_l1_height(&self) -> Result<Option<SlotNumber>>;

    /// Set the last scanned slot
    fn set_last_scanned_l1_height(&self, l1_height: SlotNumber) -> Result<()>;

    /// Get the last pruned block number
    fn get_last_pruned_l2_height(&self) -> Result<Option<u64>>;

    /// Set the last pruned block number
    fn set_last_pruned_l2_height(&self, l2_height: u64) -> Result<()>;

    /// Gets all executed migrations.
    fn get_executed_migrations(&self) -> anyhow::Result<Vec<(String, u64)>>;

    /// Put a pending commitment l2 range
    fn put_executed_migration(&self, migration: (String, u64)) -> anyhow::Result<()>;

    /// Stores a short header proof by l1 hash
    fn put_short_header_proof_by_l1_hash(
        &self,
        hash: &[u8; 32],
        short_header_proof: Vec<u8>,
    ) -> anyhow::Result<()>;

    /// Returns stored short header proof by l1 hash
    fn get_short_header_proof_by_l1_hash(&self, hash: &[u8; 32])
        -> anyhow::Result<Option<Vec<u8>>>;
    /// Set L2 range by l2 block hash merkle root
    fn set_l2_range_by_commitment_merkle_root(
        &self,
        root: [u8; 32],
        range: L2HeightRange,
    ) -> anyhow::Result<()>;

    /// Get L2 range by l2 block hash merkle root
    fn get_l2_range_by_commitment_merkle_root(
        &self,
        root: [u8; 32],
    ) -> anyhow::Result<Option<L2HeightRange>>;

    /// Store commitment by index
    fn put_commitment_by_index(&self, commitment: &SequencerCommitment) -> anyhow::Result<()>;

    /// Get commitment by index
    fn get_commitment_by_index(&self, index: u32) -> anyhow::Result<Option<SequencerCommitment>>;

    /// Get commitment by index range
    fn get_commitment_by_range(
        &self,
        range: std::ops::RangeInclusive<u32>,
    ) -> anyhow::Result<Vec<SequencerCommitment>>;
}

/// Node ledger operations
pub trait NodeLedgerOps: SharedLedgerOps + Send + Sync {
    /// Stores proof related data on disk, accessible via l1 slot height
    fn update_verified_proof_data(
        &self,
        l1_height: u64,
        proof: Proof,
        output: StoredBatchProofOutput,
    ) -> Result<()>;

    /// Gets the commitments in the da slot with given height if any
    fn get_commitments_on_da_slot(&self, height: u64) -> Result<Option<Vec<SequencerCommitment>>>;

    /// Get L2 height by status
    fn get_highest_l2_height_for_status(
        &self,
        status: L2HeightStatus,
        height: Option<u64>,
    ) -> Result<Option<L2HeightAndIndex>>;

    /// Set L2 height by status
    fn set_l2_height_status(
        &self,
        status: L2HeightStatus,
        l1_height: u64,
        l2_height_and_index: L2HeightAndIndex,
    ) -> Result<()>;

    /// Get highest committed and proven L2 heights up to a specific L1 height
    fn get_l2_status_heights_by_l1_height(
        &self,
        l1_height: u64,
    ) -> Result<(Option<L2HeightAndIndex>, Option<L2HeightAndIndex>)>;

    /// Store an either out of order or l2 range not synced yet commitment by index for later processing
    fn store_pending_commitment(
        &self,
        commitment: SequencerCommitment,
        found_in_l1_height: u64,
    ) -> Result<()>;

    /// Get a pending commitment by index
    fn get_pending_commitment_by_index(
        &self,
        index: u32,
    ) -> anyhow::Result<Option<(SequencerCommitment, u64)>>;

    /// Get all out of order or l2 range not synced yet commitments to process, sorted by index
    fn get_pending_commitments(&self) -> Result<SchemaIterator<'_, PendingSequencerCommitments>>;

    /// Remove pending commitment by index
    fn remove_pending_commitment(&self, index: u32) -> Result<()>;

    /// Store an out of order proof by commitment index range for later processing
    fn store_pending_proof(
        &self,
        min_commitment_index: u32,
        max_commitment_index: u32,
        proof: Proof,
        found_in_l1_height: u64,
    ) -> Result<()>;

    /// Get all out of order commitment to process sorted by commitment index range
    fn get_pending_proofs(&self) -> Result<SchemaIterator<'_, PendingProofs>>;

    /// Remove a pending proof by its commitment index range
    fn remove_pending_proof(&self, min_index: u32, max_index: u32) -> Result<()>;
}

/// Prover ledger operations
pub trait BatchProverLedgerOps: SharedLedgerOps + Send + Sync {
    /// Save a specific L2 range state diff
    fn set_l2_state_diff(&self, l2_height: L2BlockNumber, state_diff: StateDiff) -> Result<()>;

    /// Returns an L2 state diff
    fn get_l2_state_diff(&self, l2_height: L2BlockNumber) -> Result<Option<StateDiff>>;

    /// Set commitment index to be proven
    fn put_prover_pending_commitment(&self, index: u32) -> Result<()>;

    /// Get commitment indices to be proven
    fn get_prover_pending_commitments(&self) -> anyhow::Result<Vec<SequencerCommitment>>;

    /// Delete commitment indices from pending commitments table
    fn delete_prover_pending_commitments(&self, indices: Vec<u32>) -> Result<()>;

    /// Put commitment indices found in the L1 height
    fn put_commitment_index_by_l1(&self, l1_height: SlotNumber, index: u32) -> Result<()>;

    /// Inserts a new prover job with its corresponding commitment indices, marking job as running
    #[allow(clippy::ptr_arg)]
    fn insert_new_proving_job(&self, id: Uuid, commitment_indices: &Vec<u32>) -> Result<()>;

    /// Get commitment indices of job id
    fn get_commitment_indices_by_job_id(&self, id: Uuid) -> Result<Option<Vec<u32>>>;

    /// Get job id by commitment index
    fn get_job_id_by_commitment_index(&self, index: u32) -> anyhow::Result<Option<Uuid>>;

    /// Save proof by its job id
    fn put_proof_by_job_id(
        &self,
        id: Uuid,
        proof: Proof,
        output: StoredBatchProofOutput,
    ) -> Result<()>;

    /// Updates job tx id and removes job from running jobs
    fn finalize_proving_job(&self, id: Uuid, l1_tx_id: [u8; 32]) -> Result<()>;

    /// Get stored proof by job id
    fn get_proof_by_job_id(&self, id: Uuid) -> Result<Option<StoredBatchProof>>;

    /// Get jobs pending to be submitted to DA
    fn get_pending_l1_submission_jobs(&self) -> Result<Vec<Uuid>>;

    /// Get latest (job id, status) with max count.
    fn get_latest_jobs(&self, count: usize) -> Result<Vec<(Uuid, JobStatus)>>;

    /// Get commitment indices by l1 height
    fn get_prover_commitment_indices_by_l1(
        &self,
        l1_height: SlotNumber,
    ) -> Result<Option<Vec<u32>>>;

    /// Get job status (non-existent job IS RUNNING)
    fn job_status(&self, id: Uuid) -> JobStatus;
}

/// Light client prover ledger operations
pub trait LightClientProverLedgerOps: SharedLedgerOps + Send + Sync {
    /// Inserts light client proof data by L1 height
    fn insert_light_client_proof_data_by_l1_height(
        &self,
        l1_height: u64,
        proof: Proof,
        light_client_proof_output: StoredLightClientProofOutput,
    ) -> Result<()>;

    /// Gets light client proof data by L1 height
    fn get_light_client_proof_data_by_l1_height(
        &self,
        l1_height: u64,
    ) -> Result<Option<StoredLightClientProof>>;
}

/// Ledger operations for the Bonsai service
pub trait BonsaiLedgerOps: BatchProverLedgerOps + SharedLedgerOps + Send + Sync {
    /// Gets all bonsai sessions and their associated job ids
    fn get_pending_bonsai_sessions(&self) -> Result<Vec<(Uuid, BonsaiSession)>>;

    /// Insert or update bonsai proving session
    fn upsert_pending_bonsai_session(&self, job_id: Uuid, session: BonsaiSession) -> Result<()>;

    /// Removes bonsai proving session
    fn remove_pending_bonsai_session(&self, job_id: Uuid) -> Result<()>;
}

/// Sequencer ledger operations
pub trait SequencerLedgerOps: SharedLedgerOps {
    /// Gets the state diff by block number
    fn get_state_diff(&self, l2_height: L2BlockNumber) -> Result<StateDiff>;

    /// Sets the state diff generated by l2 block by block number
    fn set_state_diff(&self, l2_height: L2BlockNumber, state_diff: &StateDiff) -> Result<()>;

    /// Deletes the state diff by l2 height range
    fn delete_state_diff_by_range(
        &self,
        l2_height_range: RangeInclusive<L2BlockNumber>,
    ) -> Result<()>;

    /// Insert mempool transaction
    fn insert_mempool_tx(&self, tx_hash: Vec<u8>, tx: Vec<u8>) -> anyhow::Result<()>;

    /// Insert mempool transaction
    fn remove_mempool_txs(&self, tx_hashes: Vec<Vec<u8>>) -> anyhow::Result<()>;

    /// Fetch mempool transactions
    fn get_mempool_txs(&self) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>>;
}

/// Test ledger operations
#[cfg(test)]
pub trait TestLedgerOps {
    /// Fetch the test values
    fn get_values(&self) -> anyhow::Result<Vec<(u64, (u64, u64))>>;
    /// Insert the test values
    fn put_value(&self, key: u64, value: (u64, u64)) -> anyhow::Result<()>;
}

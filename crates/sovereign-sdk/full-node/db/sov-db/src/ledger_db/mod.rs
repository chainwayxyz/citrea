use std::mem::ManuallyDrop;
use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use metrics::histogram;
use rocksdb::ReadOptions;
use sov_rollup_interface::block::L2Block;
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::fork::{Fork, ForkMigration};
use sov_rollup_interface::stf::StateDiff;
use sov_rollup_interface::zk::{Proof, StorageRootHash};
use sov_schema_db::schema::{KeyCodec, ValueCodec};
pub use sov_schema_db::SchemaBatch;
use sov_schema_db::{
    ScanDirection, Schema, SchemaIterator, SchemaIteratorTx, SeekKeyEncoder, TransactionDB, DB,
};
use tracing::instrument;
use uuid::Uuid;

use crate::rocks_db_config::RocksdbConfig;
#[cfg(test)]
use crate::schema::tables::TestTableNew;
use crate::schema::tables::{
    CommitmentIndicesByJobId, CommitmentMerkleRoots, CommitmentsByNumber, ExecutedMigrations,
    L2BlockByHash, L2BlockByNumber, L2GenesisStateRoot, L2RangeByL1Height, L2StatusHeights,
    LastPrunedBlock, MempoolTxs, PendingBonsaiSessionByJobId, PendingBoundlessSessionByJobId,
    PendingL1SubmissionJobs, ProofByJobId, ProverLastScannedSlot, ProverPendingCommitments,
    ProverStateDiffs, SequencerCommitmentByIndex, ShortHeaderProofBySlotHash, SlotByHash,
    StateDiffByBlockNumber, VerifiedBatchProofsBySlotNumber, LEDGER_TABLES,
};
use crate::schema::types::batch_proof::{
    StoredBatchProof, StoredBatchProofOutput, StoredVerifiedProof,
};
use crate::schema::types::job_status::JobStatus;
use crate::schema::types::l2_block::{StoredL2Block, StoredTransaction};
use crate::schema::types::{
    BonsaiSession, BoundlessSession, L2BlockNumber, L2HeightAndIndex, L2HeightRange,
    L2HeightStatus, SlotNumber,
};

/// Implementation of database migrator
pub mod migrations;
mod rpc;
#[cfg(test)]
mod tests;
mod traits;

pub use traits::*;

#[derive(Clone, Debug)]
/// A database which stores the ledger history (slots, transactions, events, etc).
/// Ledger data is first ingested into an in-memory map before being fed to the state-transition function.
/// Once the state-transition function has been executed and finalized, the results are committed to the final db
pub struct LedgerDB {
    /// The database which stores the committed ledger. Uses an optimized layout which
    /// requires transactions to be executed before being committed.
    pub(crate) db: Arc<DB>,
}

impl LedgerDB {
    /// LedgerDB path suffix
    pub const DB_PATH_SUFFIX: &'static str = "ledger";
    const DB_NAME: &'static str = "ledger-db";

    /// Open a [`LedgerDB`] (backed by RocksDB) at the specified path.
    /// Will take optional column families, used for migration purposes.
    /// The returned instance will be at the path `{path}/ledger`.
    #[instrument(level = "trace", skip_all, err)]
    pub fn with_config(cfg: &RocksdbConfig) -> Result<Self, anyhow::Error> {
        let path = cfg.path.join(LedgerDB::DB_PATH_SUFFIX);
        let raw_options = cfg.as_raw_options(false);
        let tables = cfg
            .column_families
            .clone()
            .unwrap_or_else(|| LEDGER_TABLES.iter().map(|e| e.to_string()).collect());
        let inner = DB::open(path, LedgerDB::DB_NAME, tables, &raw_options)?;

        Ok(Self {
            db: Arc::new(inner),
        })
    }

    /// Gets all data with identifier in `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    #[instrument(level = "trace", skip_all, err)]
    fn get_data_range<T, K, V>(&self, range: &std::ops::Range<K>) -> Result<Vec<V>, anyhow::Error>
    where
        T: Schema<Key = K, Value = V>,
        K: Into<u64> + Copy + SeekKeyEncoder<T>,
    {
        let mut raw_iter = self.db.iter()?;
        let max_items = (range.end.into() - range.start.into()) as usize;
        raw_iter.seek(&range.start)?;
        let iter = raw_iter.take(max_items);
        let mut out = Vec::with_capacity(max_items);
        for res in iter {
            let batch = res?.value;
            out.push(batch)
        }
        Ok(out)
    }

    fn last_version_written<T: Schema<Key = U>, U: Into<u64>>(
        db: &DB,
        _schema: T,
    ) -> anyhow::Result<Option<u64>> {
        let mut iter = db.iter::<T>()?;
        iter.seek_to_last();

        match iter.next() {
            Some(Ok(item)) => Ok(Some(item.key.into())),
            Some(Err(e)) => Err(e),
            _ => Ok(None),
        }
    }

    /// Reference to underlying sov DB
    pub fn db_handle(&self) -> Arc<sov_schema_db::DB> {
        self.db.clone()
    }

    /// Reads single record by key.
    pub fn get<S: Schema>(&self, schema_key: impl KeyCodec<S>) -> anyhow::Result<Option<S::Value>> {
        self.db.get::<S>(&schema_key)
    }

    /// Returns a forward [`SchemaIterator`] on a certain schema with the default read options.
    pub fn iter<S: Schema>(&self) -> anyhow::Result<SchemaIterator<S>> {
        self.db.iter::<S>()
    }

    /// Writes single record.
    pub fn put<S: Schema>(
        &self,
        key: impl KeyCodec<S>,
        value: impl ValueCodec<S>,
    ) -> anyhow::Result<()> {
        self.db.put::<S>(&key, &value)
    }

    /// Writes a group of records wrapped in a [`SchemaBatch`].
    /// TODO: This is a temporary solution until we have proper transaction support.
    pub fn write_schemas(&self, batch: SchemaBatch) -> anyhow::Result<()> {
        self.db.write_schemas(batch)
    }
}

impl SharedLedgerOps for LedgerDB {
    /// Returns the path of the DB
    fn path(&self) -> &Path {
        self.db.path()
    }

    /// Returns the inner DB instance
    fn inner(&self) -> Arc<DB> {
        self.db.clone()
    }

    /// Commits a l2 block to the database by inserting its transactions and batches before
    fn commit_l2_block(
        &self,
        l2_block: L2Block,
        tx_hashes: Vec<[u8; 32]>,
        tx_bodies: Option<Vec<Vec<u8>>>,
    ) -> Result<SchemaBatch, anyhow::Error> {
        let txs = if let Some(tx_bodies) = tx_bodies {
            assert_eq!(
                tx_bodies.len(),
                tx_hashes.len(),
                "Tx body count does not match tx hash count"
            );
            tx_hashes
                .into_iter()
                .zip(tx_bodies)
                .map(|(hash, body)| StoredTransaction {
                    hash,
                    body: Some(body),
                })
                .collect::<Vec<_>>()
        } else {
            tx_hashes
                .into_iter()
                .map(|hash| StoredTransaction { hash, body: None })
                .collect::<Vec<_>>()
        };

        let height = l2_block.height();

        // Insert l2 block
        let l2_block_to_store = StoredL2Block {
            height,
            hash: l2_block.hash(),
            prev_hash: l2_block.prev_hash(),
            txs,
            state_root: l2_block.state_root(),
            signature: l2_block.signature().to_vec(),
            l1_fee_rate: l2_block.l1_fee_rate(),
            timestamp: l2_block.timestamp(),
            tx_merkle_root: l2_block.tx_merkle_root(),
        };

        let mut schema_batch = SchemaBatch::new();

        let l2_block_number = L2BlockNumber(height);
        schema_batch.put::<L2BlockByNumber>(&l2_block_number, &l2_block_to_store)?;
        schema_batch.put::<L2BlockByHash>(&l2_block.hash(), &l2_block_number)?;

        Ok(schema_batch)
    }

    /// Records the L2 height that was created as a l2 block of an L1 height
    #[instrument(level = "trace", skip(self), err, ret)]
    fn extend_l2_range_of_l1_slot(
        &self,
        l1_height: SlotNumber,
        l2_height: L2BlockNumber,
    ) -> Result<(), anyhow::Error> {
        let current_range = self.db.get::<L2RangeByL1Height>(&l1_height)?;

        let new_range = match current_range {
            Some(existing) => (existing.0, l2_height),
            None => (l2_height, l2_height),
        };

        self.db.put::<L2RangeByL1Height>(&l1_height, &new_range)
    }

    #[instrument(level = "trace", skip(self), err, ret)]
    fn put_short_header_proof_by_l1_hash(
        &self,
        hash: &[u8; 32],
        short_header_proof: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.db
            .put::<ShortHeaderProofBySlotHash>(hash, &short_header_proof)
    }

    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_short_header_proof_by_l1_hash(
        &self,
        hash: &[u8; 32],
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.db.get::<ShortHeaderProofBySlotHash>(hash)
    }

    /// Gets l1 height of l1 hash
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_l1_height_of_l1_hash(&self, hash: [u8; 32]) -> Result<Option<u64>, anyhow::Error> {
        self.db.get::<SlotByHash>(&hash).map(|v| v.map(|a| a.0))
    }

    /// Gets the commitments in the da slot with given height if any
    /// Adds the new coming commitment info
    #[instrument(level = "trace", skip(self, commitment), err, ret)]
    fn update_commitments_on_da_slot(
        &self,
        height: u64,
        commitment: SequencerCommitment,
    ) -> anyhow::Result<SchemaBatch> {
        let mut schema_batch = SchemaBatch::new();

        // get commitments
        let commitments = self.db.get::<CommitmentsByNumber>(&SlotNumber(height))?;

        match commitments {
            // If there were other commitments, upsert
            Some(mut commitments) => {
                if !commitments.contains(&commitment) {
                    commitments.push(commitment);
                    schema_batch.put::<CommitmentsByNumber>(&SlotNumber(height), &commitments)?;
                }
            }
            // Else insert
            None => {
                schema_batch.put::<CommitmentsByNumber>(&SlotNumber(height), &vec![commitment])?;
            }
        }

        Ok(schema_batch)
    }

    /// Set the genesis state root
    #[instrument(level = "trace", skip_all, err, ret)]
    fn set_l2_genesis_state_root(&self, state_root: &StorageRootHash) -> anyhow::Result<()> {
        let buf = bincode::serialize(state_root)?;
        self.db.put::<L2GenesisStateRoot>(&(), &buf)
    }

    /// Get the state root by L2 height
    #[instrument(level = "trace", skip_all, err)]
    fn get_l2_state_root(&self, l2_height: u64) -> anyhow::Result<Option<StorageRootHash>> {
        if l2_height == 0 {
            self.db
                .get::<L2GenesisStateRoot>(&())?
                .map(|state_root| bincode::deserialize(&state_root).map_err(Into::into))
                .transpose()
        } else {
            self.db
                .get::<L2BlockByNumber>(&L2BlockNumber(l2_height))?
                .map(|l2_block| bincode::deserialize(&l2_block.state_root).map_err(Into::into))
                .transpose()
        }
    }

    /// Get the most recent committed l2 block, if any
    #[instrument(level = "trace", skip(self), err)]
    fn get_head_l2_block(&self) -> anyhow::Result<Option<(L2BlockNumber, StoredL2Block)>> {
        let mut iter = self.db.iter::<L2BlockByNumber>()?;
        iter.seek_to_last();

        match iter.next() {
            Some(Ok(item)) => Ok(Some(item.into_tuple())),
            Some(Err(e)) => Err(e),
            _ => Ok(None),
        }
    }

    fn get_head_l2_block_height(&self) -> anyhow::Result<Option<u64>> {
        let head_l2_height = Self::last_version_written(&self.db, L2BlockByNumber)?;
        Ok(head_l2_height)
    }

    /// Gets all l2 blocks with numbers `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    #[instrument(level = "trace", skip(self), err)]
    fn get_l2_block_range(
        &self,
        range: &std::ops::RangeInclusive<L2BlockNumber>,
    ) -> Result<Vec<StoredL2Block>, anyhow::Error> {
        let start = *range.start();
        let end = L2BlockNumber(range.end().0 + 1);
        self.get_data_range::<L2BlockByNumber, _, _>(&(start..end))
    }

    /// Gets all l2 blocks by numbers
    #[instrument(level = "trace", skip(self), err)]
    fn get_l2_block_by_number(
        &self,
        number: &L2BlockNumber,
    ) -> Result<Option<StoredL2Block>, anyhow::Error> {
        self.db.get::<L2BlockByNumber>(number)
    }

    /// Returns the commitment with highest index.
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_last_commitment(&self) -> anyhow::Result<Option<SequencerCommitment>> {
        let mut iter = self.db.iter::<SequencerCommitmentByIndex>()?;
        iter.seek_to_last();

        match iter.next() {
            Some(Ok(item)) => Ok(Some(item.value)),
            Some(Err(e)) => Err(e),
            _ => Ok(None),
        }
    }

    /// Get the last scanned slot by the prover
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_last_scanned_l1_height(&self) -> anyhow::Result<Option<SlotNumber>> {
        self.db.get::<ProverLastScannedSlot>(&())
    }

    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_last_pruned_l2_height(&self) -> anyhow::Result<Option<u64>> {
        self.db.get::<LastPrunedBlock>(&())
    }

    /// Set the last pruned L2 block number
    #[instrument(level = "trace", skip(self), err, ret)]
    fn set_last_pruned_l2_height(&self, l2_height: u64) -> anyhow::Result<()> {
        self.db.put::<LastPrunedBlock>(&(), &l2_height)
    }

    /// Gets all executed migrations.
    #[instrument(level = "trace", skip(self), err)]
    fn get_executed_migrations(&self) -> anyhow::Result<Vec<(String, u64)>> {
        let mut iter = self.db.iter::<ExecutedMigrations>()?;
        iter.seek_to_first();

        let migrations = iter
            .map(|item| item.map(|item| item.key))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(migrations)
    }

    /// Put a pending commitment l2 range
    #[instrument(level = "trace", skip(self), err)]
    fn put_executed_migration(&self, migration: (String, u64)) -> anyhow::Result<()> {
        self.db.put::<ExecutedMigrations>(&migration, &())
    }

    fn set_l2_range_by_commitment_merkle_root(
        &self,
        root: [u8; 32],
        range: L2HeightRange,
    ) -> anyhow::Result<()> {
        self.db.put::<CommitmentMerkleRoots>(&root, &range)
    }

    fn get_l2_range_by_commitment_merkle_root(
        &self,
        root: [u8; 32],
    ) -> anyhow::Result<Option<L2HeightRange>> {
        self.db.get::<CommitmentMerkleRoots>(&root)
    }

    fn put_commitment_by_index(&self, commitment: &SequencerCommitment) -> anyhow::Result<()> {
        self.db
            .put::<SequencerCommitmentByIndex>(&commitment.index, commitment)
    }

    fn get_commitment_by_index(&self, index: u32) -> anyhow::Result<Option<SequencerCommitment>> {
        self.db.get::<SequencerCommitmentByIndex>(&index)
    }

    fn get_commitment_by_range(
        &self,
        range: std::ops::RangeInclusive<u32>,
    ) -> anyhow::Result<Vec<SequencerCommitment>> {
        let start = *range.start();
        let end = range.end() + 1;
        self.get_data_range::<SequencerCommitmentByIndex, _, _>(&(start..end))
    }
}

impl BatchProverLedgerOps for LedgerDB {
    fn set_l2_state_diff(
        &self,
        l2_height: L2BlockNumber,
        state_diff: StateDiff,
    ) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<ProverStateDiffs>(&l2_height, &state_diff)?;

        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    #[instrument(level = "trace", skip(self), err)]
    fn put_prover_pending_commitment(&self, index: u32) -> anyhow::Result<()> {
        self.db.put::<ProverPendingCommitments>(&index, &())
    }

    #[instrument(level = "trace", skip(self), err)]
    fn get_prover_pending_commitments(&self) -> anyhow::Result<Vec<SequencerCommitment>> {
        let mut iter = self.db.iter::<ProverPendingCommitments>()?;
        iter.seek_to_first();

        let mut commitments = vec![];
        for el in iter {
            let (index, _) = el?.into_tuple();

            let commitment = self
                .db
                .get::<SequencerCommitmentByIndex>(&index)?
                .expect("Pending commitment must exist");

            commitments.push(commitment);
        }

        commitments.sort_unstable();

        Ok(commitments)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn put_proof_by_job_id(
        &self,
        id: Uuid,
        proof: Proof,
        output: StoredBatchProofOutput,
    ) -> anyhow::Result<()> {
        let stored_proof = StoredBatchProof {
            l1_tx_id: None,
            proof,
            proof_output: output,
        };

        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<PendingL1SubmissionJobs>(&id, &())?;
        schema_batch.put::<ProofByJobId>(&id, &stored_proof)?;

        self.db.write_schemas(schema_batch)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn finalize_proving_job(&self, id: Uuid, l1_tx_id: [u8; 32]) -> anyhow::Result<()> {
        let mut stored_proof = self.db.get::<ProofByJobId>(&id)?.expect("Proof must exist");
        assert_eq!(
            stored_proof.l1_tx_id, None,
            "Proof l1 tx id must not be set"
        );

        stored_proof.l1_tx_id = Some(l1_tx_id);

        let mut schema_batch = SchemaBatch::new();
        schema_batch.delete::<PendingL1SubmissionJobs>(&id)?;
        schema_batch.put::<ProofByJobId>(&id, &stored_proof)?;

        self.db.write_schemas(schema_batch)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn get_pending_l1_submission_jobs(&self) -> anyhow::Result<Vec<Uuid>> {
        let mut iter = self.db.iter::<PendingL1SubmissionJobs>()?;
        iter.seek_to_first();

        let mut jobs = vec![];
        for el in iter {
            jobs.push(el?.into_tuple().0);
        }

        Ok(jobs)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn get_latest_jobs(&self, limit: usize, skip: usize) -> anyhow::Result<Vec<(Uuid, JobStatus)>> {
        let mut read_opts = ReadOptions::default();
        // Do not fill the cache with garbage data just to read ids
        read_opts.fill_cache(false);

        let mut iter = self
            .db
            .iter_with_direction::<CommitmentIndicesByJobId>(read_opts, ScanDirection::Backward)?;
        iter.seek_to_last();

        let mut jobs = Vec::with_capacity(limit);
        for el in iter.skip(skip).take(limit) {
            let job_id = el?.key;
            let status = self.job_status(job_id);
            jobs.push((job_id, status));
        }

        Ok(jobs)
    }

    #[instrument(level = "trace", skip(self))]
    fn job_status(&self, id: Uuid) -> JobStatus {
        if let Some(el) = self.db.get::<ProofByJobId>(&id).unwrap() {
            if el.l1_tx_id.is_some() {
                JobStatus::Finished
            } else {
                JobStatus::Sending
            }
        } else {
            JobStatus::Proving
        }
    }
}

impl BonsaiLedgerOps for LedgerDB {
    /// Gets all pending sessions and step numbers
    #[instrument(level = "trace", skip(self), err)]
    fn get_pending_bonsai_sessions(&self) -> anyhow::Result<Vec<(Uuid, BonsaiSession)>> {
        let mut iter = self.db.iter::<PendingBonsaiSessionByJobId>()?;
        iter.seek_to_first();

        iter.map(|item| item.map(|item| item.into_tuple()))
            .collect()
    }

    #[instrument(level = "trace", skip(self), err)]
    fn upsert_pending_bonsai_session(
        &self,
        job_id: Uuid,
        session: BonsaiSession,
    ) -> anyhow::Result<()> {
        self.db
            .put::<PendingBonsaiSessionByJobId>(&job_id, &session)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn remove_pending_bonsai_session(&self, job_id: Uuid) -> anyhow::Result<()> {
        self.db.delete::<PendingBonsaiSessionByJobId>(&job_id)
    }
}

impl BoundlessLedgerOps for LedgerDB {
    /// Gets all pending sessions and step numbers
    fn get_pending_boundless_sessions(&self) -> anyhow::Result<Vec<(Uuid, BoundlessSession)>> {
        let mut iter = self.db.iter::<PendingBoundlessSessionByJobId>()?;
        iter.seek_to_first();

        iter.map(|item| item.map(|item| item.into_tuple()))
            .collect()
    }

    fn upsert_pending_boundless_session(
        &self,
        job_id: Uuid,
        session: BoundlessSession,
    ) -> anyhow::Result<()> {
        self.db
            .put::<PendingBoundlessSessionByJobId>(&job_id, &session)
    }

    fn remove_pending_boundless_session(&self, job_id: Uuid) -> anyhow::Result<()> {
        self.db.delete::<PendingBoundlessSessionByJobId>(&job_id)
    }
}

impl SequencerLedgerOps for LedgerDB {
    /// Sets the state diff by block number
    #[instrument(level = "trace", skip(self), err, ret)]
    fn set_state_diff(
        &self,
        l2_height: L2BlockNumber,
        state_diff: &StateDiff,
    ) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<StateDiffByBlockNumber>(&l2_height, state_diff)?;

        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    /// Sets the state diff by block number
    #[instrument(level = "trace", skip(self), err, ret)]
    fn delete_state_diff_by_range(
        &self,
        l2_height_range: RangeInclusive<L2BlockNumber>,
    ) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        for l2_height in l2_height_range.start().0..=l2_height_range.end().0 {
            schema_batch.delete::<StateDiffByBlockNumber>(&L2BlockNumber(l2_height))?;
        }

        self.db.write_schemas(schema_batch)
    }

    /// Gets the state diff by block number
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_state_diff(&self, l2_height: L2BlockNumber) -> Result<StateDiff, anyhow::Error> {
        self.db
            .get::<StateDiffByBlockNumber>(&l2_height)
            .map(|diff| diff.unwrap_or_default())
    }

    fn insert_mempool_tx(&self, tx_hash: Vec<u8>, tx: Vec<u8>) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<MempoolTxs>(&tx_hash, &tx)?;

        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    fn get_mempool_txs(&self) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut iter = self.db.iter::<MempoolTxs>()?;
        iter.seek_to_first();

        let txs = iter
            .map(|item| item.map(|item| (item.key, item.value)))
            .collect::<Result<Vec<(Vec<u8>, Vec<u8>)>, _>>()?;

        Ok(txs)
    }

    fn remove_mempool_txs(&self, tx_hashes: Vec<Vec<u8>>) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        for tx_hash in tx_hashes {
            schema_batch.delete::<MempoolTxs>(&tx_hash)?;
        }
        self.db.write_schemas(schema_batch)?;
        Ok(())
    }
}

impl NodeLedgerOps for LedgerDB {
    /// Stores proof related data on disk, accessible via l1 slot height
    #[instrument(level = "trace", skip(self, proof, proof_output), err, ret)]
    fn update_verified_proof_data(
        &self,
        l1_height: u64,
        proof: Proof,
        proof_output: StoredBatchProofOutput,
    ) -> anyhow::Result<SchemaBatch> {
        let mut schema_batch = SchemaBatch::new();

        let verified_proofs = self
            .db
            .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(l1_height))?;

        match verified_proofs {
            Some(mut verified_proofs) => {
                let stored_verified_proof = StoredVerifiedProof {
                    proof,
                    proof_output,
                };
                verified_proofs.push(stored_verified_proof);
                schema_batch.put::<VerifiedBatchProofsBySlotNumber>(
                    &SlotNumber(l1_height),
                    &verified_proofs,
                )?;
            }
            None => {
                schema_batch.put(
                    &SlotNumber(l1_height),
                    &vec![StoredVerifiedProof {
                        proof,
                        proof_output,
                    }],
                )?;
            }
        };

        Ok(schema_batch)
    }

    /// Gets the commitments in the da slot with given height if any
    #[instrument(level = "trace", skip(self), err)]
    fn get_commitments_on_da_slot(
        &self,
        height: u64,
    ) -> anyhow::Result<Option<Vec<SequencerCommitment>>> {
        self.db.get::<CommitmentsByNumber>(&SlotNumber(height))
    }

    fn get_highest_l2_height_for_status(
        &self,
        status: L2HeightStatus,
        l1_height: Option<u64>,
    ) -> anyhow::Result<Option<L2HeightAndIndex>> {
        let mut iter = self
            .db
            .iter_with_direction::<L2StatusHeights>(Default::default(), ScanDirection::Backward)?;
        iter.seek_for_prev(&(status, l1_height.unwrap_or(u64::MAX)))?;

        match iter.next() {
            Some(Ok(item)) if item.key.0 == status => {
                let ((_, _), val) = item.into_tuple();
                Ok(Some(val))
            }
            Some(Err(e)) => Err(e),
            _ => Ok(None),
        }
    }

    fn get_l2_status_heights_by_l1_height(
        &self,
        l1_height: u64,
    ) -> anyhow::Result<(Option<L2HeightAndIndex>, Option<L2HeightAndIndex>)> {
        let committed_height =
            self.get_highest_l2_height_for_status(L2HeightStatus::Committed, Some(l1_height))?;
        let proven_height =
            self.get_highest_l2_height_for_status(L2HeightStatus::Proven, Some(l1_height))?;

        Ok((committed_height, proven_height))
    }
}

#[cfg(test)]
impl TestLedgerOps for LedgerDB {
    fn get_values(&self) -> anyhow::Result<Vec<(u64, (u64, u64))>> {
        let mut iter = self.db.iter::<TestTableNew>()?;
        iter.seek_to_first();

        let values = iter
            .map(|item| item.map(|item| (item.key, item.value)))
            .collect::<Result<Vec<(u64, (u64, u64))>, _>>()?;

        Ok(values)
    }

    fn put_value(&self, key: u64, value: (u64, u64)) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<TestTableNew>(&key, &value)?;
        self.db.write_schemas(schema_batch)?;
        Ok(())
    }
}

impl ForkMigration for LedgerDB {
    fn fork_activated(&self, _fork: &Fork) -> anyhow::Result<()> {
        // TODO: Implement later
        Ok(())
    }
}

/// A transaction for batching multiple ledger operations together.
pub struct LedgerTx {
    /// The batch of schema changes to apply.
    /// Using ManuallyDrop to avoid silent drop of SchemaBatch which would lose the changes.
    /// The batch must be explicitly written to the DB using `::commit` method.
    batch: ManuallyDrop<SchemaBatch>,
}

impl Default for LedgerTx {
    fn default() -> Self {
        Self::new()
    }
}

impl LedgerTx {
    /// Create a new ledger transaction.
    pub fn new() -> Self {
        Self {
            batch: ManuallyDrop::new(SchemaBatch::new()),
        }
    }

    /// Put a state diff into the transaction to be saved.
    pub fn put_state_diff(
        &mut self,
        l2_height: L2BlockNumber,
        state_diff: &StateDiff,
    ) -> Result<&mut Self, anyhow::Error> {
        self.batch
            .put::<StateDiffByBlockNumber>(&l2_height, state_diff)
            .context("Failed to add StateDiffByBlockNumber")?;
        Ok(self)
    }

    /// Put an L2 block into the transaction to be saved.
    pub fn put_l2_block(&mut self, l2_block: &StoredL2Block) -> Result<&mut Self, anyhow::Error> {
        let l2_block_number = L2BlockNumber(l2_block.height);
        self.batch
            .put::<L2BlockByNumber>(&l2_block_number, l2_block)
            .context("Failed to add L2BlockByNumber")?;
        self.batch
            .put::<L2BlockByHash>(&l2_block.hash, &l2_block_number)
            .context("Failed to add L2BlockByHash")?;

        Ok(self)
    }

    /// Commit the transaction to the given ledger DB.
    #[must_use = "LedgerTx must be committed to apply changes"]
    pub fn commit(self, db: &LedgerDB) -> Result<(), anyhow::Error> {
        let Self { batch } = self;
        let batch = ManuallyDrop::into_inner(batch);
        db.db
            .write_schemas(batch)
            .context("Failed to write LedgerTx to DB")
    }

    /// Reject the transaction, dropping all changes.
    pub fn reject(self) {
        let Self { batch } = self;
        let _ = ManuallyDrop::into_inner(batch);
    }
}

#[derive(Clone)]
/// An instance of the ledger database capable of transactional operations.
pub struct TransactionLedgerDB {
    /// The underlying database instance.
    pub(crate) db: Arc<TransactionDB>,
}

/// A transaction for batching multiple ledger operations together.
pub struct LedgerDBTransaction<'a> {
    db: Arc<TransactionDB>,
    tx: rocksdb::Transaction<'a, rocksdb::TransactionDB>,
}

impl TransactionLedgerDB {
    /// LedgerDB path suffix
    pub const DB_PATH_SUFFIX: &'static str = "ledger";

    /// Open a [`LedgerDB`] (backed by RocksDB) at the specified path.
    /// Will take optional column families, used for migration purposes.
    /// The returned instance will be at the path `{path}/ledger`.
    #[instrument(level = "trace", skip_all, err)]
    pub fn with_config(cfg: &RocksdbConfig) -> Result<Self, anyhow::Error> {
        let path = cfg.path.join(Self::DB_PATH_SUFFIX);
        let raw_options = cfg.as_raw_options(false);
        let tables = cfg
            .column_families
            .clone()
            .unwrap_or_else(|| LEDGER_TABLES.iter().map(|e| e.to_string()).collect());
        let inner = DB::open_transaction_db(path, tables, &raw_options)?;

        Ok(Self {
            db: Arc::new(inner),
        })
    }

    /// Create a new transaction
    pub fn transaction(&self) -> LedgerDBTransaction {
        LedgerDBTransaction {
            db: Arc::clone(&self.db),
            tx: self.db.transaction(),
        }
    }
}

/// Low-level operations
/// 1. to put/get/delete data using KeyCodec/ValueCodec.
/// 2. to commit the transaction.
impl LedgerDBTransaction<'_> {
    /// Put an instance by key and value.
    pub fn put<S: Schema>(
        &self,
        key: &impl KeyCodec<S>,
        value: &impl ValueCodec<S>,
    ) -> anyhow::Result<()> {
        let start = Instant::now();

        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;
        let key = key.encode_key()?;
        let value = value.encode_value()?;

        self.tx.put_cf(cf_handle, key, value)?;

        histogram!("ledger_tx_put_latency_seconds").record(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );
        Ok(())
    }

    /// Returns the handle for a rocksdb column family.
    fn get_cf_handle(&self, cf_name: &str) -> anyhow::Result<&rocksdb::ColumnFamily> {
        self.db.get_cf_handle(cf_name)
    }

    /// Get an instance by key.
    pub fn get<S: Schema>(
        &self,
        schema_key: &impl KeyCodec<S>,
    ) -> anyhow::Result<Option<S::Value>> {
        let start = Instant::now();

        let k = schema_key.encode_key()?;
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;

        let result = self.tx.get_pinned_cf(cf_handle, k)?;

        histogram!("schemadb_get_bytes", "cf_name" => S::COLUMN_FAMILY_NAME)
            .record(result.as_ref().map_or(0.0, |v| v.len() as f64));

        let result = result
            .map(|raw_value| S::Value::decode_value(&raw_value))
            .transpose()
            .map_err(|err| err.into());

        histogram!("schemadb_get_latency_seconds", "cf_name" => S::COLUMN_FAMILY_NAME).record(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );
        result
    }

    /// Delete an instance by key.
    pub fn delete<S: Schema>(&self, key: &impl KeyCodec<S>) -> anyhow::Result<()> {
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;
        let key = key.encode_key()?;
        self.tx.delete_cf(cf_handle, key)?;

        Ok(())
    }

    /// Returns a [`SchemaIteratorTx`] on a certain schema with the provided read options and direction.
    pub fn iter_with_direction<S: Schema>(
        &self,
        opts: ReadOptions,
        direction: ScanDirection,
    ) -> anyhow::Result<SchemaIteratorTx<S>> {
        let cf_handle = self.get_cf_handle(S::COLUMN_FAMILY_NAME)?;
        Ok(SchemaIteratorTx::new(
            self.tx.raw_iterator_cf_opt(cf_handle, opts),
            direction,
        ))
    }

    /// Returns a forward [`SchemaIteratorTx`] on a certain schema with the default read options.
    pub fn iter<S: Schema>(&self) -> anyhow::Result<SchemaIteratorTx<S>> {
        let mut read_options = ReadOptions::default();
        read_options.set_async_io(true);
        self.iter_with_direction::<S>(read_options, ScanDirection::Forward)
    }

    /// Commit the transaction
    pub fn commit(self) -> anyhow::Result<()> {
        let start = Instant::now();
        self.tx.commit()?;

        histogram!("ledger_tx_commit_latency_seconds").record(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );
        Ok(())
    }
}

/// Implementation of high-level ledger operations for LedgerDBTransaction.
/// TODO: consider removing it and use raw put/get/delete methods instead.
impl LedgerDBTransaction<'_> {
    /// Sets the state diff by block number
    #[instrument(level = "trace", skip(self), err, ret)]
    pub fn set_state_diff(
        &self,
        l2_height: L2BlockNumber,
        state_diff: &StateDiff,
    ) -> anyhow::Result<()> {
        self.put::<StateDiffByBlockNumber>(&l2_height, state_diff)?;

        Ok(())
    }

    /// Removes the state diff by block range
    #[instrument(level = "trace", skip(self), err, ret)]
    pub fn delete_state_diff_by_range(
        &self,
        l2_height_range: RangeInclusive<L2BlockNumber>,
    ) -> anyhow::Result<()> {
        for l2_height in l2_height_range.start().0..=l2_height_range.end().0 {
            self.delete::<StateDiffByBlockNumber>(&L2BlockNumber(l2_height))?;
        }

        Ok(())
    }

    /// Gets the state diff by block number
    #[instrument(level = "trace", skip(self), err, ret)]
    pub fn get_state_diff(&self, l2_height: L2BlockNumber) -> Result<StateDiff, anyhow::Error> {
        self.get::<StateDiffByBlockNumber>(&l2_height)
            .map(|diff| diff.unwrap_or_default())
    }

    /// Put an L2 block into the transaction to be saved.
    #[instrument(level = "trace", skip(self), err)]
    pub fn set_l2_block(&self, l2_block: &StoredL2Block) -> Result<(), anyhow::Error> {
        let l2_block_number = L2BlockNumber(l2_block.height);
        self.put::<L2BlockByNumber>(&l2_block_number, l2_block)
            .context("Failed to add L2BlockByNumber")?;
        self.put::<L2BlockByHash>(&l2_block.hash, &l2_block_number)
            .context("Failed to add L2BlockByHash")?;

        Ok(())
    }

    /// Gets l2 block by number
    #[instrument(level = "trace", skip(self), err)]
    fn get_l2_block_by_number(
        &self,
        number: &L2BlockNumber,
    ) -> Result<Option<StoredL2Block>, anyhow::Error> {
        self.get::<L2BlockByNumber>(number)
    }
}

use std::ops::RangeInclusive;
use std::path::Path;
use std::sync::Arc;

use rocksdb::{ReadOptions, WriteBatch};
use sov_rollup_interface::block::L2Block;
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::fork::{Fork, ForkMigration};
use sov_rollup_interface::stf::StateDiff;
use sov_rollup_interface::zk::{Proof, StorageRootHash};
use sov_schema_db::{ScanDirection, Schema, SchemaBatch, SchemaIterator, SeekKeyEncoder, DB};
use tracing::instrument;
use uuid::Uuid;

use crate::rocks_db_config::RocksdbConfig;
#[cfg(test)]
use crate::schema::tables::TestTableNew;
use crate::schema::tables::{
    CommitmentIndicesByJobId, CommitmentIndicesByL1, CommitmentMerkleRoots, CommitmentsByNumber,
    ExecutedMigrations, JobIdOfCommitment, L2BlockByHash, L2BlockByNumber, L2GenesisStateRoot,
    L2RangeByL1Height, L2StatusHeights, LastPrunedBlock, LightClientProofBySlotNumber, MempoolTxs,
    PendingBonsaiSessionByJobId, PendingL1SubmissionJobs, PendingProofs,
    PendingSequencerCommitments, ProofByJobId, ProofsBySlotNumberV2, ProverLastScannedSlot,
    ProverPendingCommitments, ProverStateDiffs, SequencerCommitmentByIndex,
    ShortHeaderProofBySlotHash, SlotByHash, StateDiffByBlockNumber,
    VerifiedBatchProofsBySlotNumber, LEDGER_TABLES,
};
use crate::schema::types::batch_proof::{
    StoredBatchProof, StoredBatchProofOutput, StoredVerifiedProof,
};
use crate::schema::types::job_status::JobStatus;
use crate::schema::types::l2_block::{StoredL2Block, StoredTransaction};
use crate::schema::types::light_client_proof::{
    StoredLightClientProof, StoredLightClientProofOutput,
};
use crate::schema::types::{
    BonsaiSession, L2BlockNumber, L2HeightAndIndex, L2HeightRange, L2HeightStatus, SlotNumber,
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

    /// Returns the handle foe the column family with the given name
    pub fn get_cf_handle(&self, cf_name: &str) -> anyhow::Result<&rocksdb::ColumnFamily> {
        self.db.get_cf_handle(cf_name)
    }

    /// Insert a key-value pair into the database given a column family
    pub fn insert_into_cf_raw(
        &self,
        cf_handle: &rocksdb::ColumnFamily,
        key: &[u8],
        value: &[u8],
    ) -> anyhow::Result<()> {
        self.db.put_cf(cf_handle, key, value)
    }

    /// Deletes a key-value pair from a column family given key and column family.
    pub fn delete_from_cf_raw(
        &self,
        cf_handle: &rocksdb::ColumnFamily,
        key: &[u8],
    ) -> anyhow::Result<()> {
        self.db.delete_cf(cf_handle, key)
    }

    /// Get an iterator for the given column family
    pub fn get_iterator_for_cf<'a>(
        &'a self,
        cf_handle: &rocksdb::ColumnFamily,
        iterator_mode: Option<rocksdb::IteratorMode>,
    ) -> anyhow::Result<rocksdb::DBIterator<'a>> {
        Ok(self.db.iter_cf(cf_handle, iterator_mode))
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

    fn put_l2_block(
        &self,
        l2_block: &StoredL2Block,
        schema_batch: &mut SchemaBatch,
    ) -> Result<(), anyhow::Error> {
        let l2_block_number = L2BlockNumber(l2_block.height);
        schema_batch.put::<L2BlockByNumber>(&l2_block_number, l2_block)?;
        schema_batch.put::<L2BlockByHash>(&l2_block.hash, &l2_block_number)
    }

    /// Write raw rocksdb WriteBatch
    pub fn write(&self, batch: WriteBatch) -> anyhow::Result<()> {
        self.db.write(batch)
    }

    /// Reference to underlying sov DB
    pub fn db_handle(&self) -> Arc<sov_schema_db::DB> {
        self.db.clone()
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
    ) -> Result<(), anyhow::Error> {
        let mut schema_batch = SchemaBatch::new();

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
        self.put_l2_block(&l2_block_to_store, &mut schema_batch)?;

        self.db.write_schemas(schema_batch)?;

        Ok(())
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

    /// Sets l1 height of l1 hash
    #[instrument(level = "trace", skip(self), err, ret)]
    fn set_l1_height_of_l1_hash(&self, hash: [u8; 32], height: u64) -> anyhow::Result<()> {
        self.db.put::<SlotByHash>(&hash, &SlotNumber(height))
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
    ) -> anyhow::Result<()> {
        // get commitments
        let commitments = self.db.get::<CommitmentsByNumber>(&SlotNumber(height))?;

        match commitments {
            // If there were other commitments, upsert
            Some(mut commitments) => {
                if !commitments.contains(&commitment) {
                    commitments.push(commitment);
                    self.db
                        .put::<CommitmentsByNumber>(&SlotNumber(height), &commitments)
                } else {
                    Ok(())
                }
            }
            // Else insert
            None => self
                .db
                .put::<CommitmentsByNumber>(&SlotNumber(height), &vec![commitment]),
        }
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

    /// Set the last scanned slot by the prover
    /// Called by the prover.
    #[instrument(level = "trace", skip(self), err, ret)]
    fn set_last_scanned_l1_height(&self, l1_height: SlotNumber) -> anyhow::Result<()> {
        self.db.put::<ProverLastScannedSlot>(&(), &l1_height)
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

impl LightClientProverLedgerOps for LedgerDB {
    fn insert_light_client_proof_data_by_l1_height(
        &self,
        l1_height: u64,
        proof: Proof,
        light_client_proof_output: StoredLightClientProofOutput,
    ) -> anyhow::Result<()> {
        let data_to_store = StoredLightClientProof {
            proof,
            light_client_proof_output,
        };

        self.db
            .put::<LightClientProofBySlotNumber>(&SlotNumber(l1_height), &data_to_store)
    }

    fn get_light_client_proof_data_by_l1_height(
        &self,
        l1_height: u64,
    ) -> anyhow::Result<Option<StoredLightClientProof>> {
        self.db
            .get::<LightClientProofBySlotNumber>(&SlotNumber(l1_height))
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

    fn get_l2_state_diff(&self, l2_height: L2BlockNumber) -> anyhow::Result<Option<StateDiff>> {
        self.db.get::<ProverStateDiffs>(&l2_height)
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
    fn delete_prover_pending_commitments(&self, indices: Vec<u32>) -> anyhow::Result<()> {
        self.db.delete_batch::<ProverPendingCommitments>(indices)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn put_commitment_index_by_l1(&self, l1_height: SlotNumber, index: u32) -> anyhow::Result<()> {
        let mut indices = self
            .db
            .get::<CommitmentIndicesByL1>(&l1_height)?
            .unwrap_or_default();
        indices.push(index);
        self.db.put::<CommitmentIndicesByL1>(&l1_height, &indices)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn insert_new_proving_job(
        &self,
        id: Uuid,
        commitment_indices: &Vec<u32>,
    ) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<CommitmentIndicesByJobId>(&id, commitment_indices)?;
        for index in commitment_indices {
            schema_batch.put::<JobIdOfCommitment>(index, &id)?;
        }

        self.db.write_schemas(schema_batch)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn get_commitment_indices_by_job_id(&self, id: Uuid) -> anyhow::Result<Option<Vec<u32>>> {
        self.db.get::<CommitmentIndicesByJobId>(&id)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn get_job_id_by_commitment_index(&self, index: u32) -> anyhow::Result<Option<Uuid>> {
        self.db.get::<JobIdOfCommitment>(&index)
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
    fn get_proof_by_job_id(&self, id: Uuid) -> anyhow::Result<Option<StoredBatchProof>> {
        self.db.get::<ProofByJobId>(&id)
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
    fn get_latest_jobs(&self, count: usize) -> anyhow::Result<Vec<(Uuid, JobStatus)>> {
        let mut read_opts = ReadOptions::default();
        // Do not fill the cache with garbage data just to read ids
        read_opts.fill_cache(false);

        let mut iter = self
            .db
            .iter_with_direction::<CommitmentIndicesByJobId>(read_opts, ScanDirection::Backward)?;
        iter.seek_to_last();

        let mut jobs = Vec::with_capacity(count);
        for el in iter {
            if jobs.len() == count {
                break;
            }
            let job_id = el?.key;
            let status = self.job_status(job_id);
            jobs.push((job_id, status));
        }

        Ok(jobs)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn get_prover_commitment_indices_by_l1(
        &self,
        l1_height: SlotNumber,
    ) -> anyhow::Result<Option<Vec<u32>>> {
        self.db.get::<CommitmentIndicesByL1>(&l1_height)
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
    ) -> anyhow::Result<()> {
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
                self.db.put::<VerifiedBatchProofsBySlotNumber>(
                    &SlotNumber(l1_height),
                    &verified_proofs,
                )
            }
            None => self.db.put(
                &SlotNumber(l1_height),
                &vec![StoredVerifiedProof {
                    proof,
                    proof_output,
                }],
            ),
        }
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

    fn set_l2_height_status(
        &self,
        status: L2HeightStatus,
        l1_height: u64,
        val: L2HeightAndIndex,
    ) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<L2StatusHeights>(&(status, l1_height), &val)?;
        self.db.write_schemas(schema_batch)?;
        Ok(())
    }

    fn store_pending_commitment(
        &self,
        commitment: SequencerCommitment,
        found_in_l1_height: u64,
    ) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<PendingSequencerCommitments>(
            &commitment.index,
            &(commitment.clone(), found_in_l1_height),
        )?;
        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    fn get_pending_commitment_by_index(
        &self,
        index: u32,
    ) -> anyhow::Result<Option<(SequencerCommitment, u64)>> {
        self.db.get::<PendingSequencerCommitments>(&index)
    }

    fn get_pending_commitments(
        &self,
    ) -> anyhow::Result<SchemaIterator<'_, PendingSequencerCommitments>> {
        let mut iter = self.db.iter::<PendingSequencerCommitments>()?;
        iter.seek_to_first();

        Ok(iter)
    }

    fn remove_pending_commitment(&self, index: u32) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.delete::<PendingSequencerCommitments>(&index)?;
        self.db.write_schemas(schema_batch)?;
        Ok(())
    }

    fn store_pending_proof(
        &self,
        min_commitment_index: u32,
        max_commitment_index: u32,
        proof: Proof,
        found_in_l1_height: u64,
    ) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<PendingProofs>(
            &(min_commitment_index, max_commitment_index),
            &(proof, found_in_l1_height),
        )?;
        self.db.write_schemas(schema_batch)?;
        Ok(())
    }

    fn get_pending_proofs(&self) -> anyhow::Result<SchemaIterator<'_, PendingProofs>> {
        let mut iter = self.db.iter::<PendingProofs>()?;
        iter.seek_to_first();

        Ok(iter)
    }

    fn remove_pending_proof(&self, min_index: u32, max_index: u32) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.delete::<PendingProofs>(&(min_index, max_index))?;
        self.db.write_schemas(schema_batch)?;
        Ok(())
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

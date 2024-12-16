use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_rollup_interface::da::{DaSpec, SequencerCommitment};
use sov_rollup_interface::fork::{Fork, ForkMigration};
use sov_rollup_interface::stf::{SoftConfirmationReceipt, StateDiff};
use sov_rollup_interface::zk::Proof;
use sov_schema_db::{Schema, SchemaBatch, SeekKeyEncoder, DB};
use tracing::instrument;

use crate::rocks_db_config::RocksdbConfig;
#[cfg(test)]
use crate::schema::tables::TestTableNew;
use crate::schema::tables::{
    BatchByNumber, CommitmentsByNumber, ExecutedMigrations, L2GenesisStateRoot, L2RangeByL1Height,
    L2Witness, LastPrunedBlock, LastSequencerCommitmentSent, LastStateDiff,
    LightClientProofBySlotNumber, MempoolTxs, PendingProvingSessions,
    PendingSequencerCommitmentL2Range, ProofsBySlotNumberV2, ProverLastScannedSlot,
    ProverStateDiffs, SlotByHash, SlotByNumber, SoftConfirmationByHash, SoftConfirmationByNumber,
    SoftConfirmationStatus, VerifiedBatchProofsBySlotNumber, LEDGER_TABLES,
};
use crate::schema::types::{
    BatchNumber, L2HeightRange, SlotNumber, StoredBatchProof, StoredBatchProofOutput,
    StoredLightClientProof, StoredLightClientProofOutput, StoredSlot, StoredSoftConfirmation,
    StoredTransaction, StoredVerifiedProof,
};

/// Implementation of database migrator
pub mod migrations;
mod rpc;
#[cfg(test)]
mod tests;
mod traits;

pub use traits::*;

const LEDGER_DB_PATH_SUFFIX: &str = "ledger";

#[derive(Clone, Debug)]
/// A database which stores the ledger history (slots, transactions, events, etc).
/// Ledger data is first ingested into an in-memory map before being fed to the state-transition function.
/// Once the state-transition function has been executed and finalized, the results are committed to the final db
pub struct LedgerDB {
    /// The database which stores the committed ledger. Uses an optimized layout which
    /// requires transactions to be executed before being committed.
    pub(crate) db: Arc<DB>,
    pub(crate) next_item_numbers: Arc<Mutex<ItemNumbers>>,
}

/// A SlotNumber, BatchNumber, TxNumber, and EventNumber which are grouped together, typically representing
/// the respective heights at the start or end of slot processing.
#[derive(Default, Clone, Debug)]
pub struct ItemNumbers {
    /// The slot number
    pub slot_number: u64,
    /// The soft confirmation number
    pub soft_confirmation_number: u64,
    /// The batch number
    pub batch_number: u64,
}

impl LedgerDB {
    /// Open a [`LedgerDB`] (backed by RocksDB) at the specified path.
    /// Will take optional column families, used for migration purposes.
    /// The returned instance will be at the path `{path}/ledger`.
    #[instrument(level = "trace", skip_all, err)]
    pub fn with_config(cfg: &RocksdbConfig) -> Result<Self, anyhow::Error> {
        let path = cfg.path.join(LEDGER_DB_PATH_SUFFIX);
        let raw_options = cfg.as_raw_options(false);
        let tables = cfg
            .column_families
            .clone()
            .unwrap_or_else(|| LEDGER_TABLES.iter().map(|e| e.to_string()).collect());
        let inner = DB::open(path, "ledger-db", tables, &raw_options)?;

        let next_item_numbers = ItemNumbers {
            slot_number: Self::last_version_written(&inner, SlotByNumber)?.unwrap_or_default() + 1,
            soft_confirmation_number: Self::last_version_written(&inner, SoftConfirmationByNumber)?
                .unwrap_or_default()
                + 1,
            batch_number: Self::last_version_written(&inner, BatchByNumber)?.unwrap_or_default()
                + 1,
        };

        Ok(Self {
            db: Arc::new(inner),
            next_item_numbers: Arc::new(Mutex::new(next_item_numbers)),
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
}

impl SharedLedgerOps for LedgerDB {
    /// Returns the path of the DB
    fn path(&self) -> &Path {
        self.db.path()
    }

    #[instrument(level = "trace", skip(self, schema_batch), err, ret)]
    fn put_soft_confirmation(
        &self,
        batch: &StoredSoftConfirmation,
        batch_number: &BatchNumber,
        schema_batch: &mut SchemaBatch,
    ) -> Result<(), anyhow::Error> {
        schema_batch.put::<SoftConfirmationByNumber>(batch_number, batch)?;
        schema_batch.put::<SoftConfirmationByHash>(&batch.hash, batch_number)
    }

    /// Commits a soft confirmation to the database by inserting its transactions and batches before
    fn commit_soft_confirmation<DS: DaSpec>(
        &self,
        state_root: &[u8],
        soft_confirmation_receipt: SoftConfirmationReceipt<DS>,
        tx_bodies: Option<Vec<Vec<u8>>>,
    ) -> Result<(), anyhow::Error> {
        // Create a scope to ensure that the lock is released before we commit to the db
        let mut current_item_numbers = {
            let mut next_item_numbers = self.next_item_numbers.lock().unwrap();
            let item_numbers = next_item_numbers.clone();
            next_item_numbers.soft_confirmation_number += 1;
            item_numbers
            // The lock is released here
        };

        let mut schema_batch = SchemaBatch::new();

        let tx_bodies = if let Some(tx_bodies) = tx_bodies {
            tx_bodies.into_iter().map(Some).collect()
        } else {
            vec![None; soft_confirmation_receipt.tx_hashes.len()]
        };

        let tx_hashes = soft_confirmation_receipt.tx_hashes.into_iter();

        let txs = tx_hashes
            .zip(tx_bodies)
            .map(|(tx_hash, tx_body)| StoredTransaction {
                hash: tx_hash,
                body: tx_body,
            })
            .collect();

        // Insert soft confirmation
        let soft_confirmation_to_store = StoredSoftConfirmation {
            da_slot_height: soft_confirmation_receipt.da_slot_height,
            l2_height: current_item_numbers.soft_confirmation_number,
            da_slot_hash: soft_confirmation_receipt.da_slot_hash.into(),
            da_slot_txs_commitment: soft_confirmation_receipt.da_slot_txs_commitment.into(),
            hash: soft_confirmation_receipt.hash,
            prev_hash: soft_confirmation_receipt.prev_hash,
            txs,
            state_root: state_root.to_vec(),
            soft_confirmation_signature: soft_confirmation_receipt.soft_confirmation_signature,
            pub_key: soft_confirmation_receipt.pub_key,
            deposit_data: soft_confirmation_receipt.deposit_data,
            l1_fee_rate: soft_confirmation_receipt.l1_fee_rate,
            timestamp: soft_confirmation_receipt.timestamp,
        };
        self.put_soft_confirmation(
            &soft_confirmation_to_store,
            &BatchNumber(current_item_numbers.soft_confirmation_number),
            &mut schema_batch,
        )?;
        current_item_numbers.soft_confirmation_number += 1;

        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    /// Records the L2 height that was created as a soft confirmaiton of an L1 height
    #[instrument(level = "trace", skip(self), err, ret)]
    fn extend_l2_range_of_l1_slot(
        &self,
        l1_height: SlotNumber,
        l2_height: BatchNumber,
    ) -> Result<(), anyhow::Error> {
        let current_range = self.db.get::<L2RangeByL1Height>(&l1_height)?;

        let new_range = match current_range {
            Some(existing) => (existing.0, l2_height),
            None => (l2_height, l2_height),
        };

        let mut schema_batch = SchemaBatch::new();

        schema_batch.put::<L2RangeByL1Height>(&l1_height, &new_range)?;
        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    /// Get the next slot, block, transaction numbers
    #[instrument(level = "trace", skip(self), ret)]
    fn get_next_items_numbers(&self) -> ItemNumbers {
        self.next_item_numbers.lock().unwrap().clone()
    }

    /// Gets all slots with numbers `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    #[instrument(level = "trace", skip(self), err)]
    fn _get_slot_range(
        &self,
        range: &std::ops::Range<SlotNumber>,
    ) -> Result<Vec<StoredSlot>, anyhow::Error> {
        self.get_data_range::<SlotByNumber, _, _>(range)
    }

    /// Gets l1 height of l1 hash
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_state_diff(&self) -> Result<StateDiff, anyhow::Error> {
        self.db
            .get::<LastStateDiff>(&())
            .map(|diff| diff.unwrap_or_default())
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

    /// Saves a soft confirmation status for a given L1 height
    #[instrument(level = "trace", skip(self), err, ret)]
    fn put_soft_confirmation_status(
        &self,
        height: BatchNumber,
        status: sov_rollup_interface::rpc::SoftConfirmationStatus,
    ) -> Result<(), anyhow::Error> {
        let mut schema_batch = SchemaBatch::new();

        schema_batch.put::<SoftConfirmationStatus>(&height, &status)?;
        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    /// Saves a soft confirmation status for a given L1 height
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_soft_confirmation_status(
        &self,
        height: BatchNumber,
    ) -> Result<Option<sov_rollup_interface::rpc::SoftConfirmationStatus>, anyhow::Error> {
        let status = self.db.get::<SoftConfirmationStatus>(&height)?;

        Ok(status)
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
                commitments.push(commitment);
                self.db
                    .put::<CommitmentsByNumber>(&SlotNumber(height), &commitments)
            }
            // Else insert
            None => self
                .db
                .put::<CommitmentsByNumber>(&SlotNumber(height), &vec![commitment]),
        }
    }

    /// Set the genesis state root
    #[instrument(level = "trace", skip_all, err, ret)]
    fn set_l2_genesis_state_root<StateRoot: Serialize>(
        &self,
        state_root: &StateRoot,
    ) -> anyhow::Result<()> {
        let buf = bincode::serialize(state_root)?;
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<L2GenesisStateRoot>(&(), &buf)?;

        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    /// Get the state root by L2 height
    #[instrument(level = "trace", skip_all, err)]
    fn get_l2_state_root<StateRoot: DeserializeOwned>(
        &self,
        l2_height: u64,
    ) -> anyhow::Result<Option<StateRoot>> {
        if l2_height == 0 {
            self.db
                .get::<L2GenesisStateRoot>(&())?
                .map(|state_root| bincode::deserialize(&state_root).map_err(Into::into))
                .transpose()
        } else {
            self.db
                .get::<SoftConfirmationByNumber>(&BatchNumber(l2_height))?
                .map(|soft_confirmation| {
                    bincode::deserialize(&soft_confirmation.state_root).map_err(Into::into)
                })
                .transpose()
        }
    }

    /// Get the most recent committed soft confirmation, if any
    #[instrument(level = "trace", skip(self), err)]
    fn get_head_soft_confirmation(
        &self,
    ) -> anyhow::Result<Option<(BatchNumber, StoredSoftConfirmation)>> {
        let mut iter = self.db.iter::<SoftConfirmationByNumber>()?;
        iter.seek_to_last();

        match iter.next() {
            Some(Ok(item)) => Ok(Some(item.into_tuple())),
            Some(Err(e)) => Err(e),
            _ => Ok(None),
        }
    }

    /// Gets all soft confirmations with numbers `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    #[instrument(level = "trace", skip(self), err)]
    fn get_soft_confirmation_range(
        &self,
        range: &std::ops::RangeInclusive<BatchNumber>,
    ) -> Result<Vec<StoredSoftConfirmation>, anyhow::Error> {
        let start = *range.start();
        let end = BatchNumber(range.end().0 + 1);
        self.get_data_range::<SoftConfirmationByNumber, _, _>(&(start..end))
    }

    /// Gets all soft confirmations by numbers
    #[instrument(level = "trace", skip(self), err)]
    fn get_soft_confirmation_by_number(
        &self,
        number: &BatchNumber,
    ) -> Result<Option<StoredSoftConfirmation>, anyhow::Error> {
        self.db.get::<SoftConfirmationByNumber>(number)
    }

    /// Get the most recent committed batch
    /// Returns L2 height.
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_last_commitment_l2_height(&self) -> anyhow::Result<Option<BatchNumber>> {
        self.db.get::<LastSequencerCommitmentSent>(&())
    }

    /// Used by the nodes to record that it has committed a soft confirmations on a given L2 height.
    /// For a sequencer, the last commitment height is set when the block is produced.
    /// For a full node the last commitment is set when a commitment is read from a finalized DA layer block.
    #[instrument(level = "trace", skip(self), err, ret)]
    fn set_last_commitment_l2_height(&self, l2_height: BatchNumber) -> Result<(), anyhow::Error> {
        let mut schema_batch = SchemaBatch::new();

        schema_batch.put::<LastSequencerCommitmentSent>(&(), &l2_height)?;
        self.db.write_schemas(schema_batch)?;

        Ok(())
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
        let mut schema_batch = SchemaBatch::new();

        schema_batch.put::<ProverLastScannedSlot>(&(), &l1_height)?;
        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_last_pruned_l2_height(&self) -> anyhow::Result<Option<u64>> {
        self.db.get::<LastPrunedBlock>(&())
    }

    /// Set the last pruned L2 block number
    #[instrument(level = "trace", skip(self), err, ret)]
    fn set_last_pruned_l2_height(&self, l2_height: u64) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();

        schema_batch.put::<LastPrunedBlock>(&(), &l2_height)?;
        self.db.write_schemas(schema_batch)?;

        Ok(())
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
    /// Get the witness by L2 height
    #[instrument(level = "trace", skip_all, err)]
    fn get_l2_witness<Witness: DeserializeOwned>(
        &self,
        l2_height: u64,
    ) -> anyhow::Result<Option<(Witness, Witness)>> {
        let buf = self.db.get::<L2Witness>(&BatchNumber(l2_height))?;
        if let Some((state_buf, offchain_buf)) = buf {
            let state_witness = bincode::deserialize(&state_buf)?;
            let offchain_witness = bincode::deserialize(&offchain_buf)?;
            Ok(Some((state_witness, offchain_witness)))
        } else {
            Ok(None)
        }
    }

    /// Stores proof related data on disk, accessible via l1 slot height
    #[instrument(level = "trace", skip(self, proof, proof_output), err, ret)]
    fn insert_batch_proof_data_by_l1_height(
        &self,
        l1_height: u64,
        l1_tx_id: [u8; 32],
        proof: Proof,
        proof_output: StoredBatchProofOutput,
    ) -> anyhow::Result<()> {
        let data_to_store = StoredBatchProof {
            l1_tx_id,
            proof,
            proof_output,
        };
        let proofs = self
            .db
            .get::<ProofsBySlotNumberV2>(&SlotNumber(l1_height))?;
        match proofs {
            Some(mut proofs) => {
                proofs.push(data_to_store);
                self.db
                    .put::<ProofsBySlotNumberV2>(&SlotNumber(l1_height), &proofs)
            }
            None => self
                .db
                .put::<ProofsBySlotNumberV2>(&SlotNumber(l1_height), &vec![data_to_store]),
        }
    }

    #[instrument(level = "trace", skip(self), err)]
    fn get_proofs_by_l1_height(
        &self,
        l1_height: u64,
    ) -> anyhow::Result<Option<Vec<StoredBatchProof>>> {
        self.db.get::<ProofsBySlotNumberV2>(&SlotNumber(l1_height))
    }

    /// Set the witness by L2 height
    #[instrument(level = "trace", skip_all, err, ret)]
    fn set_l2_witness<Witness: Serialize>(
        &self,
        l2_height: u64,
        state_witness: &Witness,
        offchain_witness: &Witness,
    ) -> anyhow::Result<()> {
        let state_buf = bincode::serialize(state_witness)?;
        let offchain_buf = bincode::serialize(offchain_witness)?;
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<L2Witness>(&BatchNumber(l2_height), &(state_buf, offchain_buf))?;

        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    fn set_l2_state_diff(
        &self,
        l2_height: BatchNumber,
        state_diff: StateDiff,
    ) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<ProverStateDiffs>(&l2_height, &state_diff)?;

        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    fn get_l2_state_diff(&self, l2_height: BatchNumber) -> anyhow::Result<Option<StateDiff>> {
        self.db.get::<ProverStateDiffs>(&l2_height)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn clear_pending_proving_sessions(&self) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        let mut iter = self.db.iter::<PendingProvingSessions>()?;
        iter.seek_to_first();

        for item in iter {
            let item = item?;
            schema_batch.delete::<PendingProvingSessions>(&item.key)?;
        }

        self.db.write_schemas(schema_batch)?;

        Ok(())
    }
}

impl ProvingServiceLedgerOps for LedgerDB {
    /// Gets all pending sessions and step numbers
    #[instrument(level = "trace", skip(self), err)]
    fn get_pending_proving_sessions(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut iter = self.db.iter::<PendingProvingSessions>()?;
        iter.seek_to_first();

        let sessions = iter
            .map(|item| item.map(|item| (item.key)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(sessions)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn add_pending_proving_session(&self, session: Vec<u8>) -> anyhow::Result<()> {
        self.db.put::<PendingProvingSessions>(&session, &())
    }

    #[instrument(level = "trace", skip(self), err)]
    fn remove_pending_proving_session(&self, session: Vec<u8>) -> anyhow::Result<()> {
        self.db.delete::<PendingProvingSessions>(&session)
    }

    #[instrument(level = "trace", skip(self), err)]
    fn clear_pending_proving_sessions(&self) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        let mut iter = self.db.iter::<PendingProvingSessions>()?;
        iter.seek_to_first();

        for item in iter {
            let item = item?;
            schema_batch.delete::<PendingProvingSessions>(&item.key)?;
        }

        self.db.write_schemas(schema_batch)?;

        Ok(())
    }
}

impl SequencerLedgerOps for LedgerDB {
    /// Put slots
    #[instrument(level = "trace", skip(self, schema_batch), err, ret)]
    fn put_slot(
        &self,
        slot: &StoredSlot,
        slot_number: &SlotNumber,
        schema_batch: &mut SchemaBatch,
    ) -> Result<(), anyhow::Error> {
        schema_batch.put::<SlotByNumber>(slot_number, slot)?;
        schema_batch.put::<SlotByHash>(&slot.hash, slot_number)
    }

    /// Used by the sequencer to record that it has committed to soft confirmations on a given L2 height
    #[instrument(level = "trace", skip(self), err, ret)]
    fn set_last_sequencer_commitment_l2_height(
        &self,
        l2_height: BatchNumber,
    ) -> Result<(), anyhow::Error> {
        let mut schema_batch = SchemaBatch::new();

        schema_batch.put::<LastSequencerCommitmentSent>(&(), &l2_height)?;
        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    /// Gets all pending commitments' l2 ranges.
    /// Returns start-end L2 heights.
    #[instrument(level = "trace", skip(self), err)]
    fn get_pending_commitments_l2_range(&self) -> anyhow::Result<Vec<L2HeightRange>> {
        let mut iter = self.db.iter::<PendingSequencerCommitmentL2Range>()?;
        iter.seek_to_first();

        let mut l2_ranges = iter
            .map(|item| item.map(|item| item.key))
            .collect::<Result<Vec<_>, _>>()?;
        // Sort ascending
        l2_ranges.sort();

        Ok(l2_ranges)
    }

    /// Put a pending commitment l2 range
    #[instrument(level = "trace", skip(self), err)]
    fn put_pending_commitment_l2_range(&self, l2_range: &L2HeightRange) -> anyhow::Result<()> {
        self.db
            .put::<PendingSequencerCommitmentL2Range>(l2_range, &())
    }

    /// Delete a pending commitment l2 range
    #[instrument(level = "trace", skip(self), err)]
    fn delete_pending_commitment_l2_range(&self, l2_range: &L2HeightRange) -> anyhow::Result<()> {
        self.db
            .delete::<PendingSequencerCommitmentL2Range>(l2_range)
    }

    /// Sets the latest state diff
    #[instrument(level = "trace", skip(self), err, ret)]
    fn set_state_diff(&self, state_diff: &StateDiff) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<LastStateDiff>(&(), state_diff)?;

        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    /// Get the most recent commitment's l1 height
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_l1_height_of_last_commitment(&self) -> anyhow::Result<Option<SlotNumber>> {
        let l2_height = self.get_last_commitment_l2_height()?;
        match l2_height {
            Some(l2_height) => {
                let soft_confirmation = self
                    .get_soft_confirmation_by_number(&l2_height)?
                    .expect("Expected soft confirmation to exist");
                Ok(Some(SlotNumber(soft_confirmation.da_slot_height)))
            }
            None => Ok(None),
        }
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

    /// Get the most recent committed slot, if any
    #[instrument(level = "trace", skip(self), err)]
    fn get_head_slot(&self) -> anyhow::Result<Option<(SlotNumber, StoredSlot)>> {
        let mut iter = self.db.iter::<SlotByNumber>()?;
        iter.seek_to_last();

        match iter.next() {
            Some(Ok(item)) => Ok(Some(item.into_tuple())),
            Some(Err(e)) => Err(e),
            _ => Ok(None),
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

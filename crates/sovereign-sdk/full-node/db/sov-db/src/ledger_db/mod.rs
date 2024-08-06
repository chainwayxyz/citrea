use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_rollup_interface::da::{DaSpec, SequencerCommitment};
use sov_rollup_interface::services::da::SlotData;
use sov_rollup_interface::stf::{BatchReceipt, Event, SoftBatchReceipt, StateDiff};
use sov_rollup_interface::zk::Proof;
use sov_schema_db::{Schema, SchemaBatch, SeekKeyEncoder, DB};
use tokio::sync::broadcast;
use tracing::instrument;

use crate::rocks_db_config::gen_rocksdb_options;
use crate::schema::tables::{
    BatchByHash, BatchByNumber, CommitmentsByNumber, EventByKey, EventByNumber, L2GenesisStateRoot,
    L2RangeByL1Height, L2Witness, LastSequencerCommitmentSent, LastStateDiff, LatestBonsaiSession,
    LatestBonsaiSnarkSession, LatestProofL1Hash, PendingSequencerCommitmentL2Range,
    ProofBySlotNumber, ProverLastScannedSlot, SlotByHash, SlotByNumber, SoftBatchByHash,
    SoftBatchByNumber, SoftConfirmationStatus, TxByHash, TxByNumber, VerifiedProofsBySlotNumber,
    LEDGER_TABLES,
};
use crate::schema::types::{
    split_tx_for_storage, BatchNumber, EventNumber, L2HeightRange, SlotNumber, StoredBatch,
    StoredProof, StoredSlot, StoredSoftBatch, StoredStateTransition, StoredTransaction,
    StoredVerifiedProof, TxNumber,
};

mod rpc;
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
    db: Arc<DB>,
    next_item_numbers: Arc<Mutex<ItemNumbers>>,
    slot_subscriptions: broadcast::Sender<u64>,
}

/// A SlotNumber, BatchNumber, TxNumber, and EventNumber which are grouped together, typically representing
/// the respective heights at the start or end of slot processing.
#[derive(Default, Clone, Debug)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
pub struct ItemNumbers {
    /// The slot number
    pub slot_number: u64,
    /// The soft batch number
    pub soft_batch_number: u64,
    /// The batch number
    pub batch_number: u64,
    /// The transaction number
    pub tx_number: u64,
    /// The event number
    pub event_number: u64,
}

/// All of the data to be committed to the ledger db for a single slot.
#[derive(Debug)]
pub struct SlotCommit<S: SlotData, B, T> {
    slot_data: S,
    batch_receipts: Vec<BatchReceipt<B, T>>,
    num_txs: usize,
    num_events: usize,
}

impl<S: SlotData, B, T> SlotCommit<S, B, T> {
    /// Returns a reference to the commit's slot_data
    pub fn slot_data(&self) -> &S {
        &self.slot_data
    }

    /// Returns a reference to the commit's batch_receipts
    pub fn batch_receipts(&self) -> &[BatchReceipt<B, T>] {
        &self.batch_receipts
    }

    /// Create a new SlotCommit from the given slot data
    pub fn new(slot_data: S) -> Self {
        Self {
            slot_data,
            batch_receipts: vec![],
            num_txs: 0,
            num_events: 0,
        }
    }
    /// Add a `batch` (of transactions) to the commit
    pub fn add_batch(&mut self, batch: BatchReceipt<B, T>) {
        self.num_txs += batch.tx_receipts.len();
        let events_this_batch: usize = batch.tx_receipts.iter().map(|r| r.events.len()).sum();
        self.batch_receipts.push(batch);
        self.num_events += events_this_batch;
    }
}

impl LedgerDB {
    /// Open a [`LedgerDB`] (backed by RocksDB) at the specified path.
    /// The returned instance will be at the path `{path}/ledger-db`.
    #[instrument(level = "trace", skip_all, err)]
    pub fn with_path(path: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        let path = path.as_ref().join(LEDGER_DB_PATH_SUFFIX);
        let inner = DB::open(
            path,
            "ledger-db",
            LEDGER_TABLES.iter().copied(),
            &gen_rocksdb_options(&Default::default(), false),
        )?;

        let next_item_numbers = ItemNumbers {
            slot_number: Self::last_version_written(&inner, SlotByNumber)?.unwrap_or_default() + 1,
            soft_batch_number: Self::last_version_written(&inner, SoftBatchByNumber)?
                .unwrap_or_default()
                + 1,
            batch_number: Self::last_version_written(&inner, BatchByNumber)?.unwrap_or_default()
                + 1,
            tx_number: Self::last_version_written(&inner, TxByNumber)?.unwrap_or_default() + 1,
            event_number: Self::last_version_written(&inner, EventByNumber)?.unwrap_or_default()
                + 1,
        };

        Ok(Self {
            db: Arc::new(inner),
            next_item_numbers: Arc::new(Mutex::new(next_item_numbers)),
            slot_subscriptions: broadcast::channel(10).0,
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
}

impl SharedLedgerOps for LedgerDB {
    #[instrument(level = "trace", skip(self, schema_batch), err, ret)]
    fn put_soft_batch(
        &self,
        batch: &StoredSoftBatch,
        batch_number: &BatchNumber,
        schema_batch: &mut SchemaBatch,
    ) -> Result<(), anyhow::Error> {
        schema_batch.put::<SoftBatchByNumber>(batch_number, batch)?;
        schema_batch.put::<SoftBatchByHash>(&batch.hash, batch_number)
    }

    #[instrument(level = "trace", skip(self, schema_batch), err, ret)]
    fn put_batch(
        &self,
        batch: &StoredBatch,
        batch_number: &BatchNumber,
        schema_batch: &mut SchemaBatch,
    ) -> Result<(), anyhow::Error> {
        schema_batch.put::<BatchByNumber>(batch_number, batch)?;
        schema_batch.put::<BatchByHash>(&batch.hash, batch_number)
    }

    #[instrument(level = "trace", skip(self, tx, schema_batch), err, ret)]
    fn put_transaction(
        &self,
        tx: &StoredTransaction,
        tx_number: &TxNumber,
        schema_batch: &mut SchemaBatch,
    ) -> Result<(), anyhow::Error> {
        schema_batch.put::<TxByNumber>(tx_number, tx)?;
        schema_batch.put::<TxByHash>(&tx.hash, tx_number)
    }

    #[instrument(level = "trace", skip_all, fields(event_number, tx_number), err, ret)]
    fn put_event(
        &self,
        event: &Event,
        event_number: &EventNumber,
        tx_number: TxNumber,
        schema_batch: &mut SchemaBatch,
    ) -> Result<(), anyhow::Error> {
        schema_batch.put::<EventByNumber>(event_number, event)?;
        schema_batch.put::<EventByKey>(&(event.key().clone(), tx_number, *event_number), &())
    }

    /// Commits a soft batch to the database by inserting its transactions and batches before
    fn commit_soft_batch<B: Serialize, T: Serialize, DS: DaSpec>(
        &self,
        batch_receipt: SoftBatchReceipt<B, T, DS>,
        include_tx_body: bool,
    ) -> Result<(), anyhow::Error> {
        let mut batch_receipt = batch_receipt;

        // Create a scope to ensure that the lock is released before we commit to the db
        let mut current_item_numbers = {
            let mut next_item_numbers = self.next_item_numbers.lock().unwrap();
            let item_numbers = next_item_numbers.clone();
            next_item_numbers.tx_number += batch_receipt.tx_receipts.len() as u64;
            next_item_numbers.soft_batch_number += 1;
            next_item_numbers.event_number += batch_receipt
                .tx_receipts
                .iter()
                .map(|r| r.events.len() as u64)
                .sum::<u64>();
            item_numbers
            // The lock is released here
        };

        let mut schema_batch = SchemaBatch::new();

        let mut txs = Vec::with_capacity(batch_receipt.tx_receipts.len());

        let first_tx_number = current_item_numbers.tx_number;
        let last_tx_number = first_tx_number + batch_receipt.tx_receipts.len() as u64;
        // Insert transactions and events from each batch before inserting the batch
        for tx in batch_receipt.tx_receipts.into_iter() {
            let (mut tx_to_store, events) =
                split_tx_for_storage(tx, current_item_numbers.event_number);
            for event in events.into_iter() {
                self.put_event(
                    &event,
                    &EventNumber(current_item_numbers.event_number),
                    TxNumber(current_item_numbers.tx_number),
                    &mut schema_batch,
                )?;
                current_item_numbers.event_number += 1;
            }

            // Rollup full nodes don't need to store the tx body as they already store evm body
            // Sequencer full nodes need to store the tx body as they are the only ones that have it
            if !include_tx_body {
                tx_to_store.body = None;
                batch_receipt.deposit_data = vec![];
            }

            self.put_transaction(
                &tx_to_store,
                &TxNumber(current_item_numbers.tx_number),
                &mut schema_batch,
            )?;
            current_item_numbers.tx_number += 1;
            txs.push(tx_to_store);
        }

        // Insert batch
        let batch_to_store = StoredSoftBatch {
            da_slot_height: batch_receipt.da_slot_height,
            l2_height: current_item_numbers.soft_batch_number,
            da_slot_hash: batch_receipt.da_slot_hash.into(),
            da_slot_txs_commitment: batch_receipt.da_slot_txs_commitment.into(),
            hash: batch_receipt.hash,
            prev_hash: batch_receipt.prev_hash,
            tx_range: TxNumber(first_tx_number)..TxNumber(last_tx_number),
            txs,
            state_root: batch_receipt.state_root,
            soft_confirmation_signature: batch_receipt.soft_confirmation_signature,
            pub_key: batch_receipt.pub_key,
            deposit_data: batch_receipt.deposit_data,
            l1_fee_rate: batch_receipt.l1_fee_rate,
            timestamp: batch_receipt.timestamp,
        };
        self.put_soft_batch(
            &batch_to_store,
            &BatchNumber(current_item_numbers.soft_batch_number),
            &mut schema_batch,
        )?;
        current_item_numbers.soft_batch_number += 1;

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

    /// Get the next slot, block, transaction, and event numbers
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

    /// Gets all batches with numbers `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    #[instrument(level = "trace", skip(self), err)]
    fn get_batch_range(
        &self,
        range: &std::ops::Range<BatchNumber>,
    ) -> Result<Vec<StoredBatch>, anyhow::Error> {
        self.get_data_range::<BatchByNumber, _, _>(range)
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

    /// Get the most recent committed soft batch, if any
    #[instrument(level = "trace", skip(self), err)]
    fn get_head_soft_batch(&self) -> anyhow::Result<Option<(BatchNumber, StoredSoftBatch)>> {
        let mut iter = self.db.iter::<SoftBatchByNumber>()?;
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
    fn get_soft_batch_range(
        &self,
        range: &std::ops::Range<BatchNumber>,
    ) -> Result<Vec<StoredSoftBatch>, anyhow::Error> {
        self.get_data_range::<SoftBatchByNumber, _, _>(range)
    }

    /// Gets all soft confirmations by numbers
    #[instrument(level = "trace", skip(self), err)]
    fn get_soft_batch_by_number(
        &self,
        number: &BatchNumber,
    ) -> Result<Option<StoredSoftBatch>, anyhow::Error> {
        self.db.get::<SoftBatchByNumber>(number)
    }
}

impl ProverLedgerOps for LedgerDB {
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
                .get::<SoftBatchByNumber>(&BatchNumber(l2_height))?
                .map(|soft_batch| bincode::deserialize(&soft_batch.state_root).map_err(Into::into))
                .transpose()
        }
    }

    /// Get the last scanned slot by the prover
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_prover_last_scanned_l1_height(&self) -> anyhow::Result<Option<SlotNumber>> {
        self.db.get::<ProverLastScannedSlot>(&())
    }

    /// Returns the uuid of the latest bonsai session, if not completed
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_latest_bonsai_session(&self) -> anyhow::Result<Option<String>> {
        self.db.get::<LatestBonsaiSession>(&())
    }

    /// Returns the uuid of the latest bonsai snark session, if not completed
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_latest_bonsai_snark_session(&self) -> anyhow::Result<Option<String>> {
        self.db.get::<LatestBonsaiSnarkSession>(&())
    }

    /// Get the latest proof l1 hash
    /// Only returns a value if proof submission is not complete
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_latest_proof_l1_hash(&self) -> anyhow::Result<Option<[u8; 32]>> {
        self.db.get::<LatestProofL1Hash>(&())
    }

    /// Sets the uuid of the latest bonsai session
    #[instrument(level = "trace", skip(self), err, ret)]
    fn set_latest_bonsai_session(&self, session_id: &String) -> anyhow::Result<()> {
        self.db.put::<LatestBonsaiSession>(&(), session_id)
    }

    /// Sets the uuid of the latest bonsai snark session
    #[instrument(level = "trace", skip(self), err, ret)]
    fn set_latest_bonsai_snark_session(&self, session_id: &String) -> anyhow::Result<()> {
        self.db.put::<LatestBonsaiSnarkSession>(&(), session_id)
    }

    /// Sets the latest proof l1 hash
    #[instrument(level = "trace", skip(self), err, ret)]
    fn set_latest_proof_l1_hash(&self, hash: [u8; 32]) -> anyhow::Result<()> {
        self.db.put::<LatestProofL1Hash>(&(), &hash)
    }

    /// Clears the uuid of the latest bonsai session
    #[instrument(level = "trace", skip(self), err, ret)]
    fn clear_latest_bonsai_session(&self) -> anyhow::Result<()> {
        self.db.delete::<LatestBonsaiSession>(&())
    }

    /// Clears the uuid of the latest bonsai snark session
    #[instrument(level = "trace", skip(self), err, ret)]
    fn clear_latest_bonsai_snark_session(&self) -> anyhow::Result<()> {
        self.db.delete::<LatestBonsaiSnarkSession>(&())
    }

    /// Deletes the latest proof l1 hash
    #[instrument(level = "trace", skip(self), err, ret)]
    fn clear_latest_proof_l1_hash(&self) -> anyhow::Result<()> {
        self.db.delete::<LatestProofL1Hash>(&())
    }

    /// Set the last scanned slot by the prover
    /// Called by the prover.
    #[instrument(level = "trace", skip(self), err, ret)]
    fn set_prover_last_scanned_l1_height(&self, l1_height: SlotNumber) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();

        schema_batch.put::<ProverLastScannedSlot>(&(), &l1_height)?;
        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    /// Get the witness by L2 height
    #[instrument(level = "trace", skip_all, err)]
    fn get_l2_witness<Witness: DeserializeOwned>(
        &self,
        l2_height: u64,
    ) -> anyhow::Result<Option<Witness>> {
        let buf = self.db.get::<L2Witness>(&BatchNumber(l2_height))?;
        if let Some(buf) = buf {
            let witness = bincode::deserialize(&buf)?;
            Ok(Some(witness))
        } else {
            Ok(None)
        }
    }

    /// Stores proof related data on disk, accessible via l1 slot height
    #[instrument(level = "trace", skip(self, proof, state_transition), err, ret)]
    fn put_proof_data(
        &self,
        l1_height: u64,
        l1_tx_id: [u8; 32],
        proof: Proof,
        state_transition: StoredStateTransition,
    ) -> anyhow::Result<()> {
        let data_to_store = StoredProof {
            l1_tx_id,
            proof,
            state_transition,
        };
        self.db
            .put::<ProofBySlotNumber>(&SlotNumber(l1_height), &data_to_store)
    }

    /// Set the witness by L2 height
    #[instrument(level = "trace", skip_all, err, ret)]
    fn set_l2_witness<Witness: Serialize>(
        &self,
        l2_height: u64,
        witness: &Witness,
    ) -> anyhow::Result<()> {
        let buf = bincode::serialize(witness)?;
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<L2Witness>(&BatchNumber(l2_height), &buf)?;

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

    /// Commits a slot to the database by inserting its events, transactions, and batches before
    /// inserting the slot metadata.
    #[instrument(level = "trace", skip_all, err, ret)]
    fn commit_slot<S: SlotData, B: Serialize, T: Serialize>(
        &self,
        data_to_commit: SlotCommit<S, B, T>,
    ) -> Result<(), anyhow::Error> {
        // Create a scope to ensure that the lock is released before we commit to the db
        let mut current_item_numbers = {
            let mut next_item_numbers = self.next_item_numbers.lock().unwrap();
            let item_numbers = next_item_numbers.clone();
            next_item_numbers.slot_number += 1;
            next_item_numbers.batch_number += data_to_commit.batch_receipts.len() as u64;
            next_item_numbers.tx_number += data_to_commit.num_txs as u64;
            next_item_numbers.event_number += data_to_commit.num_events as u64;
            item_numbers
            // The lock is released here
        };

        let mut schema_batch = SchemaBatch::new();

        let first_batch_number = current_item_numbers.batch_number;
        let last_batch_number = first_batch_number + data_to_commit.batch_receipts.len() as u64;
        // Insert data from "bottom up" to ensure consistency if the application crashes during insertion
        for batch_receipt in data_to_commit.batch_receipts.into_iter() {
            let first_tx_number = current_item_numbers.tx_number;
            let last_tx_number = first_tx_number + batch_receipt.tx_receipts.len() as u64;
            // Insert transactions and events from each batch before inserting the batch
            for tx in batch_receipt.tx_receipts.into_iter() {
                let (tx_to_store, events) =
                    split_tx_for_storage(tx, current_item_numbers.event_number);
                for event in events.into_iter() {
                    self.put_event(
                        &event,
                        &EventNumber(current_item_numbers.event_number),
                        TxNumber(current_item_numbers.tx_number),
                        &mut schema_batch,
                    )?;
                    current_item_numbers.event_number += 1;
                }
                self.put_transaction(
                    &tx_to_store,
                    &TxNumber(current_item_numbers.tx_number),
                    &mut schema_batch,
                )?;
                current_item_numbers.tx_number += 1;
            }

            // Insert batch
            let batch_to_store = StoredBatch {
                hash: batch_receipt.hash,
                txs: TxNumber(first_tx_number)..TxNumber(last_tx_number),
            };
            self.put_batch(
                &batch_to_store,
                &BatchNumber(current_item_numbers.batch_number),
                &mut schema_batch,
            )?;
            current_item_numbers.batch_number += 1;
        }

        // Once all batches are inserted, Insert slot
        let slot_to_store = StoredSlot {
            hash: data_to_commit.slot_data.hash(),
            // TODO: Add a method to the slot data trait allowing additional data to be stored
            extra_data: vec![].into(),
            batches: BatchNumber(first_batch_number)..BatchNumber(last_batch_number),
        };
        self.put_slot(
            &slot_to_store,
            &SlotNumber(current_item_numbers.slot_number),
            &mut schema_batch,
        )?;

        self.db.write_schemas(schema_batch)?;

        // Notify subscribers. This call returns an error IFF there are no subscribers, so we don't need to check the result
        let _ = self
            .slot_subscriptions
            .send(current_item_numbers.slot_number);

        Ok(())
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
    fn set_state_diff(&self, state_diff: StateDiff) -> anyhow::Result<()> {
        let mut schema_batch = SchemaBatch::new();
        schema_batch.put::<LastStateDiff>(&(), &state_diff)?;

        self.db.write_schemas(schema_batch)?;

        Ok(())
    }

    /// Get the most recent committed batch
    /// Returns L2 height.
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_last_sequencer_commitment_l2_height(&self) -> anyhow::Result<Option<BatchNumber>> {
        self.db.get::<LastSequencerCommitmentSent>(&())
    }

    /// Get the most recent commitment's l1 height
    #[instrument(level = "trace", skip(self), err, ret)]
    fn get_l1_height_of_last_commitment(&self) -> anyhow::Result<Option<SlotNumber>> {
        let l2_height = self.get_last_sequencer_commitment_l2_height()?;
        match l2_height {
            Some(l2_height) => {
                let soft_confirmation = self
                    .get_soft_batch_by_number(&l2_height)?
                    .expect("Expected soft confirmation to exist");
                Ok(Some(SlotNumber(soft_confirmation.da_slot_height)))
            }
            None => Ok(None),
        }
    }
}

impl NodeLedgerOps for LedgerDB {
    /// Stores proof related data on disk, accessible via l1 slot height
    #[instrument(level = "trace", skip(self, proof, state_transition), err, ret)]
    fn update_verified_proof_data(
        &self,
        l1_height: u64,
        proof: Proof,
        state_transition: StoredStateTransition,
    ) -> anyhow::Result<()> {
        let verified_proofs = self
            .db
            .get::<VerifiedProofsBySlotNumber>(&SlotNumber(l1_height))?;

        match verified_proofs {
            Some(mut verified_proofs) => {
                let stored_verified_proof = StoredVerifiedProof {
                    proof,
                    state_transition,
                };
                verified_proofs.push(stored_verified_proof);
                self.db
                    .put::<VerifiedProofsBySlotNumber>(&SlotNumber(l1_height), &verified_proofs)
            }
            None => self.db.put(
                &SlotNumber(l1_height),
                &vec![StoredVerifiedProof {
                    proof,
                    state_transition,
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

    /// Gets all transactions with numbers `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    #[instrument(level = "trace", skip(self), err)]
    fn get_tx_range(
        &self,
        range: &std::ops::Range<TxNumber>,
    ) -> Result<Vec<StoredTransaction>, anyhow::Error> {
        self.get_data_range::<TxByNumber, _, _>(range)
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

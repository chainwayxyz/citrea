use std::sync::Arc;
use std::time::{Duration, Instant};

use borsh::BorshDeserialize;
use rocksdb::WriteBatch;
use sov_db::ledger_db::migrations::{LedgerMigration, MigrationName, MigrationVersion};
use sov_db::ledger_db::LedgerDB;
use sov_db::schema::tables::SoftConfirmationByNumber;
use sov_db::schema::types::soft_confirmation::{StoredSoftConfirmation, StoredTransaction};
use sov_db::schema::types::DbHash;

use crate::utils::compute_tx_merkle_root;

#[derive(Debug, PartialEq, BorshDeserialize)]
struct StoredSoftConfirmationV1 {
    pub l2_height: u64,
    pub da_slot_height: u64,
    pub da_slot_hash: [u8; 32],
    pub da_slot_txs_commitment: [u8; 32],
    pub hash: DbHash,
    pub prev_hash: DbHash,
    pub txs: Vec<StoredTransaction>,
    pub deposit_data: Vec<Vec<u8>>,
    pub state_root: [u8; 32],
    pub soft_confirmation_signature: Vec<u8>,
    pub pub_key: Vec<u8>,
    pub l1_fee_rate: u128,
    pub timestamp: u64,
}

/// Add tx_merkle_root to StoredSoftConfirmation
pub struct MigrateSoftConfirmationTxMerkleRoot;

impl LedgerMigration for MigrateSoftConfirmationTxMerkleRoot {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("MigrateSoftConfirmationTxMerkleRoot".to_owned(), 4)
    }

    fn execute(
        &self,
        ledger_db: Arc<LedgerDB>,
        _tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let cf = ledger_db.get_cf_handle(SoftConfirmationByNumber::table_name())?;

        let mut total_entries = 0;

        let mut batch = WriteBatch::default();
        let mut count = 0;
        let batch_size = 10_000;

        let mut migrate_from_iterator = ledger_db.get_iterator_for_cf(cf, None)?;

        let mut merkle_time_acc = Duration::default();

        // Iterate from end to get total number of entry on first value
        migrate_from_iterator.set_mode(rocksdb::IteratorMode::End);

        for key_value_res in migrate_from_iterator {
            let (key, value) = key_value_res.unwrap();

            let v: StoredSoftConfirmationV1 = borsh::from_slice(&value).unwrap();

            // Get total_entries from first value since we iterate from end
            if (total_entries) == 0 {
                total_entries = v.l2_height;
            }

            let merkle_start = Instant::now();
            let leaves: Vec<[u8; 32]> = v.txs.iter().map(|tx| tx.hash).collect();
            let tx_merkle_root = compute_tx_merkle_root(&leaves)?;

            merkle_time_acc += merkle_start.elapsed();

            let stored_conf = StoredSoftConfirmation {
                l2_height: v.l2_height,
                da_slot_height: v.da_slot_height,
                da_slot_hash: v.da_slot_hash,
                da_slot_txs_commitment: v.da_slot_txs_commitment,
                hash: v.hash,
                prev_hash: v.prev_hash,
                txs: v.txs,
                deposit_data: v.deposit_data,
                state_root: v.state_root,
                soft_confirmation_signature: v.soft_confirmation_signature,
                pub_key: v.pub_key,
                l1_fee_rate: v.l1_fee_rate,
                timestamp: v.timestamp,
                tx_merkle_root,
            };

            let new_value = borsh::to_vec(&stored_conf)?;

            batch.put_cf(cf, key, new_value);

            count += 1;

            if count % batch_size == 0 {
                let progress = (count as f64 / total_entries as f64) * 100.0;
                let avg_merkle = merkle_time_acc.as_micros() as f64 / count as f64;
                tracing::info!(
                    "Progress: {}/{} ({:.2}%) | Avg merkle time: {:.2}µs",
                    count,
                    total_entries,
                    progress,
                    avg_merkle
                );

                ledger_db.write(batch)?;
                batch = WriteBatch::default();
            }
        }

        if count % batch_size != 0 {
            ledger_db.write(batch)?;
        }

        Ok(())
    }
}

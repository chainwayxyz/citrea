use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::anyhow;
use sov_schema_db::SchemaBatch;

use super::migrations::{LedgerDBMigrator, LedgerMigration, MigrationName, MigrationVersion};
use super::LedgerDB;
use crate::ledger_db::{NodeLedgerOps, SharedLedgerOps, TestLedgerOps};
use crate::rocks_db_config::RocksdbConfig;
use crate::schema::tables::{TestTableOld, LEDGER_TABLES};

pub fn successful_migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| vec![Box::new(OldToNewMigration {})])
}

pub fn failed_migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| vec![Box::new(FailedOldToNewMigration {})])
}

struct OldToNewMigration {}
impl LedgerMigration for OldToNewMigration {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("OldToNew".to_owned(), 1)
    }

    fn execute(
        &self,
        ledger_db: sov_rollup_interface::RefCount<LedgerDB>,
        _tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let Some(values) = ledger_db.db.get::<TestTableOld>(&())? else {
            return Ok(());
        };
        for (index, value) in values.into_iter().enumerate() {
            ledger_db.put_value(index as u64, (index as u64, value))?;
        }

        // Clear old table
        ledger_db.db.delete::<TestTableOld>(&())?;
        Ok(())
    }
}

struct FailedOldToNewMigration {}
impl LedgerMigration for FailedOldToNewMigration {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("OldToNew".to_owned(), 1)
    }

    fn execute(
        &self,
        _ledger_db: sov_rollup_interface::RefCount<LedgerDB>,
        _tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        Err(anyhow!("Could not fetch data"))
    }
}

#[test]
fn test_successful_migrations() {
    let ledger_db_path = tempfile::tempdir().unwrap();

    // Write some data to the pre-migrations version of the database.
    let ledger_db =
        LedgerDB::with_config(&RocksdbConfig::new(ledger_db_path.path(), None, None)).unwrap();

    let mut schema_batch = SchemaBatch::new();
    schema_batch
        .put::<TestTableOld>(&(), &vec![1, 2, 3, 4, 5])
        .unwrap();
    ledger_db.db.write_schemas(schema_batch).unwrap();
    drop(ledger_db);

    // Run migrations
    let ledger_db_migrator = LedgerDBMigrator::new(ledger_db_path.path(), successful_migrations());
    let ledger_tables = LEDGER_TABLES.iter().map(|x| x.to_string()).collect();

    assert!(matches!(
        ledger_db_migrator.migrate(None, ledger_tables),
        Ok(())
    ));

    // This instance is post-migrations DB.
    let ledger_db =
        LedgerDB::with_config(&RocksdbConfig::new(ledger_db_path.path(), None, None)).unwrap();

    // Check for:
    // 1. The new values are there
    assert_eq!(
        ledger_db.get_values().unwrap(),
        vec![
            (0u64, (0u64, 1u64)),
            (1u64, (1u64, 2u64)),
            (2u64, (2u64, 3u64)),
            (3u64, (3u64, 4u64)),
            (4u64, (4u64, 5u64))
        ]
    );
    // 2. DB has been recorded to be executed
    let executed_migrations = ledger_db.get_executed_migrations().unwrap();
    assert_eq!(executed_migrations.len(), 1);

    // 3. Table has been cleared
    let old_values = ledger_db.db.get::<TestTableOld>(&()).unwrap();
    assert_eq!(old_values, None);
}

#[test]
fn test_failed_migrations() {
    let ledger_db_path = tempfile::tempdir().unwrap();

    // Write some data to the pre-migrations version of the database.
    let ledger_db =
        LedgerDB::with_config(&RocksdbConfig::new(ledger_db_path.path(), None, None)).unwrap();

    let mut schema_batch = SchemaBatch::new();
    schema_batch
        .put::<TestTableOld>(&(), &vec![1, 2, 3, 4, 5])
        .unwrap();
    ledger_db.db.write_schemas(schema_batch).unwrap();
    drop(ledger_db);

    // Run migrations
    let ledger_db_migrator = LedgerDBMigrator::new(ledger_db_path.path(), failed_migrations());
    let ledger_tables = LEDGER_TABLES.iter().map(|x| x.to_string()).collect();
    assert!(ledger_db_migrator.migrate(None, ledger_tables).is_err());

    let ledger_db =
        LedgerDB::with_config(&RocksdbConfig::new(ledger_db_path.path(), None, None)).unwrap();
    let executed_migrations = ledger_db.get_executed_migrations().unwrap();
    assert_eq!(executed_migrations.len(), 0);
}

#[test]
fn test_pending_proofs_current_flow_rewrite_increases_disk_usage() {
    const PROOF_SIZE_BYTES: usize = 64 * 1024;
    const L1_CYCLES: usize = 40;
    let proof = pseudo_random_proof(PROOF_SIZE_BYTES);

    // Current behavior: while iterating pending proofs, first pending proof is stored again.
    let current_flow = simulate_pending_proof_cycles(proof.clone(), L1_CYCLES, true);
    // Expected fixed behavior: keep pending proof without rewriting identical value.
    let fixed_flow = simulate_pending_proof_cycles(proof, L1_CYCLES, false);

    // Enable this one-line dump when collecting numbers for issue/PR notes.
    // eprintln!(
    //     "pending_proofs_disk_repro proof_size_bytes={} l1_cycles={} current_rewrites={} fixed_rewrites={} current_pre_flush_db_bytes={} fixed_pre_flush_db_bytes={} current_post_flush_db_bytes={} fixed_post_flush_db_bytes={} current_live_bytes={} fixed_live_bytes={} current_total_sst_bytes={} fixed_total_sst_bytes={}",
    //     PROOF_SIZE_BYTES,
    //     L1_CYCLES,
    //     current_flow.rewrites,
    //     fixed_flow.rewrites,
    //     current_flow.pre_flush_db_bytes,
    //     fixed_flow.pre_flush_db_bytes,
    //     current_flow.post_flush_db_bytes,
    //     fixed_flow.post_flush_db_bytes,
    //     current_flow.live_bytes,
    //     fixed_flow.live_bytes,
    //     current_flow.total_sst_bytes,
    //     fixed_flow.total_sst_bytes,
    // );

    assert_eq!(
        current_flow.pending_rows, 1,
        "current flow must keep one pending proof row"
    );
    assert_eq!(
        fixed_flow.pending_rows, 1,
        "fixed flow must keep one pending proof row"
    );
    assert_eq!(
        current_flow.rewrites, L1_CYCLES,
        "current flow should rewrite on every cycle"
    );
    assert_eq!(
        fixed_flow.rewrites, 0,
        "fixed flow should not rewrite existing pending proof"
    );

    // This is the core reproduction: existing flow writes identical proof bytes on every cycle.
    assert!(
        current_flow.pre_flush_db_bytes > fixed_flow.pre_flush_db_bytes,
        "expected current flow to consume more disk before flush: current={} fixed={}",
        current_flow.pre_flush_db_bytes,
        fixed_flow.pre_flush_db_bytes
    );
    assert!(
        current_flow.post_flush_db_bytes >= fixed_flow.post_flush_db_bytes,
        "expected current flow to be no smaller after flush: current={} fixed={}",
        current_flow.post_flush_db_bytes,
        fixed_flow.post_flush_db_bytes
    );
    assert_eq!(
        current_flow.live_bytes, fixed_flow.live_bytes,
        "logical live data should be identical"
    );
    assert_eq!(
        current_flow.total_sst_bytes, fixed_flow.total_sst_bytes,
        "total SST footprint should converge for this synthetic setup"
    );
}

#[derive(Debug)]
struct PendingProofDiskMetrics {
    pending_rows: usize,
    rewrites: usize,
    pre_flush_db_bytes: u64,
    post_flush_db_bytes: u64,
    live_bytes: u64,
    total_sst_bytes: u64,
}

fn simulate_pending_proof_cycles(
    proof: Vec<u8>,
    l1_cycles: usize,
    rewrite_on_pending: bool,
) -> PendingProofDiskMetrics {
    const PENDING_PROOFS_CF: &str = "PendingProofs";
    const LIVE_DATA_SIZE_PROP: &str = "rocksdb.estimate-live-data-size";
    const TOTAL_SST_SIZE_PROP: &str = "rocksdb.total-sst-files-size";

    let ledger_db_path = tempfile::tempdir().unwrap();
    let ledger_db =
        LedgerDB::with_config(&RocksdbConfig::new(ledger_db_path.path(), None, None)).unwrap();
    ledger_db.store_pending_proof(1, 2, proof, 100).unwrap();

    let mut rewrites = 0usize;
    for _ in 0..l1_cycles {
        let mut pending_proofs = ledger_db.get_pending_proofs().unwrap();
        let Some(item) = pending_proofs.next() else {
            panic!("pending proof unexpectedly missing");
        };
        let ((min_index, max_index), (pending_proof, found_in_l1_height)) =
            item.unwrap().into_tuple();
        // Mirrors current fullnode behavior: on Pending, the same proof is written again.
        if rewrite_on_pending {
            ledger_db
                .store_pending_proof(min_index, max_index, pending_proof, found_in_l1_height)
                .unwrap();
            rewrites += 1;
        }
        // process_pending_proofs breaks on first pending proof.
    }

    let pending_rows = ledger_db
        .get_pending_proofs()
        .unwrap()
        .try_fold(0usize, |count, item| item.map(|_| count + 1))
        .unwrap();

    let pre_flush_db_bytes = dir_size_bytes(ledger_db.db.path());
    ledger_db.db.flush_cf(PENDING_PROOFS_CF).unwrap();
    let live_size = ledger_db
        .db
        .get_property(PENDING_PROOFS_CF, LIVE_DATA_SIZE_PROP)
        .unwrap();
    let total_sst_size = ledger_db
        .db
        .get_property(PENDING_PROOFS_CF, TOTAL_SST_SIZE_PROP)
        .unwrap();
    let post_flush_db_bytes = dir_size_bytes(ledger_db.db.path());

    PendingProofDiskMetrics {
        pending_rows,
        rewrites,
        pre_flush_db_bytes,
        post_flush_db_bytes,
        live_bytes: live_size,
        total_sst_bytes: total_sst_size,
    }
}

fn pseudo_random_proof(size: usize) -> Vec<u8> {
    // Deterministic bytes reduce test flakiness while keeping compression modest.
    let mut out = Vec::with_capacity(size);
    let mut x: u64 = 0x9e3779b97f4a7c15;
    for _ in 0..size {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let v = x.wrapping_mul(0x2545f4914f6cdd1d);
        out.push((v & 0xff) as u8);
    }
    out
}

fn dir_size_bytes(path: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };

    entries
        .filter_map(Result::ok)
        .map(|entry| {
            let Ok(metadata) = entry.metadata() else {
                return 0;
            };
            if metadata.is_dir() {
                dir_size_bytes(&entry.path())
            } else {
                metadata.len()
            }
        })
        .sum()
}

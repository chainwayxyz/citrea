use std::sync::Arc;

use sov_db::ledger_db::migrations::LedgerMigration;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::schema::types::SlotNumber;
use tracing::info;

/// Moves the L1 scan of a full node database that v2 left past L0, the L1 height of the
/// network's RISC0 cutoff, back to L0.
///
/// v2 can't read the SP1 batch proofs published after L0, so it discarded them without a trace.
/// Rescanning from L0 reads them again. Everything else v2 stored stays: its commitments are
/// the same, its proven heights come from RISC0 proofs it verified, and the rescan doesn't
/// record a status at an L1 height below v2's latest row, see `set_l2_height_status`.
pub struct RescanL1AfterRisc0Cutoff {
    /// L0, the L1 height of the network's RISC0 cutoff
    pub l0: u64,
}

impl LedgerMigration for RescanL1AfterRisc0Cutoff {
    fn identifier(&self) -> (String, u64) {
        ("rescan_l1_after_risc0_cutoff".to_string(), 1)
    }

    fn execute(
        &self,
        ledger_db: Arc<LedgerDB>,
        _tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        if let Some(last_scanned) = ledger_db.get_last_scanned_l1_height()? {
            if last_scanned.0 > self.l0 {
                info!(
                    "Rescanning L1 blocks {}-{} for the SP1 batch proofs v2 could not read",
                    self.l0 + 1,
                    last_scanned.0
                );
                ledger_db.set_last_scanned_l1_height(SlotNumber(self.l0))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use sov_db::ledger_db::migrations::{LedgerDBMigrator, Migrations};
    use sov_db::rocks_db_config::RocksdbConfig;
    use sov_db::schema::tables::FULL_NODE_LEDGER_TABLES;

    use super::*;

    const L0: u64 = 1000;

    fn migrations() -> Migrations {
        static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync>>> = OnceLock::new();
        MIGRATIONS.get_or_init(|| vec![Box::new(RescanL1AfterRisc0Cutoff { l0: L0 })])
    }

    /// A database v2 left past L0 goes back to L0 once. One at L0 and a new database keep their
    /// scan, and none of them rescans the blocks it reads later.
    #[test]
    fn rescans_from_l0_once() {
        let tables = FULL_NODE_LEDGER_TABLES
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        for (before, after) in [(Some(5000), Some(L0)), (Some(L0), Some(L0)), (None, None)] {
            let directory = tempfile::tempdir().unwrap();
            let open = || {
                LedgerDB::with_config(&RocksdbConfig::new(
                    directory.path(),
                    None,
                    Some(tables.clone()),
                ))
                .unwrap()
            };
            let migrate = || {
                LedgerDBMigrator::new(directory.path(), migrations())
                    .migrate(None, tables.clone())
                    .unwrap()
            };
            let last_scanned =
                |ledger_db: &LedgerDB| ledger_db.get_last_scanned_l1_height().unwrap().map(|h| h.0);

            if let Some(height) = before {
                open()
                    .set_last_scanned_l1_height(SlotNumber(height))
                    .unwrap();
            }
            migrate();
            let ledger_db = open();
            assert_eq!(last_scanned(&ledger_db), after, "{before:?}");

            // The node scans on and restarts
            ledger_db
                .set_last_scanned_l1_height(SlotNumber(6000))
                .unwrap();
            drop(ledger_db);
            migrate();
            assert_eq!(last_scanned(&open()), Some(6000), "{before:?}");
        }
    }
}

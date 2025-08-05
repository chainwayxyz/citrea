use std::sync::Arc;

use sov_db::ledger_db::migrations::LedgerMigration;
use sov_db::ledger_db::LedgerDB;
use tracing::info;

/// Migration to drop fullnode tables that were removed from SEQUENCER_LEDGER_TABLES
pub struct DropFullnodeTables;

impl LedgerMigration for DropFullnodeTables {
    fn identifier(&self) -> (String, u64) {
        ("drop_fullnode_tables".to_string(), 1)
    }

    fn execute(
        &self,
        _ledger_db: Arc<LedgerDB>,
        tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let fullnode_tables_to_drop = vec![
            "VerifiedBatchProofsBySlotNumber",
            "SlotByHash",
            "PendingSequencerCommitments",
            "ShortHeaderProofBySlotHash",
            "CommitmentMerkleRoots",
            "L2StatusHeights",
            "PendingProofs",
        ];

        for table in fullnode_tables_to_drop {
            tables_to_drop.push(table.to_string());
            info!("Removing table '{}'", table);
        }

        Ok(())
    }
}

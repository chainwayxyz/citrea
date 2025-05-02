use std::path::Path;
use std::sync::Arc;

use sov_db::ledger_db::migrations::{LedgerMigration, MigrationName, MigrationVersion};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::{PendingSequencerCommitments, FULL_NODE_LEDGER_TABLES};
use sov_rollup_interface::da::SequencerCommitment;
use sov_schema_db::SchemaBatch;

/// Table removal migration
/// tables BatchByNumber and SlotByNumber are removed
pub(crate) struct PendingCommitmentL1HeightFieldAdd {}

impl LedgerMigration for PendingCommitmentL1HeightFieldAdd {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("PendingCommitmentL1HeightFieldAdd".to_owned(), 1)
    }

    /// Pending commitments need l1 heights that they were found in.
    /// This migration adds the l1 height field to the pending commitments
    /// and updates the existing pending commitments with the l1 height,
    /// but because the ones that are already in the db cannot be known,
    /// the l1 height is set to 0.
    fn execute(
        &self,
        ledger_db: Arc<LedgerDB>,
        _tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let cf_handle = ledger_db
            .get_cf_handle("PendingSequencerCommitments")
            .unwrap();

        let iterator = ledger_db.get_iterator_for_cf(cf_handle, None).unwrap();

        // Store the original values
        let mut commitments = vec![];
        for res in iterator {
            let (_, value) = res.unwrap();
            let sequencer_commitment: SequencerCommitment =
                borsh::BorshDeserialize::deserialize(&mut &value[..]).unwrap();
            commitments.push(sequencer_commitment);
        }

        let mut schema_batch = SchemaBatch::new();

        // Overwrite new values
        for commitment in commitments {
            let key = commitment.index;
            let value = (commitment.clone(), 0u64);
            schema_batch
                .put::<PendingSequencerCommitments>(&key, &value)
                .unwrap();
        }
        ledger_db.inner().write_schemas(schema_batch).unwrap();
        Ok(())
    }
}

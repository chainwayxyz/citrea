use std::path::Path;
use std::sync::Arc;

use sov_db::ledger_db::migrations::{LedgerMigration, MigrationName, MigrationVersion};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::{PendingProofs, FULL_NODE_LEDGER_TABLES};
use sov_rollup_interface::zk::Proof;
use sov_schema_db::SchemaBatch;

/// Table value type change migration
/// Value has one more u64 field added to it
pub(crate) struct PendingProofsL1HeightFieldAdd {}

impl LedgerMigration for PendingProofsL1HeightFieldAdd {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("PendingProofsL1HeightFieldAdd".to_owned(), 2)
    }

    /// Pending proofs need l1 heights that they were found in.
    /// This migration adds the l1 height field to the pending proofs
    /// and updates the existing pending proofs with the l1 height,
    /// but because the ones that are already in the db cannot be known,
    /// the l1 height is set to 0.
    fn execute(
        &self,
        ledger_db: Arc<LedgerDB>,
        _tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let cf_handle = ledger_db.get_cf_handle("PendingProofs").unwrap();

        let iterator = ledger_db.get_iterator_for_cf(cf_handle, None).unwrap();

        // Store the original values
        let mut proofs = vec![];
        let mut keys = vec![];
        for res in iterator {
            let (key, value) = res.unwrap();
            let key: (u32, u32) = borsh::BorshDeserialize::deserialize(&mut &key[..]).unwrap();
            keys.push(key);
            let pending_proof: Proof =
                borsh::BorshDeserialize::deserialize(&mut &value[..]).unwrap();
            proofs.push(pending_proof);
        }

        let mut schema_batch = SchemaBatch::new();

        // Overwrite new values
        for (proof, key) in proofs.into_iter().zip(keys.iter()) {
            let value = (proof, 0u64);
            schema_batch.put::<PendingProofs>(key, &value).unwrap();
        }
        ledger_db.inner().write_schemas(schema_batch).unwrap();
        Ok(())
    }
}

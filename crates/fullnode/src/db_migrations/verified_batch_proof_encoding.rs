use std::sync::Arc;

use bincode::Options;
use sov_db::ledger_db::migrations::{LedgerMigration, MigrationName, MigrationVersion};
use sov_db::ledger_db::LedgerDB;
use sov_db::schema::types::SlotNumber;

/// Table removal migration
/// tables BatchByNumber and SlotByNumber are removed
pub(crate) struct FixVerifiedBatchProofsEncoding;

impl LedgerMigration for FixVerifiedBatchProofsEncoding {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("FixVerifiedBatchProofsEncoding".to_owned(), 4)
    }

    /// VerifiedBatchProofsBySlotNumber used to have default encoding which made keys to be encoded/decoded using borsh
    /// This caused problems when trying to seek for the biggest key in the database
    /// This migration uses seek key encoding and encodes keys with bincode fixint encoding to fix that issue
    fn execute(
        &self,
        ledger_db: Arc<LedgerDB>,
        _tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let cf_handle = ledger_db
            .get_cf_handle("VerifiedBatchProofsBySlotNumber")
            .unwrap();

        let iterator = ledger_db.get_iterator_for_cf(cf_handle, None).unwrap();

        for res in iterator {
            let (key, value) = res.unwrap();
            let key_deserialized: SlotNumber = borsh::from_slice(&key).unwrap();
            // Delete old key and insert new key
            ledger_db.delete_from_cf_raw(cf_handle, &key).unwrap();
            let bincode_options = bincode::options().with_fixint_encoding().with_big_endian();
            let seek_codec_serialized_key = bincode_options.serialize(&key_deserialized).unwrap();
            // value has the same (borsh) codec so no need to change it
            ledger_db
                .insert_into_cf_raw(cf_handle, &seek_codec_serialized_key, &value)
                .unwrap();
        }
        Ok(())
    }
}

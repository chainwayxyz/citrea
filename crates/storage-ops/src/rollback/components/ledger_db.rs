use std::sync::Arc;

/// Rollback native DB
pub(crate) fn rollback_ledger_db(_ledger_db: Arc<sov_schema_db::DB>, _down_to_block: u64) {}

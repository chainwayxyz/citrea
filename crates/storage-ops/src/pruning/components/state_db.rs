use std::sync::Arc;

/// Prune state DB
pub(crate) fn prune_state_db(_state_db: Arc<sov_schema_db::DB>, _up_to_block: u64) {}

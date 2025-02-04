use std::sync::Arc;

use tracing::{debug, error};

/// Prune state DB
pub(crate) fn prune_state_db(state_db: Arc<sov_schema_db::DB>, up_to_block: u64) {}

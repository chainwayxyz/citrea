use std::path::PathBuf;
use std::sync::Arc;

use citrea_storage_ops::pruning::{Pruner, PruningConfig};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::native_db::NativeDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::state_db::StateDB;
use tracing::{debug, info};

use super::StorageNodeTypeArg;
use crate::commands::cfs_from_node_type;

pub(crate) async fn prune(
    node_type: StorageNodeTypeArg,
    db_path: PathBuf,
    distance: u64,
) -> anyhow::Result<()> {
    info!(
        "Pruning DB at {} with pruning distance of {}",
        db_path.display(),
        distance
    );
    let config = PruningConfig { distance };

    let column_families = cfs_from_node_type(node_type);

    let rocksdb_config = RocksdbConfig::new(&db_path, None, Some(column_families.to_vec()));
    let ledger_db = LedgerDB::with_config(&rocksdb_config)?;
    let native_db = NativeDB::setup_schema_db(&rocksdb_config)?;
    let state_db = StateDB::setup_schema_db(&rocksdb_config)?;

    let Some(soft_confirmation_number) = ledger_db.get_head_soft_confirmation_height()? else {
        return Ok(());
    };
    let last_pruned_block_number = ledger_db.get_last_pruned_l2_height()?.unwrap_or(0);

    debug!(
        "Pruning up to latest soft confirmation number: {}, taking into consideration the configured distance of {}",
        soft_confirmation_number, distance
    );

    let pruner = Pruner::new(
        config,
        ledger_db.inner(),
        Arc::new(state_db),
        Arc::new(native_db),
    );
    if let Some(up_to_block) =
        pruner.should_prune(last_pruned_block_number, soft_confirmation_number)
    {
        pruner.prune(node_type.into(), up_to_block).await;
    }
    Ok(())
}

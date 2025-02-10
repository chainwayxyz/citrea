use std::path::PathBuf;
use std::sync::Arc;

use citrea_storage_ops::pruning::{Pruner, PruningConfig};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::native_db::NativeDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::state_db::StateDB;
use sov_prover_storage_manager::SnapshotManager;
use tracing::{debug, info};

pub(crate) async fn prune(db_path: PathBuf, distance: u64) -> anyhow::Result<()> {
    info!(
        "Pruning DB at {} with pruning distance of {}",
        db_path.display(),
        distance
    );
    let config = PruningConfig { distance };

    let rocksdb_config = RocksdbConfig::new(&db_path, None, None);
    let ledger_db = LedgerDB::with_config(&rocksdb_config)?;
    let native_db = NativeDB::<SnapshotManager>::setup_schema_db(&rocksdb_config)?;
    let state_db = StateDB::<SnapshotManager>::setup_schema_db(&rocksdb_config)?;

    let Some((soft_confirmation_number, _)) = ledger_db.get_head_soft_confirmation()? else {
        return Ok(());
    };

    debug!(
        "Pruning up to latest soft confirmation number: {}, taking into consideration the configured distance of {}",
        soft_confirmation_number.0, distance
    );

    let pruner = Pruner::new(config, ledger_db, Arc::new(state_db), Arc::new(native_db));
    pruner.prune(soft_confirmation_number.0).await;

    Ok(())
}

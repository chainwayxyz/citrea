use std::path::PathBuf;
use std::sync::Arc;

use citrea_storage_ops::rollback::Rollback;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::native_db::NativeDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::state_db::StateDB;
use tracing::info;

pub(crate) async fn rollback(db_path: PathBuf, num_blocks: u64) -> anyhow::Result<()> {
    info!(
        "Rolling back DB at {} {} down",
        db_path.display(),
        num_blocks
    );

    let rocksdb_config = RocksdbConfig::new(&db_path, None, None);
    let ledger_db = LedgerDB::with_config(&rocksdb_config)?;
    let native_db = NativeDB::setup_schema_db(&rocksdb_config)?;
    let state_db = StateDB::setup_schema_db(&rocksdb_config)?;

    let rollback = Rollback::new(ledger_db.inner(), Arc::new(state_db), Arc::new(native_db));
    rollback.execute(num_blocks).await?;

    Ok(())
}

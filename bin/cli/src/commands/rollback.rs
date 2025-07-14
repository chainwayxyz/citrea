use std::path::PathBuf;
use std::sync::Arc;

use citrea_storage_ops::rollback::Rollback;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::native_db::NativeDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::state_db::StateDB;
use tracing::info;

use super::NodeTypeArg;
use crate::commands::cfs_from_node_type;

pub(crate) async fn rollback(
    node_type: NodeTypeArg,
    db_path: PathBuf,
    l2_target: Option<u64>,
    l1_target: Option<u64>,
    last_sequencer_commitment_index: Option<u32>,
) -> anyhow::Result<()> {
    info!(
        "Rolling back DB at {} down to L2 {:?}, L1 {:?}",
        db_path.display(),
        l2_target,
        l1_target,
    );

    let column_families = cfs_from_node_type(node_type);

    let rocksdb_config = RocksdbConfig::new(&db_path, None, Some(column_families.to_vec()));
    let ledger_db = LedgerDB::with_config(&rocksdb_config)?;
    let native_db = NativeDB::setup_schema_db(&rocksdb_config)?;
    let state_db = StateDB::setup_schema_db(&rocksdb_config)?;

    let rollback = Rollback::new(ledger_db.inner(), Arc::new(state_db), Arc::new(native_db));
    rollback
        .execute(
            node_type.into(),
            l2_target,
            l1_target,
            last_sequencer_commitment_index,
        )
        .await?;

    Ok(())
}

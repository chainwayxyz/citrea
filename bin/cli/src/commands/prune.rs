use std::path::PathBuf;

use citrea_pruning::{Pruner, PruningConfig};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::rocks_db_config::RocksdbConfig;

pub(crate) fn prune(db_path: PathBuf, distance: u64) -> anyhow::Result<()> {
    let config = PruningConfig { distance };

    let rocksdb_config = RocksdbConfig::new(&db_path, None, None);
    let ledger_db = LedgerDB::with_config(&rocksdb_config)?;

    let last_pruned_block = ledger_db.get_last_pruned_l2_height()?.unwrap_or(0);
    let pruner = Pruner::new(config, last_pruned_block, l2_receiver, ledger_db)?;

    Ok(())
}

use std::path::Path;

use sov_schema_db::DB;

use crate::ledger_db::{LedgerDB, LEDGER_TABLES};
use crate::rocks_db_config::RocksdbConfig;

/// Drop a column family from the database
pub fn drop_column_families(cfg: &RocksdbConfig, cf_names: Vec<String>) -> anyhow::Result<()> {
    let path = cfg.path.join(LedgerDB::DB_PATH_SUFFIX);
    let raw_options = cfg.as_raw_options(false);
    let mut inner = DB::open(
        path,
        LedgerDB::DB_NAME,
        cfg.column_families
            .clone()
            .unwrap_or_else(|| LEDGER_TABLES.iter().map(|s| s.to_string()).collect()),
        &raw_options,
    )?;

    for cf_name in cf_names {
        inner.drop_cf(&cf_name)?;
    }

    Ok(())
}

/// List all column families in the database
pub fn list_column_families(path: &Path) -> Vec<String> {
    rocksdb::DB::list_cf(
        &rocksdb::Options::default(),
        path.join(LedgerDB::DB_PATH_SUFFIX),
    )
    .unwrap()
}

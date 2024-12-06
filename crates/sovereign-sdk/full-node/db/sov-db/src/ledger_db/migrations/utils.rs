use std::path::Path;

use sov_schema_db::DB;

use crate::ledger_db::{LEDGER_DB_PATH_SUFFIX, LEDGER_TABLES};
use crate::rocks_db_config::RocksdbConfig;

/// Drop a column family from the database
pub fn drop_column_family(cfg: &RocksdbConfig, cf_name: &str) -> anyhow::Result<()> {
    let path = cfg.path.join(LEDGER_DB_PATH_SUFFIX);
    let raw_options = cfg.as_raw_options(false);
    let mut inner = DB::open(
        path,
        "ledger-db",
        cfg.column_families
            .clone()
            .unwrap_or_else(|| LEDGER_TABLES.iter().map(|s| s.to_string()).collect()),
        &raw_options,
    )?;

    inner.drop_cf(cf_name)?;

    Ok(())
}

/// List all column families in the database
pub fn list_column_families(path: &Path) -> Vec<String> {
    rocksdb::DB::list_cf(
        &rocksdb::Options::default(),
        path.join(LEDGER_DB_PATH_SUFFIX),
    )
    .unwrap()
}

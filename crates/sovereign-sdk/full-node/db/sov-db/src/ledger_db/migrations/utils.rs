use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_rollup_interface::da::{DaSpec, SequencerCommitment};
use sov_rollup_interface::fork::{Fork, ForkMigration};
use sov_rollup_interface::services::da::SlotData;
use sov_rollup_interface::stf::{BatchReceipt, SoftConfirmationReceipt, StateDiff};
use sov_rollup_interface::zk::Proof;
use sov_schema_db::{Schema, SchemaBatch, SeekKeyEncoder, DB};
use tracing::instrument;

use crate::rocks_db_config::RocksdbConfig;

/// Drop a column family from the database
pub fn drop_cf(
    cfg: &RocksdbConfig,
    column_families: Option<Vec<String>>,
    cf_name: &str,
) -> anyhow::Result<()> {
    let path = cfg.path.join(LEDGER_DB_PATH_SUFFIX);
    let raw_options = cfg.as_raw_options(false);
    let mut inner = DB::open(
        path,
        "ledger-db",
        column_families.unwrap_or_else(|| LEDGER_TABLES.iter().map(|s| s.to_string()).collect()),
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

use std::path::PathBuf;

use sov_db::ledger_db::migrations::utils::drop_column_families;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::{PendingProofs, PendingSequencerCommitments};
use tracing::info;

use crate::commands::{cfs_from_node_type, StorageNodeTypeArg};

/// Clear pending commitments and proofs
/// Use with caution as this can lead to a stuck node. Should be used alongside rollback
/// TODO remove and properly index so that this can be rolled back by l1 block by mainnet
pub(crate) async fn clear_pending_proofs_and_commitments(db_path: PathBuf) -> anyhow::Result<()> {
    info!(
        "Clearing pending commitments and proofs for DB at {}",
        db_path.display(),
    );

    let column_families = cfs_from_node_type(StorageNodeTypeArg::FullNode);
    drop_column_families(
        &RocksdbConfig::new(&db_path, None, Some(column_families)),
        vec![
            PendingProofs::table_name().to_string(),
            PendingSequencerCommitments::table_name().to_string(),
        ],
    )?;
    Ok(())
}

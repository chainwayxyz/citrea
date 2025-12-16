use std::path::PathBuf;

use sov_db::ledger_db::migrations::LedgerDBMigrator;
use tracing::info;

use super::NodeTypeArg;
use crate::commands::cfs_from_node_type;

pub(crate) async fn db_migrate(
    node_type: NodeTypeArg,
    db_path: PathBuf,
    db_max_open_files: Option<i32>,
) -> anyhow::Result<()> {
    info!(
        "Running database migrations for {} at {}",
        node_type,
        db_path.display()
    );

    let column_families = cfs_from_node_type(node_type);

    // Get migrations list based on node type
    let migrations = match node_type {
        NodeTypeArg::Sequencer => citrea_sequencer::db_migrations::migrations(),
        NodeTypeArg::FullNode => citrea_fullnode::db_migrations::migrations(),
        NodeTypeArg::BatchProver => citrea_batch_prover::db_migrations::migrations(),
        NodeTypeArg::LightClientProver => citrea_light_client_prover::db_migrations::migrations(),
    };

    info!("Found {} registered migrations", migrations.len());

    // Create migrator and execute migrations
    let migrator = LedgerDBMigrator::new(&db_path, migrations);
    migrator.migrate(db_max_open_files, column_families)?;

    info!("Database migration completed successfully");

    Ok(())
}

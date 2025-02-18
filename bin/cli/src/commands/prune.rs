use std::path::PathBuf;
use std::sync::Arc;

use citrea_storage_ops::pruning::types::PruningNodeType;
use citrea_storage_ops::pruning::{Pruner, PruningConfig};
use clap::ValueEnum;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::native_db::NativeDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::{
    BATCH_PROVER_LEDGER_TABLES, FULL_NODE_LEDGER_TABLES, LIGHT_CLIENT_PROVER_LEDGER_TABLES,
    SEQUENCER_LEDGER_TABLES,
};
use sov_db::state_db::StateDB;
use tracing::{debug, info};

#[derive(Copy, Clone, ValueEnum)]
pub enum PruningNodeTypeArg {
    Sequencer,
    FullNode,
    BatchProver,
    LightClient,
}

impl From<PruningNodeTypeArg> for PruningNodeType {
    fn from(value: PruningNodeTypeArg) -> Self {
        match value {
            PruningNodeTypeArg::Sequencer => PruningNodeType::Sequencer,
            PruningNodeTypeArg::FullNode => PruningNodeType::FullNode,
            PruningNodeTypeArg::BatchProver => PruningNodeType::BatchProver,
            PruningNodeTypeArg::LightClient => PruningNodeType::LightClient,
        }
    }
}

pub(crate) async fn prune(
    node_type: PruningNodeTypeArg,
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

fn cfs_from_node_type(node_type: PruningNodeTypeArg) -> Vec<String> {
    let cfs = match node_type {
        PruningNodeTypeArg::Sequencer => SEQUENCER_LEDGER_TABLES,
        PruningNodeTypeArg::FullNode => FULL_NODE_LEDGER_TABLES,
        PruningNodeTypeArg::BatchProver => BATCH_PROVER_LEDGER_TABLES,
        PruningNodeTypeArg::LightClient => LIGHT_CLIENT_PROVER_LEDGER_TABLES,
    };

    cfs.iter().map(|x| x.to_string()).collect::<Vec<_>>()
}

use std::path::PathBuf;

use citrea_storage_ops::types::NodeKind;
use clap::{Parser, Subcommand, ValueEnum};
use commands::StorageNodeTypeArg;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod commands;

#[derive(Clone, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum NodeKindArg {
    BatchProver,
    Sequencer,
    FullNode,
    LightClientProver,
}

impl std::fmt::Display for NodeKindArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeKindArg::BatchProver => write!(f, "batch-prover"),
            NodeKindArg::Sequencer => write!(f, "sequencer"),
            NodeKindArg::FullNode => write!(f, "full-node"),
            NodeKindArg::LightClientProver => write!(f, "light-client-prover"),
        }
    }
}

impl From<NodeKindArg> for NodeKind {
    fn from(value: NodeKindArg) -> Self {
        match value {
            NodeKindArg::Sequencer => NodeKind::Sequencer,
            NodeKindArg::FullNode => NodeKind::FullNode,
            NodeKindArg::BatchProver => NodeKind::BatchProver,
            NodeKindArg::LightClientProver => NodeKind::LightClientProver,
        }
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Prune old DB entries
    Prune {
        #[arg(long)]
        node_type: StorageNodeTypeArg,
        /// The path of the database to prune
        #[arg(long)]
        db_path: PathBuf,
        /// The distance of the last pruned block to prune up to
        #[arg(long)]
        distance: u64,
    },
    /// Rollback the most recent N blocks
    Rollback {
        #[arg(long)]
        node_type: StorageNodeTypeArg,
        /// The path of the database to prune
        #[arg(long)]
        db_path: PathBuf,
        /// The target L2 block number to rollback to (non-inclusive)
        #[arg(long)]
        l2_target: Option<u64>,
        /// The target L1 block number to rollback to (non-inclusive)
        #[arg(long)]
        l1_target: Option<u64>,
        /// The target sequencer commitment index to rollback to
        #[arg(long)]
        sequencer_commitment_index: Option<u32>,
    },
    /// Backup DBs
    RestoreBackup {
        /// The node kind
        #[arg(long)]
        node_kind: NodeKindArg,
        /// The path of the databases to restore to
        #[arg(long)]
        db_path: PathBuf,
        /// The backup path
        #[arg(long)]
        backup_path: PathBuf,
        /// The backup ID
        #[arg(long)]
        backup_id: u32,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry().with(fmt::layer()).init();

    let cli = Cli::parse();

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match cli.command {
        Commands::Prune {
            node_type,
            db_path,
            distance,
        } => {
            commands::prune(node_type, db_path.clone(), distance).await?;
        }
        Commands::Rollback {
            node_type,
            db_path,
            l2_target,
            l1_target,
            sequencer_commitment_index,
        } => {
            if l2_target.is_none() && l1_target.is_none() && sequencer_commitment_index.is_none() {
                println!("Missing L2/L1 target or sequencer commitment");
                return Ok(());
            }
            commands::rollback(
                node_type,
                db_path.clone(),
                l2_target,
                l1_target,
                sequencer_commitment_index,
            )
            .await?;
        }
        Commands::RestoreBackup {
            db_path,
            backup_path,
            node_kind,
            backup_id,
        } => {
            commands::restore_backup(node_kind.into(), db_path, backup_path, backup_id).await?;
        }
    }

    Ok(())
}

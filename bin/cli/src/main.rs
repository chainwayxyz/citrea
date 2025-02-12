use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod commands;

#[derive(Clone, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum NodeKind {
    BatchProver,
    Sequencer,
    FullNode,
    LightClientProver,
}

impl std::fmt::Display for NodeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeKind::BatchProver => write!(f, "batch-prover"),
            NodeKind::Sequencer => write!(f, "sequencer"),
            NodeKind::FullNode => write!(f, "full-node"),
            NodeKind::LightClientProver => write!(f, "light-client-prover"),
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
        /// The path of the database to prune
        #[arg(long)]
        db_path: PathBuf,
        /// The distance of the last pruned block to prune up to
        #[arg(long)]
        distance: u64,
    },
    /// Rollback the most recent N blocks
    Rollback {
        /// The path of the database to prune
        #[arg(long)]
        db_path: PathBuf,
        /// The number of blocks to rollback
        #[arg(long)]
        blocks: u32,
    },
    /// Backup DBs
    Backup {
        /// The node kind
        #[arg(long)]
        node_kind: NodeKind,
        /// The path of the databases to restore to
        #[arg(long)]
        db_path: PathBuf,
        /// The backup path
        #[arg(long)]
        backup_path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry().with(fmt::layer()).init();

    let cli = Cli::parse();

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match cli.command {
        Commands::Prune { db_path, distance } => {
            commands::prune(db_path.clone(), distance).await?;
        }
        Commands::Rollback {
            db_path: _db_path,
            blocks,
        } => {
            commands::rollback(blocks).await?;
        }
        Commands::Backup {
            db_path,
            backup_path,
            node_kind,
        } => {
            commands::restore_backup(node_kind.to_string(), db_path, backup_path).await?;
        }
    }

    Ok(())
}

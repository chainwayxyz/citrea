use std::path::PathBuf;

use clap::{Parser, Subcommand};
use commands::NodeTypeArg;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod commands;

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
        node_type: NodeTypeArg,
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
        node_type: NodeTypeArg,
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
    /// Restore DBs from backup
    RestoreBackup {
        /// The node kind
        #[arg(long)]
        node_type: NodeTypeArg,
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
    /// Purge backups up to backup ID
    PurgeBackup {
        /// The backup path
        #[arg(long)]
        backup_path: PathBuf,
        /// The backup ID to purge up to (exclusive)
        #[arg(
            long,
            conflicts_with = "num_to_keep",
            required_unless_present = "num_to_keep"
        )]
        backup_id: Option<u32>,

        /// Number of most recent backups to keep
        #[arg(
            long,
            conflicts_with = "backup_id",
            required_unless_present = "backup_id"
        )]
        num_to_keep: Option<u32>,
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
            node_type,
            backup_id,
        } => {
            commands::restore_backup(node_type.into(), db_path, backup_path, backup_id).await?;
        }
        Commands::PurgeBackup {
            backup_path,
            backup_id,
            num_to_keep,
        } => {
            commands::purge_backup(backup_path, num_to_keep, backup_id).await?;
        }
    }

    Ok(())
}

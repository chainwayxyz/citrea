use std::path::PathBuf;

use clap::{Parser, Subcommand};
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry().with(fmt::layer()).init();

    let cli = Cli::parse();

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Commands::Prune { db_path, distance } => {
            commands::prune(db_path.clone(), *distance).await?;
        }
        Commands::Rollback {
            db_path: _db_path,
            blocks,
        } => {
            commands::rollback(*blocks).await?;
        }
    }

    Ok(())
}

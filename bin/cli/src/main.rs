use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
        blocks: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Commands::Prune { db_path, distance } => {
            println!("Pruning stuff: {:?}, distance: {}", db_path, distance);
        }
        Commands::Rollback { db_path, blocks } => {
            println!("Rolling back stuff: {:?}, blocks: {}", db_path, blocks);
        }
    }
}

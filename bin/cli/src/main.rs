use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Prune database
    Prune {
        db_path: PathBuf,
    },
    Rollback {
        db_path: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Commands::Prune { db_path } => {
            println!("Pruning stuff: {:?}", db_path);
        }
        Commands::Rollback { db_path } => {
            println!("Rolling back stuff: {:?}", db_path);
        }
    }
}

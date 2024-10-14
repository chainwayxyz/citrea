use core::fmt::Debug as DebugTrait;

use anyhow::Context as _;
use bitcoin_da::service::BitcoinServiceConfig;
use citrea::{initialize_logging, BitcoinRollup, CitreaRollupBlueprint, MockDemoRollup};
use citrea_common::{from_toml_path, FromEnv, FullNodeConfig, ProverConfig, SequencerConfig};
use citrea_stf::genesis_config::GenesisPaths;
use clap::Parser;
use sov_mock_da::MockDaConfig;
use sov_modules_api::Spec;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_state::storage::NativeStorage;
use tracing::{error, instrument};

#[cfg(test)]
mod test_rpc;

/// Main runner. Initializes a DA service, and starts a node using the provided arguments.

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the genesis configuration.
    /// Defines the genesis of module states like evm.
    #[arg(long)]
    genesis_paths: String,

    /// The data layer type.
    #[arg(long, default_value = "mock")]
    da_layer: SupportedDaLayer,

    /// The path to the rollup config.
    #[arg(long, default_value = "resources/configs/mock/rollup_config.toml")]
    rollup_config_path: String,

    /// The option to run the node in sequencer mode, if a string is provided, it will be used as the path to the sequencer config, otherwise environment variables will be used.
    #[arg(long, conflicts_with = "prover")]
    sequencer: Option<Option<String>>,

    /// The option to run the node in prover mode, if a string is provided, it will be used as the path to the prover config, otherwise the environment variables will be used.
    #[arg(long, conflicts_with = "sequencer")]
    prover: Option<Option<String>>,

    /// Logging verbosity
    #[arg(long, short = 'v', action = clap::ArgAction::Count, default_value = "2")]
    verbose: u8,
    /// Logging verbosity
    #[arg(long, short = 'q', action)]
    quiet: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum SupportedDaLayer {
    Mock,
    Bitcoin,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut args = Args::parse();

    if args.quiet {
        args.verbose = 0;
    }
    let logging_level = match args.verbose {
        0 => tracing::Level::ERROR,
        1 => tracing::Level::WARN,
        2 => tracing::Level::INFO,
        3 => tracing::Level::DEBUG,
        4 => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    };
    initialize_logging(logging_level);

    let rollup_config_path = args.rollup_config_path.as_str();

    let sequencer_config = match args.sequencer {
        Some(Some(path)) => Some(
            from_toml_path(path)
                .context("Failed to read sequencer configuration from the config file")?,
        ),
        Some(None) => Some(
            SequencerConfig::from_env()
                .context("Failed to read sequencer configuration from the environment")?,
        ),
        None => None,
    };
    let prover_config = match args.prover {
        Some(Some(path)) => Some(
            from_toml_path(path)
                .context("Failed to read prover configuration from the config file")?,
        ),
        Some(None) => Some(
            ProverConfig::from_env()
                .context("Failed to read prover configuration from the environment")?,
        ),
        None => None,
    };

    if prover_config.is_some() && sequencer_config.is_some() {
        return Err(anyhow::anyhow!(
            "Cannot run in both prover and sequencer mode at the same time"
        ));
    }

    match args.da_layer {
        SupportedDaLayer::Mock => {
            start_rollup::<MockDemoRollup, MockDaConfig>(
                &GenesisPaths::from_dir(&args.genesis_paths),
                rollup_config_path,
                prover_config,
                sequencer_config,
            )
            .await?;
        }
        SupportedDaLayer::Bitcoin => {
            start_rollup::<BitcoinRollup, BitcoinServiceConfig>(
                &GenesisPaths::from_dir(&args.genesis_paths),
                rollup_config_path,
                prover_config,
                sequencer_config,
            )
            .await?;
        }
    }

    Ok(())
}

#[instrument(level = "trace", skip_all, err)]
async fn start_rollup<S, DaC>(
    rt_genesis_paths: &<<S as RollupBlueprint>::NativeRuntime as sov_modules_stf_blueprint::Runtime<
        <S as RollupBlueprint>::NativeContext,
        <S as RollupBlueprint>::DaSpec,
    >>::GenesisPaths,
    rollup_config_path: &str,
    prover_config: Option<ProverConfig>,
    sequencer_config: Option<SequencerConfig>,
) -> Result<(), anyhow::Error>
where
    DaC: serde::de::DeserializeOwned + DebugTrait + Clone + FromEnv,
    S: CitreaRollupBlueprint<DaConfig = DaC>,
    <<S as RollupBlueprint>::NativeContext as Spec>::Storage: NativeStorage,
{
    let rollup_config: FullNodeConfig<DaC> =
        from_toml_path(rollup_config_path).unwrap_or_else(|_| {
            FullNodeConfig::<DaC>::from_env()
                .context("Failed to read rollup configuration")
                .unwrap()
        });
    let rollup_blueprint = S::new();

    if let Some(sequencer_config) = sequencer_config {
        let sequencer_rollup = rollup_blueprint
            .create_new_sequencer(rt_genesis_paths, rollup_config.clone(), sequencer_config)
            .await
            .expect("Could not start sequencer");
        if let Err(e) = sequencer_rollup.run().await {
            error!("Error: {}", e);
        }
    } else if let Some(prover_config) = prover_config {
        let prover = CitreaRollupBlueprint::create_new_prover(
            &rollup_blueprint,
            rt_genesis_paths,
            rollup_config,
            prover_config,
        )
        .await
        .expect("Coult not start prover");
        if let Err(e) = prover.run().await {
            error!("Error: {}", e);
        }
    } else {
        let rollup = CitreaRollupBlueprint::create_new_rollup(
            &rollup_blueprint,
            rt_genesis_paths,
            rollup_config,
        )
        .await
        .expect("Could not start full-node");
        if let Err(e) = rollup.run().await {
            error!("Error: {}", e);
        }
    }

    Ok(())
}

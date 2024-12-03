use core::fmt::Debug as DebugTrait;

use anyhow::Context as _;
use bitcoin_da::service::BitcoinServiceConfig;
use citrea::{
    initialize_logging, BitcoinRollup, CitreaRollupBlueprint, MockDemoRollup, NetworkArg,
};
use citrea_common::{
    from_toml_path, BatchProverConfig, FromEnv, FullNodeConfig, LightClientProverConfig,
    SequencerConfig,
};
use citrea_stf::genesis_config::GenesisPaths;
use clap::Parser;
use sov_mock_da::MockDaConfig;
use sov_modules_api::Spec;
use sov_modules_rollup_blueprint::{Network, RollupBlueprint};
use sov_state::storage::NativeStorage;
use tracing::{error, info, instrument};

#[cfg(test)]
mod test_rpc;

/// Main runner. Initializes a DA service, and starts a node using the provided arguments.

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The mode in which the node runs.
    /// This determines which guest code to use.
    /// Default is Mainnet.
    #[clap(short, long, default_value_t, value_enum)]
    network: NetworkArg,

    /// Override network to run testnet directly.
    #[arg(long)]
    testnet: bool,

    /// Run the development chain
    #[arg(long, conflicts_with_all = ["testnet"])]
    dev: bool,

    /// Path to the genesis configuration.
    /// Defines the genesis of module states like evm.
    #[arg(long)]
    genesis_paths: String,

    /// The data layer type.
    #[arg(long, default_value = "mock")]
    da_layer: SupportedDaLayer,

    /// The path to the rollup config, if a string is provided, it will be used as the path to the rollup config, otherwise environment variables will be used.
    #[arg(long)]
    rollup_config_path: Option<String>,

    /// The option to run the node in sequencer mode, if a string is provided, it will be used as the path to the sequencer config, otherwise environment variables will be used.
    #[arg(long, conflicts_with_all = ["batch_prover", "light_client_prover"])]
    sequencer: Option<Option<String>>,

    /// The option to run the node in batch prover mode, if a string is provided, it will be used as the path to the batch prover config, otherwise the environment variables will be used.
    #[arg(long, conflicts_with_all = ["sequencer", "light_client_prover"])]
    batch_prover: Option<Option<String>>,

    /// The option to run the node in light client prover mode, if a string is provided, it will be used as the path to the light client prover config, otherwise the environment variables will be used.
    #[arg(long, conflicts_with_all = ["sequencer", "batch_prover"])]
    light_client_prover: Option<Option<String>>,

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

    let batch_prover_config = match args.batch_prover {
        Some(Some(path)) => Some(
            from_toml_path(path)
                .context("Failed to read prover configuration from the config file")?,
        ),
        Some(None) => Some(
            BatchProverConfig::from_env()
                .context("Failed to read prover configuration from the environment")?,
        ),
        None => None,
    };

    let light_client_prover_config = match args.light_client_prover {
        Some(Some(path)) => Some(
            from_toml_path(path)
                .context("Failed to read prover configuration from the config file")?,
        ),
        Some(None) => Some(
            LightClientProverConfig::from_env()
                .context("Failed to read prover configuration from the environment")?,
        ),
        None => None,
    };

    if batch_prover_config.is_some() && sequencer_config.is_some() {
        return Err(anyhow::anyhow!(
            "Cannot run in both batch prover and sequencer mode at the same time"
        ));
    }
    if batch_prover_config.is_some() && light_client_prover_config.is_some() {
        return Err(anyhow::anyhow!(
            "Cannot run in both batch prover and light client prover mode at the same time"
        ));
    }
    if light_client_prover_config.is_some() && sequencer_config.is_some() {
        return Err(anyhow::anyhow!(
            "Cannot run in both light client prover and sequencer mode at the same time"
        ));
    }

    let mut network = args.network.into();
    if args.testnet {
        network = Network::Testnet;
    } else if args.dev {
        network = Network::Nightly;
    }

    info!("Starting node on {network}");

    match args.da_layer {
        SupportedDaLayer::Mock => {
            start_rollup::<MockDemoRollup, MockDaConfig>(
                network,
                &GenesisPaths::from_dir(&args.genesis_paths),
                args.rollup_config_path,
                batch_prover_config,
                light_client_prover_config,
                sequencer_config,
            )
            .await?;
        }
        SupportedDaLayer::Bitcoin => {
            start_rollup::<BitcoinRollup, BitcoinServiceConfig>(
                network,
                &GenesisPaths::from_dir(&args.genesis_paths),
                args.rollup_config_path,
                batch_prover_config,
                light_client_prover_config,
                sequencer_config,
            )
            .await?;
        }
    }

    Ok(())
}

#[instrument(level = "trace", skip_all, err)]
async fn start_rollup<S, DaC>(
    network: Network,
    rt_genesis_paths: &<<S as RollupBlueprint>::NativeRuntime as sov_modules_stf_blueprint::Runtime<
        <S as RollupBlueprint>::NativeContext,
        <S as RollupBlueprint>::DaSpec,
    >>::GenesisPaths,
    rollup_config_path: Option<String>,
    batch_prover_config: Option<BatchProverConfig>,
    light_client_prover_config: Option<LightClientProverConfig>,
    sequencer_config: Option<SequencerConfig>,
) -> Result<(), anyhow::Error>
where
    DaC: serde::de::DeserializeOwned + DebugTrait + Clone + FromEnv,
    S: CitreaRollupBlueprint<DaConfig = DaC>,
    <<S as RollupBlueprint>::NativeContext as Spec>::Storage: NativeStorage,
{
    let rollup_config: FullNodeConfig<DaC> = match rollup_config_path {
        Some(path) => from_toml_path(path)
            .context("Failed to read rollup configuration from the config file")?,
        None => FullNodeConfig::from_env()
            .context("Failed to read rollup configuration from the environment")?,
    };
    let rollup_blueprint = S::new(network);

    if let Some(sequencer_config) = sequencer_config {
        let sequencer_rollup = rollup_blueprint
            .create_new_sequencer(rt_genesis_paths, rollup_config.clone(), sequencer_config)
            .await
            .expect("Could not start sequencer");
        if let Err(e) = sequencer_rollup.run().await {
            error!("Error: {}", e);
        }
    } else if let Some(batch_prover_config) = batch_prover_config {
        let prover = CitreaRollupBlueprint::create_new_batch_prover(
            &rollup_blueprint,
            rt_genesis_paths,
            rollup_config,
            batch_prover_config,
        )
        .await
        .expect("Could not start batch prover");
        if let Err(e) = prover.run().await {
            error!("Error: {}", e);
        }
    } else if let Some(light_client_prover_config) = light_client_prover_config {
        let prover = CitreaRollupBlueprint::create_new_light_client_prover(
            &rollup_blueprint,
            rollup_config,
            light_client_prover_config,
        )
        .await
        .expect("Could not start light client prover");
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

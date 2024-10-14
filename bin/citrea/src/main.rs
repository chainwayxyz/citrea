use core::fmt::Debug as DebugTrait;

use anyhow::Context as _;
use bitcoin_da::service::BitcoinServiceConfig;
use citrea::{initialize_logging, BitcoinRollup, CitreaRollupBlueprint, MockDemoRollup};
use citrea_common::{from_toml_path, FullNodeConfig, BatchProverConfig, LightClientProverConfig, SequencerConfig};
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

    /// The path to the sequencer config. If set, runs the node in sequencer mode, otherwise in full node mode.
    #[arg(long, conflicts_with_all = ["batch_prover_config_path", "light_client_prover_config_path"])]
    sequencer_config_path: Option<String>,

    /// The path to the batch prover config. If set, runs the node in batch prover mode, otherwise in full node mode.
    #[arg(long, conflicts_with_all = ["sequencer_config_path", "light_client_prover_config_path"])]
    batch_prover_config_path: Option<String>,

    /// The path to the light client prover config. If set, runs the node in light client prover mode, otherwise in full node mode.
    #[arg(long, conflicts_with_all = ["sequencer_config_path", "batch_prover_config_path"])]
    light_client_prover_config_path: Option<String>,

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

    let sequencer_config: Option<SequencerConfig> =
        args.sequencer_config_path.clone().map(|path| {
            from_toml_path(path)
                .context("Failed to read sequencer configuration")
                .unwrap()
        });

    let batch_prover_config: Option<BatchProverConfig> =
        args.batch_prover_config_path.clone().map(|path| {
            from_toml_path(path)
                .context("Failed to read batch prover configuration")
                .unwrap()
        });

    let light_client_prover_config: Option<LightClientProverConfig> =
        args.light_client_prover_config_path.clone().map(|path| {
            from_toml_path(path)
                .context("Failed to read light client prover configuration")
                .unwrap()
        });

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

    match args.da_layer {
        SupportedDaLayer::Mock => {
            start_rollup::<MockDemoRollup, MockDaConfig>(
                &GenesisPaths::from_dir(&args.genesis_paths),
                rollup_config_path,
                batch_prover_config,
                light_client_prover_config,
                sequencer_config,
            )
            .await?;
        }
        SupportedDaLayer::Bitcoin => {
            start_rollup::<BitcoinRollup, BitcoinServiceConfig>(
                &GenesisPaths::from_dir(&args.genesis_paths),
                rollup_config_path,
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
    rt_genesis_paths: &<<S as RollupBlueprint>::NativeRuntime as sov_modules_stf_blueprint::Runtime<
        <S as RollupBlueprint>::NativeContext,
        <S as RollupBlueprint>::DaSpec,
    >>::GenesisPaths,
    rollup_config_path: &str,
    batch_prover_config: Option<BatchProverConfig>,
    light_client_prover_config: Option<LightClientProverConfig>,
    sequencer_config: Option<SequencerConfig>,
) -> Result<(), anyhow::Error>
where
    DaC: serde::de::DeserializeOwned + DebugTrait + Clone,
    S: CitreaRollupBlueprint<DaConfig = DaC>,
    <<S as RollupBlueprint>::NativeContext as Spec>::Storage: NativeStorage,
{
    let rollup_config: FullNodeConfig<DaC> = from_toml_path(rollup_config_path)
        .context("Failed to read rollup configuration")
        .unwrap();
    let rollup_blueprint = S::new();

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

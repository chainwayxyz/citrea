use core::fmt::Debug as DebugTrait;
use std::env;
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context as _};
use bitcoin_da::service::{BitcoinService, DaServiceConfig};
use bitcoin_da::spec::RollupParams;
use chainway_sequencer::ChainwaySequencer;
use clap::Parser;
use const_rollup_config::{ROLLUP_NAME, TEST_PRIVATE_KEY};
use demo_stf::genesis_config::GenesisPaths;
use sequencer_client::SequencerClient;
use serde::de::DeserializeOwned;
use sov_celestia_adapter::{CelestiaConfig, CelestiaService};
use sov_demo_rollup::{BitcoinRollup, CelestiaDemoRollup, MockDemoRollup};
use sov_mock_da::{MockDaConfig, MockDaService};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::Spec;
use sov_modules_rollup_blueprint::{Rollup, RollupBlueprint};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::ProverConfig;
use sov_state::storage::NativeStorage;
use sov_state::Storage;
use sov_stf_runner::{from_toml_path, RollupConfig, RollupProverConfig};
use tracing::log::debug;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[cfg(test)]
mod test_rpc;

/// Main demo runner. Initializes a DA chain, and starts a demo-rollup using the provided.
/// If you're trying to sign or submit transactions to the rollup, the `sov-cli` binary
/// is the one you want. You can run it `cargo run --bin sov-cli`.

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The data layer type.
    #[arg(long, default_value = "mock")]
    da_layer: SupportedDaLayer,

    /// The path to the rollup config.
    #[arg(long, default_value = "mock_rollup_config.toml")]
    rollup_config_path: String,

    /// If set, runs the node in sequencer mode, otherwise in full node mode.
    #[arg(long)]
    sequence: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum SupportedDaLayer {
    Celestia,
    Mock,
    Bitcoin,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Initializing logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_str(
                &env::var("RUST_LOG")
                    .unwrap_or_else(|_| "debug,hyper=info,risc0_zkvm=info".to_string()),
            )
            .unwrap(),
        )
        .init();

    let args = Args::parse();
    let rollup_config_path = args.rollup_config_path.as_str();

    match args.da_layer {
        SupportedDaLayer::Mock => {
            // create_config_generic::<MockDaConfig>(rollup_config_path);

            // let rollup_config: RollupConfig<MockDaConfig> = from_toml_path(rollup_config_path)
            //     .context("Failed to read rollup configuration")?;
            start_rollup::<MockDemoRollup, MockDaConfig>(
                //rollup_config,
                rollup_config_path,
                RollupProverConfig::Execute,
                &GenesisPaths::from_dir("../test-data/genesis/demo-tests/mock"),
                args.sequence,
            )
            .await;
        }
        SupportedDaLayer::Bitcoin => {
            start_rollup::<BitcoinRollup, DaServiceConfig>(
                //rollup_config,
                rollup_config_path,
                RollupProverConfig::Execute,
                &GenesisPaths::from_dir("../test-data/genesis/demo-tests/bitcoin"),
                args.sequence,
            )
            .await;
        }
        SupportedDaLayer::Celestia => {
            // let rollup_config: RollupConfig<CelestiaConfig> = from_toml_path(rollup_config_path)
            //     .context("Failed to read rollup configuration")?;
            start_rollup::<CelestiaDemoRollup, CelestiaConfig>(
                //rollup_config,
                rollup_config_path,
                RollupProverConfig::Execute,
                &GenesisPaths::from_dir("../test-data/genesis/demo-tests/celestia"),
                args.sequence,
            )
            .await;
        }
    }

    Ok(())
}

fn create_config_generic<DaC>(rollup_config_path: &str) -> ()
where
    DaC: serde::de::DeserializeOwned + DebugTrait + Clone,
{
    let rollup_config: RollupConfig<DaC> = from_toml_path(rollup_config_path)
        .context("Failed to read rollup configuration")
        .unwrap();
}

async fn start_rollup<R, DaC>(
    rollup_config_path: &str,
    // rollup_config: RollupConfig<DaC>,
    prover_config: RollupProverConfig,
    genesis_paths: &<<R as RollupBlueprint>::NativeRuntime as sov_modules_stf_blueprint::Runtime<
        <R as RollupBlueprint>::NativeContext,
        <R as RollupBlueprint>::DaSpec,
    >>::GenesisPaths,
    is_sequencer: bool,
) -> Result<(), anyhow::Error>
where
    DaC: serde::de::DeserializeOwned + DebugTrait + Clone,
    R: RollupBlueprint<DaConfig = DaC>,
    <<R as RollupBlueprint>::NativeContext as Spec>::Storage: NativeStorage,
{
    let rollup_config: RollupConfig<DaC> = from_toml_path(rollup_config_path)
        .context("Failed to read rollup configuration")
        .unwrap();
    let rollup_bp = R::new();
    let da_service = rollup_bp.create_da_service(&rollup_config).await;

    let rollup = rollup_bp
        .create_new_rollup(genesis_paths, rollup_config.clone(), prover_config)
        .await
        .unwrap();

    if is_sequencer {
        if rollup_config.sequencer.is_some() {
            return Err(anyhow!(
                "Sequencer client is not necessary for sequencer nodes."
            ));
        }
        let mut seq: ChainwaySequencer<DefaultContext, <R as RollupBlueprint>::DaService, R> =
            ChainwaySequencer::new(
                rollup,
                da_service,
                DefaultPrivateKey::from_hex(TEST_PRIVATE_KEY).unwrap(),
                0,
            );
        seq.start_rpc_server(None).await?;
        seq.run()
            .await
            .map_err(|e| anyhow!("Failed to run sequencer: {}", e));
    } else {
        if rollup_config.sequencer.is_none() {
            return Err(anyhow!("Sequencer client is necessary for full nodes."));
        }
        rollup
            .run()
            .await
            .map_err(|e| anyhow!("Failed to run rollup: {}", e));
    }

    Ok(())
}

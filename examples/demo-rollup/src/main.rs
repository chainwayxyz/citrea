use std::env;
use std::str::FromStr;

use anyhow::Context as _;
use bitcoin_da::service::{BitcoinService, DaServiceConfig};
use bitcoin_da::spec::RollupParams;
#[cfg(feature = "experimental")]
use chainway_sequencer::experimental::ChainwaySequencer;
use clap::Parser;
use const_rollup_config::{ROLLUP_NAME, TEST_PRIVATE_KEY};
use demo_stf::genesis_config::GenesisPaths;
use sov_celestia_adapter::{CelestiaConfig, CelestiaService};
use sov_demo_rollup::{BitcoinRollup, CelestiaDemoRollup, MockDemoRollup};
use sov_mock_da::{MockAddress, MockDaConfig, MockDaService};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::Context;
use sov_modules_rollup_blueprint::{Rollup, RollupBlueprint};
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
            let rollup = new_rollup_with_mock_da(
                &GenesisPaths::from_dir("../test-data/genesis/demo-tests/mock"),
                rollup_config_path,
                RollupProverConfig::Execute,
            )
            .await?;
            let da_service = MockDaService::new(MockAddress::new([0u8; 32]));
            let mut seq: ChainwaySequencer<DefaultContext, MockDaService, _> =
                ChainwaySequencer::new(
                    rollup,
                    da_service,
                    DefaultPrivateKey::from_hex(TEST_PRIVATE_KEY).unwrap(),
                    // TODO: #43 https://github.com/chainwayxyz/secret-sovereign-sdk/issues/43
                    0,
                );
            seq.start_rpc_server(None).await.unwrap();
            seq.run().await?;
        }
        SupportedDaLayer::Bitcoin => {
            let rollup = new_rollup_with_bitcoin_da(
                &GenesisPaths::from_dir("../test-data/genesis/demo-tests"),
                rollup_config_path,
                RollupProverConfig::Execute,
            )
            .await?;
            let rollup_config: RollupConfig<DaServiceConfig> =
                from_toml_path(rollup_config_path)
                    .context("Failed to read rollup configuration")?;
            let da_service = BitcoinService::new(
                rollup_config.da,
                RollupParams {
                    rollup_name: ROLLUP_NAME.to_string(),
                },
            )
            .await;
            let mut seq: ChainwaySequencer<DefaultContext, BitcoinService, BitcoinRollup> =
                ChainwaySequencer::new(
                    rollup,
                    da_service,
                    DefaultPrivateKey::from_hex(TEST_PRIVATE_KEY).unwrap(),
                    // TODO: #43 https://github.com/chainwayxyz/secret-sovereign-sdk/issues/43
                    0,
                );
            seq.start_rpc_server(None).await.unwrap();
            seq.run().await?;
        }
        SupportedDaLayer::Celestia => {
            let rollup = new_rollup_with_celestia_da(
                &GenesisPaths::from_dir("../test-data/genesis/demo-tests/celestia"),
                rollup_config_path,
                RollupProverConfig::Execute,
            )
            .await?;
            let rollup_config: RollupConfig<CelestiaConfig> = from_toml_path(rollup_config_path)
                .context("Failed to read rollup configuration")?;
            let celestia_rollup = CelestiaDemoRollup {};
            let da_service = celestia_rollup.create_da_service(&rollup_config).await;
            let mut seq: ChainwaySequencer<DefaultContext, CelestiaService, CelestiaDemoRollup> =
                ChainwaySequencer::new(
                    rollup,
                    da_service,
                    DefaultPrivateKey::from_hex(TEST_PRIVATE_KEY).unwrap(),
                    0,
                );
            seq.start_rpc_server(None).await.unwrap();
            seq.run().await?;
        }
    }

    Ok(())
}

async fn new_rollup_with_bitcoin_da(
    genesis_paths: &GenesisPaths,
    rollup_config_path: &str,
    prover_config: RollupProverConfig,
) -> Result<Rollup<BitcoinRollup>, anyhow::Error> {
    debug!("Starting bitcoin rollup with config {}", rollup_config_path);

    let rollup_config: RollupConfig<DaServiceConfig> =
        from_toml_path(rollup_config_path).context("Failed to read rollup configuration")?;

    let mock_rollup = BitcoinRollup {};
    mock_rollup
        .create_new_rollup(genesis_paths, rollup_config, prover_config)
        .await
}

async fn new_rollup_with_celestia_da(
    genesis_paths: &GenesisPaths,
    rollup_config_path: &str,
    prover_config: RollupProverConfig,
) -> Result<Rollup<CelestiaDemoRollup>, anyhow::Error> {
    debug!(
        "Starting celestia rollup with config {}",
        rollup_config_path
    );

    let rollup_config: RollupConfig<sov_celestia_adapter::CelestiaConfig> =
        from_toml_path(rollup_config_path).context("Failed to read rollup configuration")?;

    let mock_rollup = CelestiaDemoRollup {};
    mock_rollup
        .create_new_rollup(genesis_paths, rollup_config, prover_config)
        .await
}

async fn new_rollup_with_mock_da(
    genesis_paths: &GenesisPaths,
    rollup_config_path: &str,
    prover_config: RollupProverConfig,
) -> Result<Rollup<MockDemoRollup>, anyhow::Error> {
    debug!("Starting mock rollup with config {}", rollup_config_path);

    let rollup_config: RollupConfig<MockDaConfig> =
        from_toml_path(rollup_config_path).context("Failed to read rollup configuration")?;

    let mock_rollup = MockDemoRollup {};
    mock_rollup
        .create_new_rollup(genesis_paths, rollup_config, prover_config)
        .await
}

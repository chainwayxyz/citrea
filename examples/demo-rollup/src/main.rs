use core::fmt::Debug as DebugTrait;

use anyhow::{anyhow, Context as _};
use bitcoin_da::service::DaServiceConfig;
use chainway_sequencer::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;
use clap::Parser;
use sov_celestia_adapter::CelestiaConfig;
use sov_demo_rollup::{initialize_logging, BitcoinRollup, CelestiaDemoRollup, MockDemoRollup};
use sov_mock_da::MockDaConfig;
use sov_modules_api::runtime::capabilities::Kernel;
use sov_modules_api::Spec;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::kernels::basic::{
    BasicKernelGenesisConfig, BasicKernelGenesisPaths,
};
use sov_state::storage::NativeStorage;
use sov_stf_runner::{from_toml_path, RollupConfig, RollupProverConfig};

#[cfg(test)]
mod test_rpc;

/// Main demo runner. Initializes a DA chain, and starts a demo-rollup using the provided.
/// If you're trying to sign or submit transactions to the rollup, the `sov-cli` binary
/// is the one you want. You can run it `cargo run --bin sov-cli`.

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The genesis type which can be different for each data layer and if dockerized or not.
    /// Defines the genesis of module states like evm.
    /// For dockerized nodes for all da layers, it should be "docker".
    /// Possible values are "docker", "mock", "celestia", "bitcoin"
    #[arg(long)]
    genesis_type: String,

    /// The data layer type.
    #[arg(long, default_value = "mock")]
    da_layer: SupportedDaLayer,

    /// The path to the rollup config.
    #[arg(long, default_value = "mock_rollup_config.toml")]
    rollup_config_path: String,

    /// The path to the sequencer config. If set, runs the node in sequencer mode, otherwise in full node mode.
    #[arg(long)]
    sequencer_config_path: Option<String>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum SupportedDaLayer {
    Celestia,
    Mock,
    Bitcoin,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    initialize_logging();

    let args = Args::parse();
    let rollup_config_path = args.rollup_config_path.as_str();

    let sequencer_config: Option<SequencerConfig> = args.sequencer_config_path.map(|path| {
        from_toml_path(path)
            .context("Failed to read sequencer configuration")
            .unwrap()
    });

    match args.da_layer {
        SupportedDaLayer::Mock => {
            let kernel_genesis_paths = &BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/demo-tests/mock/chain_state.json".into(),
            };

            let kernel_genesis = BasicKernelGenesisConfig {
                chain_state: serde_json::from_str(
                    &std::fs::read_to_string(&kernel_genesis_paths.chain_state)
                        .context("Failed to read chain state")?,
                )?,
            };

            start_rollup::<MockDemoRollup, MockDaConfig>(
                &GenesisPaths::from_dir(format!(
                    "../test-data/genesis/demo-tests/{}",
                    args.genesis_type
                )),
                kernel_genesis,
                rollup_config_path,
                RollupProverConfig::Execute,
                sequencer_config,
            )
            .await?;
        }
        SupportedDaLayer::Bitcoin => {
            let kernel_genesis_paths = &BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/demo-tests/bitcoin/chain_state.json".into(),
            };

            let kernel_genesis = BasicKernelGenesisConfig {
                chain_state: serde_json::from_str(
                    &std::fs::read_to_string(&kernel_genesis_paths.chain_state)
                        .context("Failed to read chain state")?,
                )?,
            };

            start_rollup::<BitcoinRollup, DaServiceConfig>(
                &GenesisPaths::from_dir(format!(
                    "../test-data/genesis/demo-tests/{}",
                    args.genesis_type
                )),
                kernel_genesis,
                rollup_config_path,
                RollupProverConfig::Execute,
                sequencer_config,
            )
            .await?;
        }
        SupportedDaLayer::Celestia => {
            let kernel_genesis_paths = &BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/demo-tests/celestia/chain_state.json".into(),
            };

            let kernel_genesis = BasicKernelGenesisConfig {
                chain_state: serde_json::from_str(
                    &std::fs::read_to_string(&kernel_genesis_paths.chain_state)
                        .context("Failed to read chain state")?,
                )?,
            };

            start_rollup::<CelestiaDemoRollup, CelestiaConfig>(
                &GenesisPaths::from_dir(format!(
                    "../test-data/genesis/demo-tests/{}",
                    args.genesis_type
                )),
                kernel_genesis,
                rollup_config_path,
                RollupProverConfig::Execute,
                sequencer_config,
            )
            .await?;
        }
    }

    Ok(())
}

async fn start_rollup<S, DaC>(
    rt_genesis_paths: &<<S as RollupBlueprint>::NativeRuntime as sov_modules_stf_blueprint::Runtime<
        <S as RollupBlueprint>::NativeContext,
        <S as RollupBlueprint>::DaSpec,
    >>::GenesisPaths,
    kernel_genesis: <<S as RollupBlueprint>::NativeKernel as Kernel<
        <S as RollupBlueprint>::NativeContext,
        <S as RollupBlueprint>::DaSpec,
    >>::GenesisConfig,
    rollup_config_path: &str,
    prover_config: RollupProverConfig,
    // genesis_paths: &<<S as RollupBlueprint>::NativeRuntime as sov_modules_stf_blueprint::Runtime<
    //     <S as RollupBlueprint>::NativeContext,
    //     <S as RollupBlueprint>::DaSpec,
    // >>::GenesisPaths,
    sequencer_config: Option<SequencerConfig>,
) -> Result<(), anyhow::Error>
where
    DaC: serde::de::DeserializeOwned + DebugTrait + Clone,
    S: RollupBlueprint<DaConfig = DaC>,
    <<S as RollupBlueprint>::NativeContext as Spec>::Storage: NativeStorage,
{
    let mut rollup_config: RollupConfig<DaC> = from_toml_path(rollup_config_path)
        .context("Failed to read rollup configuration")
        .unwrap();
    let rollup_blueprint = S::new();

    if let Some(sequencer_config) = sequencer_config {
        rollup_config.sequencer_client = None;

        let sequencer_rollup = rollup_blueprint
            .create_new_sequencer(
                rt_genesis_paths,
                kernel_genesis,
                rollup_config.clone(),
                sequencer_config,
            )
            .await
            .unwrap();
        sequencer_rollup.run().await?;
    } else {
        if rollup_config.sequencer_client.is_none() {
            return Err(anyhow!("Must have sequencer client for full nodes!"));
        }
        let rollup = rollup_blueprint
            .create_new_rollup(
                rt_genesis_paths,
                kernel_genesis,
                rollup_config,
                prover_config,
            )
            .await
            .unwrap();
        rollup.run().await?;
    }

    Ok(())
}

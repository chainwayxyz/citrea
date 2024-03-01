use core::fmt::Debug as DebugTrait;

use anyhow::{anyhow, Context as _};
use bitcoin_da::service::DaServiceConfig;
use chainway_sequencer::ChainwaySequencer;
use citrea_stf::genesis_config::GenesisPaths;
use clap::Parser;
use const_rollup_config::TEST_PRIVATE_KEY;
use reth_primitives::hex;
use sov_celestia_adapter::CelestiaConfig;
use sov_demo_rollup::{initialize_logging, BitcoinRollup, CelestiaDemoRollup, MockDemoRollup};
use sov_mock_da::MockDaConfig;
use sov_modules_api::runtime::capabilities::Kernel;
use sov_modules_api::Spec;
use sov_modules_rollup_blueprint::{RollupAndStorage, RollupBlueprint};
use sov_modules_stf_blueprint::kernels::basic::{
    BasicKernelGenesisConfig, BasicKernelGenesisPaths,
};
use sov_state::storage::NativeStorage;
use sov_stf_runner::{from_toml_path, RollupConfig, RollupProverConfig, SequencerConfig};

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
    #[arg(long, requires("sequencer_config_path"))]
    sequence: bool,

    /// The path to the sequencer config.
    #[arg(long)]
    sequencer_config_path: String,
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

    let is_sequencer: Option<SequencerConfig> = if args.sequence {
        let sequencer_config_path = args.sequencer_config_path;
        from_toml_path(sequencer_config_path)
            .context("Failed to read sequencer configuration")
            .unwrap()
    } else {
        None
    };

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
                &GenesisPaths::from_dir("../test-data/genesis/demo-tests/mock"),
                kernel_genesis,
                rollup_config_path,
                RollupProverConfig::Execute,
                is_sequencer,
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
                &GenesisPaths::from_dir("../test-data/genesis/demo-tests/bitcoin"),
                kernel_genesis,
                rollup_config_path,
                RollupProverConfig::Execute,
                is_sequencer,
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
                &GenesisPaths::from_dir("../test-data/genesis/demo-tests/celestia"),
                kernel_genesis,
                rollup_config_path,
                RollupProverConfig::Execute,
                is_sequencer,
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
    is_sequencer: Option<SequencerConfig>,
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
    let da_service = rollup_blueprint.create_da_service(&rollup_config).await;

    if is_sequencer.is_some() {
        rollup_config.sequencer_client = None;
    }

    let RollupAndStorage { rollup, storage } = rollup_blueprint
        .create_new_rollup(
            rt_genesis_paths,
            kernel_genesis,
            rollup_config.clone(),
            prover_config,
        )
        .await
        .unwrap();

    if let Some(sequencer_config) = is_sequencer {
        let mut seq: ChainwaySequencer<
            <S as RollupBlueprint>::NativeContext,
            <S as RollupBlueprint>::DaService,
            S,
            > = ChainwaySequencer::new(
            rollup,
            da_service,
            <<<S as RollupBlueprint>::NativeContext as Spec>::PrivateKey as TryFrom<&[u8]>>::try_from(
                hex::decode(TEST_PRIVATE_KEY).unwrap().as_slice(),
            )
            .unwrap(),
            storage,
            sequencer_config.into(),
        );
        seq.start_rpc_server(None).await?;
        seq.run().await?;
    } else {
        if rollup_config.sequencer_client.is_none() {
            return Err(anyhow!("Must have sequencer client for full nodes!"));
        }
        rollup.run().await?;
    }

    Ok(())
}

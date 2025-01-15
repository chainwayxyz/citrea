use core::fmt::Debug as DebugTrait;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use bitcoin_da::service::BitcoinServiceConfig;
use citrea::{
    initialize_logging, BitcoinRollup, CitreaRollupBlueprint, Dependencies, MockDemoRollup, Storage,
};
use citrea_common::rpc::server::start_rpc_server;
use citrea_common::{from_toml_path, FromEnv, FullNodeConfig};
use citrea_stf::genesis_config::GenesisPaths;
use clap::Parser;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_mock_da::MockDaConfig;
use sov_modules_api::Spec;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_rollup_interface::Network;
use sov_state::storage::NativeStorage;
use tracing::{debug, error, info, instrument};

use crate::cli::{client_from_args, Args, RollupClient, SupportedDaLayer};

mod cli;
#[cfg(test)]
mod test_rpc;

/// Main runner. Initializes a DA service, and starts a node using the provided arguments.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let client = client_from_args(&args)?;

    let mut network = args.network.into();
    if args.dev {
        network = Network::Nightly;
    }

    if args.dev_all_forks {
        network = Network::TestNetworkWithForks;
    }

    info!("Starting node on {network}");

    match args.da_layer {
        SupportedDaLayer::Mock => {
            start_rollup::<MockDemoRollup, MockDaConfig>(
                network,
                &GenesisPaths::from_dir(&args.genesis_paths),
                args.rollup_config_path,
                client,
            )
            .await?;
        }
        SupportedDaLayer::Bitcoin => {
            start_rollup::<BitcoinRollup, BitcoinServiceConfig>(
                network,
                &GenesisPaths::from_dir(&args.genesis_paths),
                args.rollup_config_path,
                client,
            )
            .await?;
        }
    }

    Ok(())
}

#[instrument(level = "trace", skip_all, err)]
async fn start_rollup<S, DaC>(
    network: Network,
    runtime_genesis_paths: &<<S as RollupBlueprint>::NativeRuntime as sov_modules_stf_blueprint::Runtime<
        <S as RollupBlueprint>::NativeContext,
        <S as RollupBlueprint>::DaSpec,
    >>::GenesisPaths,
    rollup_config_path: Option<String>,
    rollup_client: RollupClient,
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

    if rollup_config.telemetry.bind_host.is_some() && rollup_config.telemetry.bind_port.is_some() {
        let bind_host = rollup_config.telemetry.bind_host.as_ref().unwrap();
        let bind_port = rollup_config.telemetry.bind_port.as_ref().unwrap();
        let telemetry_addr: SocketAddr = format!("{}:{}", bind_host, bind_port)
            .parse()
            .map_err(|_| anyhow!("Invalid telemetry address"))?;

        debug!("Starting telemetry server on: {}", telemetry_addr);

        let builder = PrometheusBuilder::new().with_http_listener(telemetry_addr);
        builder
            .idle_timeout(
                MetricKindMask::GAUGE | MetricKindMask::HISTOGRAM,
                Some(Duration::from_secs(30)),
            )
            .install()
            .map_err(|_| anyhow!("failed to install Prometheus recorder"))?;
    }

    let rollup_blueprint = S::new(network);

    let genesis_config =
        rollup_blueprint.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

    let rocksdb_path = rollup_config.storage.path.clone();
    let rocksdb_config = RocksdbConfig::new(
        rocksdb_path.as_path(),
        rollup_config.storage.db_max_open_files,
        None,
    );

    let Storage {
        ledger_db,
        storage_manager,
        prover_storage,
    } = rollup_blueprint.setup_storage(&rollup_config, &rocksdb_config)?;

    let Dependencies {
        da_service,
        mut task_manager,
        soft_confirmation_channel,
    } = rollup_blueprint.setup_dependencies(&rollup_config).await?;

    let sequencer_client_url = rollup_config
        .runner
        .clone()
        .map(|runner| runner.sequencer_client_url);
    let soft_confirmation_rx = match rollup_client {
        RollupClient::Sequencer(_) | RollupClient::BatchProver(_) | RollupClient::FullNode => {
            soft_confirmation_channel.1
        }
        _ => None,
    };

    let rpc_module = rollup_blueprint.setup_rpc(
        &prover_storage,
        ledger_db.clone(),
        da_service.clone(),
        sequencer_client_url,
        soft_confirmation_rx,
    )?;
    start_rpc_server(
        rollup_config.rpc.clone(),
        &mut task_manager,
        rpc_module,
        None,
    )
    .await;

    match rollup_client {
        RollupClient::Sequencer(sequencer_config) => {
            let mut sequencer = rollup_blueprint
                .create_sequencer(
                    genesis_config,
                    rollup_config.clone(),
                    sequencer_config,
                    da_service,
                    ledger_db,
                    storage_manager,
                    prover_storage,
                    soft_confirmation_channel.0,
                    task_manager,
                )
                .expect("Could not start sequencer");

            if let Err(e) = sequencer.run().await {
                error!("Error: {}", e);
            }
        }
        RollupClient::BatchProver(batch_prover_config) => {
            let mut prover = CitreaRollupBlueprint::create_batch_prover(
                &rollup_blueprint,
                genesis_config,
                rollup_config,
                batch_prover_config,
                da_service,
                ledger_db,
                storage_manager,
                prover_storage,
                soft_confirmation_channel.0,
                task_manager,
            )
            .await
            .expect("Could not start batch prover");

            if let Err(e) = prover.run().await {
                error!("Error: {}", e);
            }
        }
        RollupClient::LightClientProver(light_client_prover_config) => {
            let mut prover = CitreaRollupBlueprint::create_light_client_prover(
                &rollup_blueprint,
                rollup_config,
                light_client_prover_config,
                &rocksdb_config,
                da_service,
                ledger_db,
                task_manager,
            )
            .await
            .expect("Could not start light client prover");

            if let Err(e) = prover.run().await {
                error!("Error: {}", e);
            }
        }
        _ => {
            let mut rollup = CitreaRollupBlueprint::create_rollup(
                &rollup_blueprint,
                genesis_config,
                rollup_config,
                da_service,
                ledger_db,
                storage_manager,
                prover_storage,
                soft_confirmation_channel.0,
                task_manager,
            )
            .await
            .expect("Could not start full-node");

            if let Err(e) = rollup.run().await {
                error!("Error: {}", e);
            }
        }
    }

    Ok(())
}

use core::fmt::Debug as DebugTrait;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use bitcoin_da::service::BitcoinServiceConfig;
use citrea::{
    initialize_logging, BitcoinRollup, CitreaRollupBlueprint, Dependencies, MockDemoRollup, Storage,
};
use citrea_common::da::get_start_l1_height;
use citrea_common::rpc::server::start_rpc_server;
use citrea_common::{from_toml_path, FromEnv, FullNodeConfig};
use citrea_light_client_prover::da_block_handler::StartVariant;
use citrea_stf::genesis_config::GenesisPaths;
use clap::Parser;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;
use sov_db::ledger_db::SharedLedgerOps;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::{
    BATCH_PROVER_LEDGER_TABLES, FULL_NODE_LEDGER_TABLES, LIGHT_CLIENT_PROVER_LEDGER_TABLES,
    SEQUENCER_LEDGER_TABLES,
};
use sov_mock_da::MockDaConfig;
use sov_modules_api::Spec;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_rollup_interface::Network;
use sov_state::storage::NativeStorage;
use tracing::{debug, error, info, instrument};

use crate::cli::{node_type_from_args, Args, NodeType, SupportedDaLayer};

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

    let node_type = node_type_from_args(&args)?;

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
                node_type,
            )
            .await?;
        }
        SupportedDaLayer::Bitcoin => {
            start_rollup::<BitcoinRollup, BitcoinServiceConfig>(
                network,
                &GenesisPaths::from_dir(&args.genesis_paths),
                args.rollup_config_path,
                node_type,
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
    node_type: NodeType,
) -> Result<(), anyhow::Error>
where
    DaC: serde::de::DeserializeOwned + DebugTrait + Clone + FromEnv + Send + Sync + 'static,
    S: CitreaRollupBlueprint<DaConfig = DaC>,
    <<S as RollupBlueprint>::NativeContext as Spec>::Storage: NativeStorage,
    <S as RollupBlueprint>::NativeRuntime: 'static,
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

    // Based on the node's type, execute migrations before constructing an instance of LedgerDB
    // so that avoid locking the DB.
    let (tables, migrations) = match node_type {
        NodeType::Sequencer(_) => (
            SEQUENCER_LEDGER_TABLES
                .iter()
                .map(|table| table.to_string())
                .collect::<Vec<_>>(),
            citrea_sequencer::db_migrations::migrations(),
        ),
        NodeType::FullNode => (
            FULL_NODE_LEDGER_TABLES
                .iter()
                .map(|table| table.to_string())
                .collect::<Vec<_>>(),
            citrea_fullnode::db_migrations::migrations(),
        ),
        NodeType::BatchProver(_) => (
            BATCH_PROVER_LEDGER_TABLES
                .iter()
                .map(|table| table.to_string())
                .collect::<Vec<_>>(),
            citrea_batch_prover::db_migrations::migrations(),
        ),
        NodeType::LightClientProver(_) => (
            LIGHT_CLIENT_PROVER_LEDGER_TABLES
                .iter()
                .map(|table| table.to_string())
                .collect::<Vec<_>>(),
            citrea_light_client_prover::db_migrations::migrations(),
        ),
    };
    rollup_blueprint.run_ledger_migrations(&rollup_config, tables.clone(), migrations)?;

    let genesis_config =
        rollup_blueprint.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

    let rocksdb_path = rollup_config.storage.path.clone();
    let rocksdb_config = RocksdbConfig::new(
        rocksdb_path.as_path(),
        rollup_config.storage.db_max_open_files,
        Some(tables),
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
    let soft_confirmation_rx = match node_type {
        NodeType::Sequencer(_) | NodeType::BatchProver(_) | NodeType::FullNode => {
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

    match node_type {
        NodeType::Sequencer(sequencer_config) => {
            let (mut sequencer, rpc_module) = rollup_blueprint
                .create_sequencer(
                    genesis_config,
                    rollup_config.clone(),
                    sequencer_config,
                    da_service,
                    ledger_db,
                    storage_manager,
                    prover_storage,
                    soft_confirmation_channel.0,
                    rpc_module,
                )
                .expect("Could not start sequencer");

            start_rpc_server(
                rollup_config.rpc.clone(),
                &mut task_manager,
                rpc_module,
                None,
            );

            task_manager.spawn(|cancellation_token| async move {
                if let Err(e) = sequencer.run(cancellation_token).await {
                    error!("Error: {}", e);
                }
            });
        }
        NodeType::BatchProver(batch_prover_config) => {
            let (mut prover, l1_block_handler, rpc_module) =
                CitreaRollupBlueprint::create_batch_prover(
                    &rollup_blueprint,
                    batch_prover_config,
                    genesis_config,
                    rollup_config.clone(),
                    da_service,
                    ledger_db.clone(),
                    storage_manager,
                    prover_storage,
                    soft_confirmation_channel.0,
                    rpc_module,
                )
                .await
                .expect("Could not start batch prover");

            start_rpc_server(
                rollup_config.rpc.clone(),
                &mut task_manager,
                rpc_module,
                None,
            );

            task_manager.spawn(|cancellation_token| async move {
                let Ok(start_l1_height) = get_start_l1_height(&rollup_config, &ledger_db).await
                else {
                    error!("Failed to start prover L1 block handler due to start l1 height not present");
                    return;
                };
                l1_block_handler
                    .run(start_l1_height, cancellation_token)
                    .await
            });

            task_manager.spawn(|cancellation_token| async move {
                if let Err(e) = prover.run(cancellation_token).await {
                    error!("Error: {}", e);
                }
            });
        }
        NodeType::LightClientProver(light_client_prover_config) => {
            let starting_block = match ledger_db.get_last_scanned_l1_height()? {
                Some(l1_height) => StartVariant::LastScanned(l1_height.0),
                // first time starting the prover
                // start from the block given in the config
                None => StartVariant::FromBlock(light_client_prover_config.initial_da_height),
            };

            let (mut prover, l1_block_handler, rpc_module) =
                CitreaRollupBlueprint::create_light_client_prover(
                    &rollup_blueprint,
                    light_client_prover_config,
                    rollup_config.clone(),
                    &rocksdb_config,
                    da_service,
                    ledger_db,
                    rpc_module,
                )
                .await
                .expect("Could not start light client prover");

            start_rpc_server(
                rollup_config.rpc.clone(),
                &mut task_manager,
                rpc_module,
                None,
            );

            task_manager.spawn(|cancellation_token| async move {
                l1_block_handler
                    .run(starting_block, cancellation_token)
                    .await
            });

            task_manager.spawn(|cancellation_token| async move {
                if let Err(e) = prover.run(cancellation_token).await {
                    error!("Error: {}", e);
                }
            });
        }
        _ => {
            let (mut full_node, l1_block_handler, pruner) =
                CitreaRollupBlueprint::create_full_node(
                    &rollup_blueprint,
                    genesis_config,
                    rollup_config.clone(),
                    da_service,
                    ledger_db.clone(),
                    storage_manager,
                    prover_storage,
                    soft_confirmation_channel.0,
                )
                .await
                .expect("Could not start full-node");

            start_rpc_server(
                rollup_config.rpc.clone(),
                &mut task_manager,
                rpc_module,
                None,
            );

            task_manager.spawn(|cancellation_token| async move {
                let Ok(start_l1_height) = get_start_l1_height(&rollup_config, &ledger_db).await
                else {
                    error!("Failed to start fullnode L1 block handler due to start l1 height not present");
                    return;
                };
                l1_block_handler
                    .run(start_l1_height, cancellation_token)
                    .await
            });

            // Spawn pruner if configs are set
            if let Some(pruner) = pruner {
                task_manager.spawn(|cancellation_token| async move {
                    pruner.run(cancellation_token).await
                });
            }

            task_manager.spawn(|cancellation_token| async move {
                if let Err(e) = full_node.run(cancellation_token).await {
                    error!("Error: {}", e);
                }
            });
        }
    }

    task_manager.wait_shutdown().await;

    Ok(())
}

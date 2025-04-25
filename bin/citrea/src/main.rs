use core::fmt::Debug as DebugTrait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use bitcoin_da::service::BitcoinServiceConfig;
use citrea::{
    initialize_logging, BitcoinRollup, CitreaRollupBlueprint, Dependencies, MockDemoRollup, Storage,
};
use citrea_common::backup::BackupManager;
use citrea_common::rpc::server::start_rpc_server;
use citrea_common::{from_toml_path, FromEnv, FullNodeConfig};
use citrea_light_client_prover::circuit::initial_values::InitialValueProvider;
use citrea_light_client_prover::da_block_handler::StartVariant;
use citrea_stf::genesis_config::GenesisPaths;
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use citrea_storage_ops::pruning::types::StorageNodeType;
use clap::Parser;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;
use reth_tasks::TaskManager;
use short_header_proof_provider::{
    NativeShortHeaderProofProviderService, SHORT_HEADER_PROOF_PROVIDER,
};
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
use tokio::signal;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{debug, error, info, instrument};

use crate::cli::{node_type_from_args, Args, NodeType, SupportedDaLayer};

mod cli;

/// Main runner. Initializes a DA service, and starts a node using the provided arguments.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = Args::parse();

    if args.quiet {
        args.verbose = 0;
    }
    let logging_level = match args.verbose {
        1 => tracing::Level::DEBUG,
        2 => tracing::Level::TRACE,
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
    runtime_genesis_paths: &<CitreaRuntime<DefaultContext, <S as RollupBlueprint>::DaSpec> as sov_modules_stf_blueprint::Runtime<DefaultContext, <S as RollupBlueprint>::DaSpec>>::GenesisPaths,
    rollup_config_path: Option<String>,
    node_type: NodeType,
) -> Result<(), anyhow::Error>
where
    DaC: serde::de::DeserializeOwned + DebugTrait + Clone + FromEnv + Send + Sync + 'static,
    S: CitreaRollupBlueprint<DaConfig = DaC>,
    <DefaultContext as Spec>::Storage: NativeStorage,
    Network: InitialValueProvider<<S as RollupBlueprint>::DaSpec>,
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
                // Keep the idle timeout larger than one L1 block production.
                // Setting this here for 30 minutes.
                Some(Duration::from_secs(30 * 60)),
            )
            .install()
            .map_err(|_| anyhow!("failed to install Prometheus recorder"))?;
    }

    let rollup_blueprint = S::new(network);

    let backup_manager = Arc::new(BackupManager::new(
        node_type.to_string(),
        rollup_config.storage.backup_path.clone(),
        Default::default(),
    ));

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
    } = rollup_blueprint.setup_storage(&rollup_config, &rocksdb_config, &backup_manager)?;

    let Dependencies {
        da_service,
        task_manager,
        l2_block_channel,
    } = rollup_blueprint
        .setup_dependencies(
            &rollup_config,
            matches!(node_type, NodeType::Sequencer(_))
                || matches!(node_type, NodeType::BatchProver(_)),
            network,
        )
        .await?;

    let (l2_block_tx, l2_block_rx) = l2_block_channel;

    let sequencer_client_url = rollup_config
        .runner
        .clone()
        .map(|runner| runner.sequencer_client_url);
    let l2_block_rx = match node_type {
        NodeType::Sequencer(_) | NodeType::BatchProver(_) | NodeType::FullNode => l2_block_rx,
        _ => None,
    };

    match SHORT_HEADER_PROOF_PROVIDER.set(Box::new(NativeShortHeaderProofProviderService::<
        <S as RollupBlueprint>::DaSpec,
    >::new(ledger_db.clone())))
    {
        Ok(_) => tracing::debug!("Short header proof provider set"),
        Err(_) => tracing::error!("Short header proof provider already set"),
    };

    let rpc_storage = storage_manager.create_final_view_storage();
    let rpc_module = rollup_blueprint.create_rpc_methods(
        rpc_storage,
        &ledger_db,
        &da_service,
        sequencer_client_url,
        l2_block_rx,
        &backup_manager,
        rollup_config.rpc.clone(),
    )?;

    let task_executor = task_manager.executor();

    match node_type {
        NodeType::Sequencer(sequencer_config) => {
            let is_reorg_sequencer: bool = std::env::var("REORG").is_ok();

            if is_reorg_sequencer {
                let (mut reorg_sequencer, rpc_module) = rollup_blueprint
                    .create_reorg_sequencer(
                        genesis_config,
                        sequencer_config,
                        da_service,
                        ledger_db,
                        storage_manager,
                        rpc_module,
                        l2_block_tx,
                        task_executor.clone(),
                    )
                    .expect("Could not start sequencer");

                start_rpc_server(rollup_config.rpc.clone(), &task_executor, rpc_module, None);

                task_executor.spawn_critical_with_graceful_shutdown_signal(
                    "reorg_sequencer",
                    |shutdown_signal| async move {
                        if let Err(e) = reorg_sequencer.run(shutdown_signal).await {
                            error!("Error: {}", e);
                        }
                    },
                );
            } else {
                let (mut sequencer, rpc_module) = rollup_blueprint
                    .create_sequencer(
                        genesis_config,
                        rollup_config.clone(),
                        sequencer_config,
                        da_service,
                        ledger_db,
                        storage_manager,
                        l2_block_tx,
                        rpc_module,
                        backup_manager,
                        task_executor.clone(),
                    )
                    .expect("Could not start sequencer");

                start_rpc_server(rollup_config.rpc.clone(), &task_executor, rpc_module, None);

                task_executor.spawn_critical_with_graceful_shutdown_signal(
                    "sequencer",
                    |shutdown_signal| async move {
                        if let Err(e) = sequencer.run(shutdown_signal).await {
                            error!("Error: {}", e);
                        }
                    },
                );
            }
        }
        NodeType::BatchProver(batch_prover_config) => {
            let (l2_syncer, l1_syncer, prover, rpc_module) =
                CitreaRollupBlueprint::create_batch_prover(
                    &rollup_blueprint,
                    batch_prover_config,
                    genesis_config,
                    rollup_config.clone(),
                    da_service,
                    ledger_db.clone(),
                    storage_manager,
                    l2_block_tx,
                    rpc_module,
                    backup_manager,
                )
                .await
                .expect("Could not start batch prover");

            start_rpc_server(rollup_config.rpc.clone(), &task_executor, rpc_module, None);

            task_executor.spawn_with_graceful_shutdown_signal(|shutdown_signal| async move {
                l1_syncer.run(shutdown_signal).await
            });

            task_executor.spawn_with_graceful_shutdown_signal(|shutdown_signal| async move {
                l2_syncer.run(shutdown_signal).await
            });

            task_executor.spawn_critical_with_graceful_shutdown_signal(
                "Prover",
                |shutdown_signal| async move { prover.run(shutdown_signal).await },
            );
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
                    network,
                    light_client_prover_config,
                    rollup_config.clone(),
                    da_service,
                    ledger_db,
                    storage_manager,
                    rpc_module,
                    backup_manager,
                )
                .await
                .expect("Could not start light client prover");

            start_rpc_server(rollup_config.rpc.clone(), &task_executor, rpc_module, None);

            task_executor.spawn_critical_with_graceful_shutdown_signal(
                "LightClient",
                |shutdown_signal| async move {
                    l1_block_handler.run(starting_block, shutdown_signal).await
                },
            );

            task_executor.spawn_with_graceful_shutdown_signal(|shutdown_signal| async move {
                if let Err(e) = prover.run(shutdown_signal).await {
                    error!("Error: {}", e);
                }
            });
        }
        _ => {
            let (mut l2_syncer, l1_block_handler, pruner_service, rpc_module) =
                CitreaRollupBlueprint::create_full_node(
                    &rollup_blueprint,
                    genesis_config,
                    rollup_config.clone(),
                    da_service,
                    ledger_db.clone(),
                    storage_manager,
                    l2_block_tx,
                    rpc_module,
                    backup_manager,
                )
                .await
                .expect("Could not start full-node");

            start_rpc_server(rollup_config.rpc.clone(), &task_executor, rpc_module, None);

            let l1_start_height = match ledger_db.get_last_scanned_l1_height()? {
                Some(l1_height) => l1_height.0,
                None => {
                    rollup_config
                        .runner
                        .ok_or(anyhow!(
                    "Failed to start batch prover L1 block handler: Runner config not present"
                ))?
                        .scan_l1_start_height
                }
            };

            task_executor.spawn_with_graceful_shutdown_signal(|shutdown_signal| async move {
                l1_block_handler.run(l1_start_height, shutdown_signal).await
            });

            // Spawn pruner if configs are set
            if let Some(pruner_service) = pruner_service {
                task_executor.spawn_with_graceful_shutdown_signal(|shutdown_signal| async move {
                    pruner_service
                        .run(StorageNodeType::FullNode, shutdown_signal)
                        .await
                });
            }

            task_executor.spawn_critical_with_graceful_shutdown_signal(
                "FullNode",
                |shutdown_signal| async move { l2_syncer.run(shutdown_signal).await },
            );
        }
    }

    wait_shutdown(task_manager).await;

    Ok(())
}

/// Wait for a termination signal and cancel all running tasks
pub async fn wait_shutdown(task_manager: TaskManager) {
    let mut term_signal =
        signal(SignalKind::terminate()).expect("Failed to create termination signal");
    let mut interrupt_signal =
        signal(SignalKind::interrupt()).expect("Failed to create interrupt signal");

    let wait_duration = Duration::from_secs(5);
    tokio::select! {
        _ = signal::ctrl_c() => {
            task_manager.graceful_shutdown_with_timeout(wait_duration);
        }
        _ = term_signal.recv() => {
            task_manager.graceful_shutdown_with_timeout(wait_duration);
        },
        _ = interrupt_signal.recv() => {
            task_manager.graceful_shutdown_with_timeout(wait_duration);
        }
    }
}

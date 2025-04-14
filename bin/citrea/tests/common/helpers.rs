use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::bail;
use borsh::BorshDeserialize;
use citrea::{CitreaRollupBlueprint, Dependencies, MockDemoRollup, Storage};
use citrea_common::backup::BackupManager;
use citrea_common::da::get_start_l1_height;
use citrea_common::rpc::server::start_rpc_server;
use citrea_common::tasks::manager::TaskManager;
use citrea_common::{
    BatchProverConfig, FullNodeConfig, LightClientProverConfig, RollupPublicKeys, RpcConfig,
    RunnerConfig, SequencerConfig, StorageConfig,
};
use citrea_light_client_prover::da_block_handler::StartVariant;
use citrea_primitives::TEST_PRIVATE_KEY;
use citrea_stf::genesis_config::GenesisPaths;
use citrea_storage_ops::pruning::PruningConfig;
use sov_db::ledger_db::SharedLedgerOps;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::{
    BATCH_PROVER_LEDGER_TABLES, FULL_NODE_LEDGER_TABLES, LIGHT_CLIENT_PROVER_LEDGER_TABLES,
    SEQUENCER_LEDGER_TABLES,
};
use sov_mock_da::{MockAddress, MockBlock, MockDaConfig, MockDaService};
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::PrivateKey;
use sov_modules_rollup_blueprint::RollupBlueprint as _;
use sov_rollup_interface::da::{BlobReaderTrait, DaTxRequest, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::zk::Proof;
use sov_rollup_interface::Network;
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::time::sleep;
use tracing::{debug, info_span, instrument, warn, Instrument};

use crate::common::client::TestClient;
use crate::common::DEFAULT_PROOF_WAIT_DURATION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    FullNode(SocketAddr),
    SequencerNode,
    Prover(SocketAddr),
    #[allow(unused)]
    LightClientProver(SocketAddr),
}

pub async fn start_rollup(
    rpc_reporting_channel: oneshot::Sender<SocketAddr>,
    runtime_genesis_paths: GenesisPaths,
    rollup_prover_config: Option<BatchProverConfig>,
    light_client_prover_config: Option<LightClientProverConfig>,
    rollup_config: FullNodeConfig<MockDaConfig>,
    sequencer_config: Option<SequencerConfig>,
) -> TaskManager<()> {
    // create rollup config default creator function and use them here for the configs

    // We enable risc0 dev mode in tests because the provers in dev mode generate fake receipts that can be verified if the verifier is also in dev mode
    // Fake receipts are receipts without the proof, they only include the journal, which makes them suitable for testing and development
    std::env::set_var("RISC0_DEV_MODE", "1");

    let mock_demo_rollup = MockDemoRollup::new(Network::Nightly);

    if sequencer_config.is_some() && rollup_prover_config.is_some() {
        panic!("Both sequencer and batch prover config cannot be set at the same time");
    }
    if sequencer_config.is_some() && light_client_prover_config.is_some() {
        panic!("Both sequencer and light client prover config cannot be set at the same time");
    }
    if rollup_prover_config.is_some() && light_client_prover_config.is_some() {
        panic!("Both batch prover and light client prover config cannot be set at the same time");
    }

    let backup_manager = Arc::new(BackupManager::new("test".to_string(), None, None));

    let (tables, migrations) = if sequencer_config.is_some() {
        (
            SEQUENCER_LEDGER_TABLES
                .iter()
                .map(|table| table.to_string())
                .collect::<Vec<_>>(),
            citrea_sequencer::db_migrations::migrations(),
        )
    } else if rollup_prover_config.is_some() {
        (
            BATCH_PROVER_LEDGER_TABLES
                .iter()
                .map(|table| table.to_string())
                .collect::<Vec<_>>(),
            citrea_batch_prover::db_migrations::migrations(),
        )
    } else if light_client_prover_config.is_some() {
        (
            LIGHT_CLIENT_PROVER_LEDGER_TABLES
                .iter()
                .map(|table| table.to_string())
                .collect::<Vec<_>>(),
            citrea_light_client_prover::db_migrations::migrations(),
        )
    } else {
        (
            FULL_NODE_LEDGER_TABLES
                .iter()
                .map(|table| table.to_string())
                .collect::<Vec<_>>(),
            citrea_fullnode::db_migrations::migrations(),
        )
    };
    mock_demo_rollup
        .run_ledger_migrations(&rollup_config, tables.clone(), migrations)
        .expect("Migrations should have executed successfully");

    let genesis_config = mock_demo_rollup
        .create_genesis_config(&runtime_genesis_paths, &rollup_config)
        .expect("Should be able to create genesis config");

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
    } = mock_demo_rollup
        .setup_storage(&rollup_config, &rocksdb_config, &backup_manager)
        .expect("Storage setup should work");

    let Dependencies {
        da_service,
        mut task_manager,
        soft_confirmation_channel,
    } = mock_demo_rollup
        .setup_dependencies(
            &rollup_config,
            sequencer_config.is_some() || rollup_prover_config.is_some(),
        )
        .await
        .expect("Dependencies setup should work");

    let sequencer_client_url = rollup_config
        .runner
        .clone()
        .map(|runner| runner.sequencer_client_url);
    let soft_confirmation_rx = if light_client_prover_config.is_none() {
        soft_confirmation_channel.1
    } else {
        None
    };
    let rpc_module = mock_demo_rollup
        .create_rpc_methods(
            &prover_storage,
            &ledger_db,
            &da_service,
            sequencer_client_url,
            soft_confirmation_rx,
            &backup_manager,
            rollup_config.rpc.clone(),
        )
        .expect("RPC module setup should work");

    if let Some(sequencer_config) = sequencer_config {
        warn!(
            "Starting sequencer node pub key: {:?}",
            DefaultPrivateKey::from_hex(TEST_PRIVATE_KEY)
                .unwrap()
                .pub_key()
        );
        let span = info_span!("Sequencer");

        let (mut sequencer, rpc_module) = CitreaRollupBlueprint::create_sequencer(
            &mock_demo_rollup,
            genesis_config,
            rollup_config.clone(),
            sequencer_config,
            da_service,
            ledger_db,
            storage_manager,
            prover_storage,
            soft_confirmation_channel.0,
            rpc_module,
            backup_manager,
        )
        .unwrap();

        start_rpc_server(
            rollup_config.rpc,
            &mut task_manager,
            rpc_module,
            Some(rpc_reporting_channel),
        );

        task_manager.spawn(|cancellation_token| async move {
            sequencer
                .run(cancellation_token)
                .instrument(span)
                .await
                .unwrap();
        });
    } else if let Some(rollup_prover_config) = rollup_prover_config {
        let span = info_span!("Prover");

        let (mut prover, l1_block_handler, rpc_module) =
            CitreaRollupBlueprint::create_batch_prover(
                &mock_demo_rollup,
                rollup_prover_config,
                genesis_config,
                rollup_config.clone(),
                da_service,
                ledger_db.clone(),
                storage_manager,
                prover_storage,
                soft_confirmation_channel.0,
                rpc_module,
                backup_manager,
            )
            .instrument(span.clone())
            .await
            .unwrap();

        start_rpc_server(
            rollup_config.rpc.clone(),
            &mut task_manager,
            rpc_module,
            Some(rpc_reporting_channel),
        );

        let handler_span = span.clone();
        task_manager.spawn(|cancellation_token| async move {
            let start_l1_height = get_start_l1_height(&rollup_config, &ledger_db)
                .await
                .expect("Failed to fetch start L1 height");
            l1_block_handler
                .run(start_l1_height, cancellation_token)
                .instrument(handler_span.clone())
                .await
        });

        task_manager.spawn(|cancellation_token| async move {
            prover
                .run(cancellation_token)
                .instrument(span)
                .await
                .unwrap();
        });
    } else if let Some(light_client_prover_config) = light_client_prover_config {
        let span = info_span!("LightClientProver");

        let starting_block = match ledger_db
            .get_last_scanned_l1_height()
            .expect("Should be able to read DB")
        {
            Some(l1_height) => StartVariant::LastScanned(l1_height.0),
            // first time starting the prover
            // start from the block given in the config
            None => StartVariant::FromBlock(light_client_prover_config.initial_da_height),
        };

        let (mut rollup, l1_block_handler, rpc_module) =
            CitreaRollupBlueprint::create_light_client_prover(
                &mock_demo_rollup,
                light_client_prover_config,
                rollup_config.clone(),
                &rocksdb_config,
                da_service,
                ledger_db,
                rpc_module,
                backup_manager,
            )
            .instrument(span.clone())
            .await
            .unwrap();

        start_rpc_server(
            rollup_config.rpc.clone(),
            &mut task_manager,
            rpc_module,
            Some(rpc_reporting_channel),
        );

        let handler_span = span.clone();
        task_manager.spawn(|cancellation_token| async move {
            l1_block_handler
                .run(starting_block, cancellation_token)
                .instrument(handler_span.clone())
                .await
        });

        task_manager.spawn(|cancellation_token| async move {
            rollup
                .run(cancellation_token)
                .instrument(span)
                .await
                .unwrap();
        });
    } else {
        let span = info_span!("FullNode");

        let (mut rollup, l1_block_handler, pruner) = CitreaRollupBlueprint::create_full_node(
            &mock_demo_rollup,
            genesis_config,
            rollup_config.clone(),
            da_service,
            ledger_db.clone(),
            storage_manager,
            prover_storage,
            soft_confirmation_channel.0,
            backup_manager,
        )
        .instrument(span.clone())
        .await
        .unwrap();

        start_rpc_server(
            rollup_config.rpc.clone(),
            &mut task_manager,
            rpc_module,
            Some(rpc_reporting_channel),
        );

        let handler_span = span.clone();
        task_manager.spawn(|cancellation_token| async move {
            let start_l1_height = get_start_l1_height(&rollup_config, &ledger_db)
                .await
                .expect("Failed to fetch starting L1 height");
            l1_block_handler
                .run(start_l1_height, cancellation_token)
                .instrument(handler_span.clone())
                .await
        });

        // Spawn pruner if configs are set
        if let Some(pruner) = pruner {
            task_manager
                .spawn(|cancellation_token| async move { pruner.run(cancellation_token).await });
        }

        task_manager.spawn(|cancellation_token| async move {
            rollup
                .run(cancellation_token)
                .instrument(span)
                .await
                .unwrap();
        });
    }

    task_manager
}

pub fn create_default_rollup_config(
    include_tx_body: bool,
    rollup_path: &Path,
    da_path: &Path,
    node_mode: NodeMode,
    pruning_config: Option<PruningConfig>,
) -> FullNodeConfig<MockDaConfig> {
    let sequencer_da_pub_key = vec![
        2, 88, 141, 32, 42, 252, 193, 238, 74, 181, 37, 76, 120, 71, 236, 37, 185, 161, 53, 187,
        218, 15, 43, 198, 158, 225, 167, 20, 116, 159, 215, 125, 201,
    ];
    let prover_da_pub_key = vec![
        3, 238, 218, 184, 136, 228, 95, 59, 220, 62, 201, 145, 140, 73, 28, 17, 229, 207, 122, 240,
        169, 31, 56, 185, 127, 188, 30, 19, 90, 228, 5, 102, 1,
    ];

    FullNodeConfig {
        public_keys: RollupPublicKeys {
            sequencer_public_key: vec![
                32, 64, 64, 227, 100, 193, 15, 43, 236, 156, 31, 229, 0, 161, 205, 76, 36, 124,
                137, 214, 80, 160, 30, 215, 232, 44, 171, 168, 103, 135, 124, 33,
            ],
            sequencer_da_pub_key: sequencer_da_pub_key.clone(),
            prover_da_pub_key: prover_da_pub_key.clone(),
        },
        storage: StorageConfig {
            path: rollup_path.to_path_buf(),
            backup_path: None,
            db_max_open_files: None,
        },
        rpc: RpcConfig {
            bind_host: "127.0.0.1".into(),
            bind_port: 0,
            max_connections: 100,
            max_request_body_size: 10 * 1024 * 1024,
            max_response_body_size: 10 * 1024 * 1024,
            batch_requests_limit: 50,
            enable_subscriptions: true,
            max_subscriptions_per_connection: 100,
            api_key: None,
        },
        runner: match node_mode {
            NodeMode::FullNode(socket_addr)
            | NodeMode::Prover(socket_addr)
            | NodeMode::LightClientProver(socket_addr) => Some(RunnerConfig {
                include_tx_body,
                sequencer_client_url: format!("http://localhost:{}", socket_addr.port()),
                sync_blocks_count: 10,
                pruning_config,
            }),
            NodeMode::SequencerNode => None,
        },
        da: MockDaConfig {
            sender_address: match node_mode {
                NodeMode::SequencerNode => MockAddress::from(sequencer_da_pub_key),
                NodeMode::Prover(_) => MockAddress::from(prover_da_pub_key),
                _ => MockAddress::new([0; 32]),
            },
            db_path: da_path.to_path_buf(),
        },
        telemetry: Default::default(),
    }
}

pub fn tempdir_with_children(children: &[&str]) -> TempDir {
    let db_dir = tempfile::tempdir().expect("Could not create temporary directory for test");
    for child in children {
        let p = db_dir.path().join(child);
        if !std::path::Path::new(&p).exists() {
            std::fs::create_dir(p).unwrap();
        }
    }

    db_dir
}

#[instrument(level = "debug", skip(client))]
pub async fn wait_for_l2_block(client: &TestClient, num: u64, timeout: Option<Duration>) {
    let start = SystemTime::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(30)); // Default 30 seconds timeout
    loop {
        debug!("Waiting for soft confirmation {}", num);
        let latest_block = client
            .ledger_get_head_soft_confirmation_height()
            .await
            .expect("Expected height to be Some");

        if latest_block >= num {
            break;
        }

        let now = SystemTime::now();
        if start + timeout <= now {
            panic!("Timeout. Latest L2 block is {:?}", latest_block);
        }

        sleep(Duration::from_secs(1)).await;
    }
}

#[instrument(level = "debug", skip(prover_client))]
pub async fn wait_for_prover_l1_height(
    prover_client: &TestClient,
    num: u64,
    timeout: Option<Duration>,
) -> anyhow::Result<()> {
    let start = SystemTime::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)); // Default 600 seconds timeout
    loop {
        debug!("Waiting for prover height {}", num);
        let latest_block = prover_client.ledger_get_last_scanned_l1_height().await;
        if latest_block >= num {
            break;
        }

        let now = SystemTime::now();
        if start + timeout <= now {
            bail!("Timeout. Latest prover L1 height is {}", latest_block);
        }

        sleep(Duration::from_secs(1)).await;
    }
    Ok(())
}

#[instrument(level = "debug", skip(da_service))]
pub async fn wait_for_l1_block(da_service: &MockDaService, num: u64, timeout: Option<Duration>) {
    let start = SystemTime::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(30)); // Default 30 seconds timeout
    loop {
        debug!("Waiting for L1 block height {}", num);
        let da_block = da_service.get_height().await;
        if da_block >= num {
            break;
        }

        let now = SystemTime::now();
        if start + timeout <= now {
            panic!("Timeout. Latest L1 block is {}", da_block);
        }

        sleep(Duration::from_secs(1)).await;
    }
    // Let knowledgage of the new DA block propagate
    sleep(Duration::from_secs(2)).await;
}

#[instrument(level = "debug", skip(da_service))]
pub async fn wait_for_commitment(
    da_service: &MockDaService,
    l1_height: u64,
    timeout: Option<Duration>,
) -> Vec<SequencerCommitment> {
    let start = SystemTime::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(30)); // Default 30 seconds timeout
    loop {
        debug!(
            "Waiting for an L1 commitments to be published at L1 height {}",
            l1_height
        );

        let Ok(l1_block) = da_service.get_block_at(l1_height).await else {
            sleep(Duration::from_secs(1)).await;
            continue;
        };

        let (sequencer_commitments, _) = extract_da_data(da_service, l1_block.clone());

        if !sequencer_commitments.is_empty() {
            return sequencer_commitments;
        }

        let now = SystemTime::now();
        if start + timeout <= now {
            panic!(
                "Timeout. {} commitments exist at this point",
                sequencer_commitments.len()
            );
        }

        sleep(Duration::from_secs(1)).await;
    }
}

pub async fn wait_for_proof(test_client: &TestClient, slot_height: u64, timeout: Option<Duration>) {
    let start = SystemTime::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(60)); // Default 60 seconds timeout
    loop {
        debug!(
            "Waiting for L1 block height containing zkproof {}",
            slot_height
        );
        let proof = test_client
            .ledger_get_verified_batch_proofs_by_slot_height(slot_height)
            .await;
        if proof.is_some() {
            break;
        }

        let now = SystemTime::now();
        if start + timeout <= now {
            panic!("Timeout while waiting for proof at height {}", slot_height);
        }

        sleep(Duration::from_secs(1)).await;
    }
    // Let knowledge of the new DA block propagate
    sleep(Duration::from_secs(2)).await;
}

fn extract_da_data(
    da_service: &MockDaService,
    block: MockBlock,
) -> (Vec<SequencerCommitment>, Vec<Proof>) {
    let mut sequencer_commitments = Vec::<SequencerCommitment>::new();
    let mut zk_proofs = Vec::<Proof>::new();

    da_service
        .extract_relevant_blobs(&block)
        .into_iter()
        .for_each(|tx| {
            let data = DaTxRequest::try_from_slice(tx.full_data());
            if let Ok(DaTxRequest::SequencerCommitment(seq_com)) = data {
                sequencer_commitments.push(seq_com);
            } else if let Ok(DaTxRequest::ZKProof(proof)) = data {
                zk_proofs.push(proof);
            } else {
                tracing::warn!(
                    "Found broken DA data in block 0x{}: {:?}",
                    hex::encode(block.hash()),
                    data
                );
            }
        });
    (sequencer_commitments, zk_proofs)
}

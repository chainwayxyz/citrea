use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use citrea::MockDemoRollup;
use citrea_sequencer::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;
use reth_rpc_types::BlockNumberOrTag;
use rollup_constants::TEST_PRIVATE_KEY;
use shared_backup_db::PostgresConnector;
use sov_mock_da::{MockAddress, MockDaConfig, MockDaService};
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::PrivateKey;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_stf_runner::{
    ProverConfig, RollupConfig, RollupPublicKeys, RpcConfig, RunnerConfig, StorageConfig,
};
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::time::sleep;
use tracing::{debug, info_span, instrument, warn, Instrument};

use crate::test_client::TestClient;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    FullNode(SocketAddr),
    SequencerNode,
    #[allow(dead_code)]
    Prover(SocketAddr),
}

#[allow(clippy::too_many_arguments)]
pub async fn start_rollup(
    rpc_reporting_channel: oneshot::Sender<SocketAddr>,
    rt_genesis_paths: GenesisPaths,
    rollup_prover_config: Option<ProverConfig>,
    node_mode: NodeMode,
    rollup_db_path: PathBuf,
    da_db_path: PathBuf,
    min_soft_confirmations_per_commitment: u64,
    include_tx_body: bool,
    rollup_config: Option<RollupConfig<MockDaConfig>>,
    sequencer_config: Option<SequencerConfig>,
    test_mode: Option<bool>,
    deposit_mempool_fetch_limit: usize,
) {
    // create rollup config default creator function and use them here for the configs
    let rollup_config = rollup_config.unwrap_or_else(|| {
        create_default_rollup_config(include_tx_body, &rollup_db_path, &da_db_path, node_mode)
    });

    let mock_demo_rollup = MockDemoRollup {};

    match node_mode {
        NodeMode::FullNode(_) => {
            let rollup = mock_demo_rollup
                .create_new_rollup(&rt_genesis_paths, rollup_config.clone())
                .await
                .unwrap();
            let span = info_span!("FullNode");
            rollup
                .run_and_report_rpc_port(Some(rpc_reporting_channel))
                .instrument(span)
                .await
                .unwrap();
        }
        NodeMode::Prover(_) => {
            let rollup = mock_demo_rollup
                .create_new_prover(
                    &rt_genesis_paths,
                    rollup_config.clone(),
                    rollup_prover_config.unwrap(),
                )
                .await
                .unwrap();
            let span = info_span!("Prover");
            rollup
                .run_and_report_rpc_port(Some(rpc_reporting_channel))
                .instrument(span)
                .await
                .unwrap();
        }
        NodeMode::SequencerNode => {
            warn!(
                "Starting sequencer node pub key: {:?}",
                DefaultPrivateKey::from_hex(TEST_PRIVATE_KEY)
                    .unwrap()
                    .pub_key()
            );
            let sequencer_config = sequencer_config.unwrap_or_else(|| {
                create_default_sequencer_config(
                    min_soft_confirmations_per_commitment,
                    test_mode,
                    deposit_mempool_fetch_limit,
                )
            });

            let sequencer_rollup = mock_demo_rollup
                .create_new_sequencer(&rt_genesis_paths, rollup_config.clone(), sequencer_config)
                .await
                .unwrap();
            let span = info_span!("Sequencer");
            sequencer_rollup
                .run_and_report_rpc_port(Some(rpc_reporting_channel))
                .instrument(span)
                .await
                .unwrap();
        }
    }
}

pub fn create_default_rollup_config(
    include_tx_body: bool,
    rollup_path: &Path,
    da_path: &Path,
    node_mode: NodeMode,
) -> RollupConfig<MockDaConfig> {
    RollupConfig {
        public_keys: RollupPublicKeys {
            sequencer_public_key: vec![
                32, 64, 64, 227, 100, 193, 15, 43, 236, 156, 31, 229, 0, 161, 205, 76, 36, 124,
                137, 214, 80, 160, 30, 215, 232, 44, 171, 168, 103, 135, 124, 33,
            ],
            sequencer_da_pub_key: vec![0; 32],
            prover_da_pub_key: vec![0; 32],
        },
        storage: StorageConfig {
            path: rollup_path.to_path_buf(),
        },
        rpc: RpcConfig {
            bind_host: "127.0.0.1".into(),
            bind_port: 0,
            max_connections: 100,
            max_request_body_size: 10 * 1024 * 1024,
            max_response_body_size: 10 * 1024 * 1024,
            batch_requests_limit: 50,
        },
        runner: match node_mode {
            NodeMode::FullNode(socket_addr) | NodeMode::Prover(socket_addr) => Some(RunnerConfig {
                include_tx_body,
                sequencer_client_url: format!("http://localhost:{}", socket_addr.port()),
                accept_public_input_as_proven: Some(true),
            }),
            NodeMode::SequencerNode => None,
        },
        da: MockDaConfig {
            sender_address: MockAddress::from([0; 32]),
            db_path: da_path.to_path_buf(),
        },
    }
}

pub fn create_default_sequencer_config(
    min_soft_confirmations_per_commitment: u64,
    test_mode: Option<bool>,
    deposit_mempool_fetch_limit: usize,
) -> SequencerConfig {
    SequencerConfig {
        private_key: TEST_PRIVATE_KEY.to_string(),
        min_soft_confirmations_per_commitment,
        test_mode: test_mode.unwrap_or(false),
        deposit_mempool_fetch_limit,
        mempool_conf: Default::default(),
        // Offchain db will be active only in some tests
        db_config: None,
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

#[instrument(level = "debug")]
pub async fn wait_for_l2_block(sequencer_client: &TestClient, num: u64, timeout: Option<Duration>) {
    let start = SystemTime::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(30)); // Default 30 seconds timeout
    loop {
        debug!("Waiting for soft batch {}", num);
        let latest_block = sequencer_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
            .await;
        if latest_block.number >= Some(num.into()) {
            break;
        }

        let now = SystemTime::now();
        if start + timeout <= now {
            panic!("Timeout");
        }

        sleep(Duration::from_secs(1)).await;
    }
}

#[instrument(level = "debug")]
pub async fn wait_for_prover_l1_height(
    prover_client: &TestClient,
    num: u64,
    timeout: Option<Duration>,
) {
    let start = SystemTime::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(30)); // Default 30 seconds timeout
    loop {
        debug!("Waiting for prover height {}", num);
        let latest_block = prover_client.prover_get_last_scanned_l1_height().await;
        if latest_block >= num {
            break;
        }

        let now = SystemTime::now();
        if start + timeout <= now {
            panic!("Timeout");
        }

        sleep(Duration::from_secs(1)).await;
    }
}

#[instrument(level = "debug")]
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
            panic!("Timeout");
        }

        sleep(Duration::from_secs(1)).await;
    }
}

#[instrument(level = "debug")]
pub async fn wait_for_postgres_commitment(
    db_test_client: &PostgresConnector,
    num: usize,
    timeout: Option<Duration>,
) {
    let start = SystemTime::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(30)); // Default 30 seconds timeout
    loop {
        debug!("Waiting for {} L1 commitments to be published", num);
        let commitments = db_test_client.get_all_commitments().await.unwrap().len();
        if commitments >= num {
            break;
        }

        let now = SystemTime::now();
        if start + timeout <= now {
            panic!("Timeout");
        }

        sleep(Duration::from_secs(1)).await;
    }
}

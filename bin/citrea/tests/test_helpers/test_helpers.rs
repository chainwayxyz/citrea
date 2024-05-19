use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use citrea::MockDemoRollup;
use citrea_sequencer::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;
use rollup_constants::TEST_PRIVATE_KEY;
use sov_mock_da::{MockAddress, MockDaConfig, MockDaSpec};
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::PrivateKey;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_stf_runner::{
    ProverConfig, RollupConfig, RollupPublicKeys, RpcConfig, RunnerConfig, StorageConfig,
};
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::time::sleep;
use tracing::{debug, warn};

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
            rollup
                .run_and_report_rpc_port(Some(rpc_reporting_channel))
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
            rollup
                .run_and_report_rpc_port(Some(rpc_reporting_channel))
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
            sequencer_rollup
                .run_and_report_rpc_port(Some(rpc_reporting_channel))
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
            rollup_path: rollup_path.to_path_buf(),
            da_path: da_path.to_path_buf(),
        },
        rpc: RpcConfig {
            bind_host: "127.0.0.1".into(),
            bind_port: 0,
            max_connections: 100,
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

pub async fn wait_for_l2_batch(sequencer_client: &TestClient, num: u64) {
    loop {
        debug!("Waiting for soft batch {}", num);
        let current = sequencer_client
            .ledger_get_soft_batch_by_number::<MockDaSpec>(num)
            .await;
        if current.is_some() {
            break;
        }

        sleep(Duration::from_secs(1)).await;
    }
}

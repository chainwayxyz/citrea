use std::net::SocketAddr;
use std::path::Path;

use citrea::MockDemoRollup;
use citrea_sequencer::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;
use const_rollup_config::TEST_PRIVATE_KEY;
use sov_mock_da::{MockAddress, MockDaConfig};
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::PrivateKey;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::kernels::basic::{
    BasicKernelGenesisConfig, BasicKernelGenesisPaths,
};
use sov_stf_runner::{
    ProverServiceConfig, RollupConfig, RollupProverConfig, RpcConfig, RunnerConfig,
    SequencerClientRpcConfig, StorageConfig,
};
use tokio::sync::oneshot;
use tracing::warn;

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
    kernel_genesis_paths: BasicKernelGenesisPaths,
    rollup_prover_config: RollupProverConfig,
    node_mode: NodeMode,
    db_path: Option<&str>,
    min_soft_confirmations_per_commitment: u64,
    include_tx_body: bool,
) {
    let mut path = db_path.map(Path::new);
    let mut temp_dir: Option<tempfile::TempDir> = None;
    if db_path.is_none() {
        temp_dir = Some(tempfile::tempdir().unwrap());

        path = Some(temp_dir.as_ref().unwrap().path());
    }

    let rollup_config = RollupConfig {
        sequencer_public_key: vec![
            32, 64, 64, 227, 100, 193, 15, 43, 236, 156, 31, 229, 0, 161, 205, 76, 36, 124, 137,
            214, 80, 160, 30, 215, 232, 44, 171, 168, 103, 135, 124, 33,
        ],
        storage: StorageConfig {
            path: path.unwrap().to_path_buf(),
        },
        runner: RunnerConfig {
            start_height: 1,
            rpc_config: RpcConfig {
                bind_host: "127.0.0.1".into(),
                bind_port: 0,
                max_connections: 100,
            },
        },
        da: MockDaConfig {
            sender_address: MockAddress::from([0; 32]),
        },
        prover_service: ProverServiceConfig {
            aggregated_proof_block_jump: 1,
        },
        sequencer_client: match node_mode {
            NodeMode::FullNode(socket_addr) | NodeMode::Prover(socket_addr) => {
                Some(SequencerClientRpcConfig {
                    url: format!("http://localhost:{}", socket_addr.port()),
                })
            }
            NodeMode::SequencerNode => None,
        },
        include_tx_body,
    };

    let sequencer_config = SequencerConfig {
        min_soft_confirmations_per_commitment,
    };

    let mock_demo_rollup = MockDemoRollup {};

    let kernel_genesis = BasicKernelGenesisConfig {
        chain_state: serde_json::from_str(
            &std::fs::read_to_string(&kernel_genesis_paths.chain_state)
                .expect("Failed to read chain_state genesis config"),
        )
        .expect("Failed to parse chain_state genesis config"),
    };

    match node_mode {
        NodeMode::FullNode(_) => {
            let rollup = mock_demo_rollup
                .create_new_rollup(
                    &rt_genesis_paths,
                    kernel_genesis,
                    rollup_config.clone(),
                    rollup_prover_config,
                    false,
                )
                .await
                .unwrap();
            rollup
                .run_and_report_rpc_port(Some(rpc_reporting_channel))
                .await
                .unwrap();
        }
        NodeMode::Prover(_) => {
            let rollup = mock_demo_rollup
                .create_new_rollup(
                    &rt_genesis_paths,
                    kernel_genesis,
                    rollup_config.clone(),
                    rollup_prover_config,
                    true,
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

            let sequencer_rollup = mock_demo_rollup
                .create_new_sequencer(
                    &rt_genesis_paths,
                    kernel_genesis,
                    rollup_config.clone(),
                    sequencer_config,
                )
                .await
                .unwrap();
            sequencer_rollup
                .run_and_report_rpc_port(Some(rpc_reporting_channel))
                .await
                .unwrap();
        }
    }

    if db_path.is_none() {
        // Close the tempdir explicitly to ensure that rustc doesn't see that it's unused and drop it unexpectedly
        temp_dir.unwrap().close().unwrap();
    }
}

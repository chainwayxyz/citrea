use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::bail;
use borsh::BorshDeserialize;
use citrea::{CitreaRollupBlueprint, MockDemoRollup};
use citrea_common::{
    BatchProverConfig, FullNodeConfig, LightClientProverConfig, RollupPublicKeys, RpcConfig,
    RunnerConfig, SequencerConfig, StorageConfig,
};
use citrea_primitives::TEST_PRIVATE_KEY;
use citrea_stf::genesis_config::GenesisPaths;
use sov_mock_da::{MockAddress, MockBlock, MockDaConfig, MockDaService};
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::PrivateKey;
use sov_modules_rollup_blueprint::{Network, RollupBlueprint as _};
use sov_rollup_interface::da::{BlobReaderTrait, DaData, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::zk::Proof;
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::time::sleep;
use tracing::{debug, info_span, instrument, warn, Instrument};

use crate::test_client::TestClient;
use crate::DEFAULT_PROOF_WAIT_DURATION;

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
    rt_genesis_paths: GenesisPaths,
    rollup_prover_config: Option<BatchProverConfig>,
    light_client_prover_config: Option<LightClientProverConfig>,
    rollup_config: FullNodeConfig<MockDaConfig>,
    sequencer_config: Option<SequencerConfig>,
) {
    // create rollup config default creator function and use them here for the configs

    // We enable risc0 dev mode in tests because the provers in dev mode generate fake receipts that can be verified if the verifier is also in dev mode
    // Fake receipts are receipts without the proof, they only include the journal, which makes them suitable for testing and development
    std::env::set_var("RISC0_DEV_MODE", "1");

    let mock_demo_rollup = MockDemoRollup::new(Network::Testnet);

    if sequencer_config.is_some() && rollup_prover_config.is_some() {
        panic!("Both sequencer and batch prover config cannot be set at the same time");
    }
    if sequencer_config.is_some() && light_client_prover_config.is_some() {
        panic!("Both sequencer and light client prover config cannot be set at the same time");
    }
    if rollup_prover_config.is_some() && light_client_prover_config.is_some() {
        panic!("Both batch prover and light client prover config cannot be set at the same time");
    }

    if let Some(sequencer_config) = sequencer_config {
        warn!(
            "Starting sequencer node pub key: {:?}",
            DefaultPrivateKey::from_hex(TEST_PRIVATE_KEY)
                .unwrap()
                .pub_key()
        );
        let span = info_span!("Sequencer");
        let (mut sequencer, rpc_methods) = CitreaRollupBlueprint::create_new_sequencer(
            &mock_demo_rollup,
            &rt_genesis_paths,
            rollup_config.clone(),
            sequencer_config,
        )
        .instrument(span.clone())
        .await
        .unwrap();

        sequencer
            .start_rpc_server(rpc_methods, Some(rpc_reporting_channel))
            .instrument(span.clone())
            .await
            .unwrap();

        sequencer.run().instrument(span).await.unwrap();
    } else if let Some(rollup_prover_config) = rollup_prover_config {
        let span = info_span!("Prover");
        let (mut rollup, rpc_methods) = CitreaRollupBlueprint::create_new_batch_prover(
            &mock_demo_rollup,
            &rt_genesis_paths,
            rollup_config,
            rollup_prover_config,
        )
        .instrument(span.clone())
        .await
        .unwrap();

        rollup
            .start_rpc_server(rpc_methods, Some(rpc_reporting_channel))
            .instrument(span.clone())
            .await
            .unwrap();

        rollup.run().instrument(span).await.unwrap();
    } else if let Some(light_client_prover_config) = light_client_prover_config {
        let span = info_span!("LightClientProver");
        let rollup = CitreaRollupBlueprint::create_new_light_client_prover(
            &mock_demo_rollup,
            rollup_config.clone(),
            light_client_prover_config,
        )
        .instrument(span.clone())
        .await
        .unwrap();
        rollup
            .run_and_report_rpc_port(Some(rpc_reporting_channel))
            .instrument(span)
            .await
            .unwrap();
    } else {
        let span = info_span!("FullNode");
        let (mut rollup, rpc_methods) = CitreaRollupBlueprint::create_new_rollup(
            &mock_demo_rollup,
            &rt_genesis_paths,
            rollup_config.clone(),
        )
        .instrument(span.clone())
        .await
        .unwrap();

        rollup
            .start_rpc_server(rpc_methods, Some(rpc_reporting_channel))
            .instrument(span.clone())
            .await;

        rollup.run().instrument(span).await.unwrap();
    }
}

pub fn create_default_rollup_config(
    include_tx_body: bool,
    rollup_path: &Path,
    da_path: &Path,
    node_mode: NodeMode,
) -> FullNodeConfig<MockDaConfig> {
    FullNodeConfig {
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
        },
        runner: match node_mode {
            NodeMode::FullNode(socket_addr)
            | NodeMode::Prover(socket_addr)
            | NodeMode::LightClientProver(socket_addr) => Some(RunnerConfig {
                include_tx_body,
                sequencer_client_url: format!("http://localhost:{}", socket_addr.port()),
                sync_blocks_count: 10,
                pruning_config: None,
            }),
            NodeMode::SequencerNode => None,
        },
        da: MockDaConfig {
            sender_address: MockAddress::from([0; 32]),
            db_path: da_path.to_path_buf(),
        },
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
            .unwrap()
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
        .for_each(|mut tx| {
            let data = DaData::try_from_slice(tx.full_data());
            if let Ok(DaData::SequencerCommitment(seq_com)) = data {
                sequencer_commitments.push(seq_com);
            } else if let Ok(DaData::ZKProof(proof)) = data {
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

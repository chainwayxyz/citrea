/// Prover node, proving and full node proof verification related tests
use std::time::Duration;

use citrea_stf::genesis_config::GenesisPaths;
use shared_backup_db::{PostgresConnector, ProofType, SharedBackupDbConfig};
use sov_mock_da::{MockAddress, MockDaService};
use sov_rollup_interface::rpc::{ProofRpcResponse, SoftConfirmationStatus};
use sov_rollup_interface::services::da::DaService;
use sov_stf_runner::ProverConfig;

use crate::evm::make_test_client;
use crate::test_helpers::{
    start_rollup, tempdir_with_children, wait_for_l1_block, wait_for_l2_block,
    wait_for_postgres_proofs, wait_for_proof, wait_for_prover_l1_height, NodeMode,
};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_PROOF_WAIT_DURATION, TEST_DATA_GENESIS_PATH,
};

/// Run the sequencer and the prover node.
/// Trigger proof production.
/// Check if the proof can be queried from the prover node and the database.
#[tokio::test(flavor = "multi_thread")]
async fn test_db_get_proof() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover"]);
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();

    let psql_db_name = "test_db_get_proof".to_string();
    let db_test_client = PostgresConnector::new_test_client(psql_db_name.clone())
        .await
        .unwrap();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            da_db_dir_cloned,
            4,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await;
    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(ProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                proof_sampling_number: 0,
                db_config: Some(SharedBackupDbConfig::default().set_db_name(psql_db_name)),
            }),
            NodeMode::Prover(seq_port),
            prover_db_dir,
            da_db_dir_cloned,
            4,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let prover_node_port = prover_node_port_rx.await.unwrap();

    let prover_node_test_client = make_test_client(prover_node_port).await;
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 4, None).await;

    // Commitment
    wait_for_l1_block(&da_service, 3, None).await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        4,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    wait_for_postgres_proofs(&db_test_client, 1, Some(Duration::from_secs(60))).await;

    let ledger_proof = prover_node_test_client
        .ledger_get_proof_by_slot_height(3)
        .await;

    let db_proofs = db_test_client.get_all_proof_data().await.unwrap();

    assert_eq!(db_proofs.len(), 1);

    let db_state_transition = &db_proofs[0].state_transition.0;

    assert_eq!(
        db_state_transition.sequencer_da_public_key,
        ledger_proof.state_transition.sequencer_da_public_key
    );
    assert_eq!(
        db_state_transition.sequencer_public_key,
        ledger_proof.state_transition.sequencer_public_key
    );
    assert_eq!(db_proofs[0].l1_tx_id, ledger_proof.l1_tx_id);

    match ledger_proof.proof {
        ProofRpcResponse::Full(p) => {
            assert_eq!(db_proofs[0].proof_type, ProofType::Full);
            assert_eq!(db_proofs[0].proof_data, p)
        }
        ProofRpcResponse::PublicInput(p) => {
            assert_eq!(db_proofs[0].proof_type, ProofType::PublicInput);
            assert_eq!(db_proofs[0].proof_data, p)
        }
    };

    seq_task.abort();
    prover_node_task.abort();
}

/// Run the sequencer, prover and full node.
/// Trigger proof production.
/// Check if the verified proof can be queried from the full node.
#[tokio::test(flavor = "multi_thread")]
async fn full_node_verify_proof_and_store() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover", "full-node"]);
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            da_db_dir_cloned,
            4,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await;

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(ProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                proof_sampling_number: 0,
                db_config: None,
            }),
            NodeMode::Prover(seq_port),
            prover_db_dir,
            da_db_dir_cloned,
            4,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let prover_node_port = prover_node_port_rx.await.unwrap();

    let prover_node_test_client = make_test_client(prover_node_port).await;

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::FullNode(seq_port),
            fullnode_db_dir,
            da_db_dir_cloned,
            4,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await;

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 4, None).await;

    // Commitment submitted
    wait_for_l1_block(&da_service, 3, None).await;

    // Full node sync commitment block
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 5, None).await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        4,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    let commitments = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(3)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments.len(), 1);

    assert_eq!(commitments[0].l2_start_block_number, 1);
    assert_eq!(commitments[0].l2_end_block_number, 4);

    assert_eq!(commitments[0].found_in_l1, 3);

    let third_block_hash = da_service.get_block_at(3).await.unwrap().header.hash;

    let commitments_hash = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_hash(third_block_hash.0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments_hash, commitments);

    let prover_proof = prover_node_test_client
        .ledger_get_proof_by_slot_height(3)
        .await;

    // The proof will be in l1 block #4 because prover publishes it after the commitment and
    // in mock da submitting proof and commitments creates a new block.
    // For full node to see the proof, we publish another l2 block and now it will check #4 l1 block
    wait_for_l1_block(&da_service, 4, None).await;

    // Up until this moment, Full node has only seen 2 DA blocks.
    // We need to force it to sync up to 4th DA block.
    for i in 6..=7 {
        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&full_node_test_client, i, None).await;
    }

    // So the full node should see the proof in block 4
    wait_for_proof(&full_node_test_client, 4, Some(Duration::from_secs(60))).await;
    let full_node_proof = full_node_test_client
        .ledger_get_verified_proofs_by_slot_height(4)
        .await
        .unwrap();
    assert_eq!(prover_proof.proof, full_node_proof[0].proof);

    assert_eq!(
        prover_proof.state_transition,
        full_node_proof[0].state_transition
    );

    full_node_test_client
        .ledger_get_soft_confirmation_status(5)
        .await
        .unwrap()
        .unwrap();

    for i in 1..=4 {
        let status = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(status, SoftConfirmationStatus::Proven);
    }

    seq_task.abort();
    prover_node_task.abort();
    full_node_task.abort();
}

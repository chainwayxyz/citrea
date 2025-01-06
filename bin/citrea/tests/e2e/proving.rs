/// Prover node, proving and full node proof verification related tests
use std::time::Duration;

use citrea_batch_prover::GroupCommitments;
use citrea_common::{BatchProverConfig, SequencerConfig};
use citrea_stf::genesis_config::GenesisPaths;
use sov_mock_da::{MockAddress, MockDaService, MockDaSpec};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::DaService;

use crate::evm::make_test_client;
use crate::test_helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l1_block,
    wait_for_l2_block, wait_for_proof, wait_for_prover_l1_height, NodeMode,
};
use crate::TEST_DATA_GENESIS_PATH;

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

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let sequencer_config = SequencerConfig::default();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await.unwrap();

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &prover_db_dir, &da_db_dir, NodeMode::Prover(seq_port));

    let prover_node_task = tokio::spawn(async {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(BatchProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                proof_sampling_number: 0,
                enable_recovery: true,
            }),
            None,
            rollup_config,
            None,
        )
        .await;
    });

    let prover_node_port = prover_node_port_rx.await.unwrap();

    let prover_node_test_client = make_test_client(prover_node_port).await.unwrap();

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &fullnode_db_dir,
        &da_db_dir,
        NodeMode::FullNode(seq_port),
    );
    let full_node_task = tokio::spawn(async {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            None,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await.unwrap();

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
    wait_for_prover_l1_height(&prover_node_test_client, 4, None)
        .await
        .unwrap();

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
        .ledger_get_batch_proofs_by_slot_height(3)
        .await
        .unwrap()[0]
        .clone();

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
        .ledger_get_verified_batch_proofs_by_slot_height(4)
        .await
        .unwrap();
    assert_eq!(prover_proof.proof, full_node_proof[0].proof);

    assert_eq!(prover_proof.proof_output, full_node_proof[0].proof_output);

    let proof_height = full_node_proof[0].proof_output.last_l2_height;
    let soft_confirmation = full_node_test_client
        .ledger_get_soft_confirmation_by_number::<MockDaSpec>(proof_height)
        .await
        .expect("should get soft confirmation");

    assert_eq!(
        full_node_proof[0].proof_output.final_state_root,
        soft_confirmation.state_root
    );

    full_node_test_client
        .ledger_get_soft_confirmation_status(5)
        .await
        .unwrap();

    for i in 1..=4 {
        let status = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap();

        assert_eq!(status, SoftConfirmationStatus::Proven);
    }

    seq_task.abort();
    prover_node_task.abort();
    full_node_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_batch_prover_prove_rpc() {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover", "full-node"]);
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let sequencer_config = SequencerConfig::default();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await.unwrap();

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &prover_db_dir, &da_db_dir, NodeMode::Prover(seq_port));

    let prover_node_task = tokio::spawn(async {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(BatchProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                // Make it impossible for proving to happen
                proof_sampling_number: 1_000_000,
                enable_recovery: true,
            }),
            None,
            rollup_config,
            None,
        )
        .await;
    });

    let prover_node_port = prover_node_port_rx.await.unwrap();

    let prover_node_test_client = make_test_client(prover_node_port).await.unwrap();

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &fullnode_db_dir,
        &da_db_dir,
        NodeMode::FullNode(seq_port),
    );
    let full_node_task = tokio::spawn(async {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            None,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await.unwrap();

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

    // Trigger proving via the RPC endpoint
    prover_node_test_client
        .batch_prover_prove(3, Some(GroupCommitments::Normal))
        .await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(&prover_node_test_client, 4, None)
        .await
        .unwrap();

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
        .ledger_get_batch_proofs_by_slot_height(3)
        .await
        .unwrap()[0]
        .clone();

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
        .ledger_get_verified_batch_proofs_by_slot_height(4)
        .await
        .unwrap();
    assert_eq!(prover_proof.proof, full_node_proof[0].proof);

    assert_eq!(prover_proof.proof_output, full_node_proof[0].proof_output);

    full_node_test_client
        .ledger_get_soft_confirmation_status(5)
        .await
        .unwrap();

    for i in 1..=4 {
        let status = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap();

        assert_eq!(status, SoftConfirmationStatus::Proven);
    }

    seq_task.abort();
    prover_node_task.abort();
    full_node_task.abort();
}

/// Prover node, proving and full node proof verification related tests
use std::time::Duration;

use alloy_primitives::U64;
use citrea_common::{BatchProverConfig, SequencerConfig};
use citrea_stf::genesis_config::GenesisPaths;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_mock_da::{MockAddress, MockDaService};
use sov_rollup_interface::rpc::SequencerCommitmentRpcParam;

use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_commitment,
    wait_for_l1_block, wait_for_l2_block, wait_for_proof, wait_for_prover_job,
    wait_for_prover_job_count, wait_for_prover_l1_height, NodeMode,
};
use crate::common::{make_test_client, TEST_DATA_GENESIS_PATH};

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

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig::default();

    let seq_task = start_rollup(
        seq_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        Some(sequencer_config),
        None,
        false,
    )
    .await;

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await.unwrap();

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &prover_db_dir,
        &da_db_dir,
        NodeMode::Prover(seq_port),
        None,
    );

    let prover_node_task = start_rollup(
        prover_node_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        Some(BatchProverConfig {
            proving_mode: citrea_common::ProverGuestRunConfig::Execute,
            proof_sampling_number: 0,
            enable_recovery: true,
        }),
        None,
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let prover_node_port = prover_node_port_rx.await.unwrap();

    let prover_client = make_test_client(prover_node_port).await.unwrap();

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &fullnode_db_dir,
        &da_db_dir,
        NodeMode::FullNode(seq_port),
        None,
    );
    let full_node_task = start_rollup(
        full_node_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_client = make_test_client(full_node_port).await.unwrap();

    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_client, 4, None).await;

    // wait for commitment at block 3, mockda produces block when it receives a transaction, hence 3
    let commitments = wait_for_commitment(&da_service, 3, None).await;
    assert_eq!(commitments.len(), 1);
    assert_eq!(commitments[0].l2_end_block_number, 4);

    // wait for prover to see commitment
    wait_for_prover_l1_height(&prover_client, 3, None)
        .await
        .unwrap();

    let commitments = prover_client
        .batch_prover_get_commitments_by_l1(3)
        .await
        .unwrap();
    assert_eq!(commitments.len(), 1);

    assert_eq!(commitments[0].l2_end_block_number.to::<u64>(), 4);

    let job_ids = wait_for_prover_job_count(&prover_client, 1, None)
        .await
        .unwrap();
    assert_eq!(job_ids.len(), 1);

    let response = wait_for_prover_job(&prover_client, job_ids[0], None)
        .await
        .unwrap();
    let prover_proof = response.proof.unwrap();

    // The proof will be in l1 block #4 because prover publishes it after the commitment and
    // in mock da submitting proof and commitments creates a new block.
    // For full node to see the proof, we publish another l2 block and now it will check #4 l1 block
    wait_for_l1_block(&da_service, 4, None).await;

    // Up until this moment, Full node has only seen 2 DA blocks.
    // We need to force it to sync up to 4th DA block.
    for i in 6..=7 {
        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&full_node_client, i, None).await;
    }

    // So the full node should see the proof in block 4
    wait_for_proof(&full_node_client, 4, Some(Duration::from_secs(60))).await;
    let full_node_proof = full_node_client
        .ledger_get_verified_batch_proofs_by_slot_height(4)
        .await
        .unwrap();
    assert_eq!(prover_proof.proof, full_node_proof[0].proof);

    assert_eq!(prover_proof.proof_output, full_node_proof[0].proof_output);

    let proof_height = full_node_proof[0].proof_output.last_l2_height;
    let l2_block = full_node_client
        .ledger_get_l2_block_by_number(proof_height.to())
        .await
        .expect("should get l2 block");

    assert_eq!(
        full_node_proof[0].proof_output.final_state_root(),
        l2_block.header.state_root
    );

    seq_task.graceful_shutdown();
    prover_node_task.graceful_shutdown();
    full_node_task.graceful_shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_batch_prover_prove_rpcs() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover", "full-node"]);
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig::default();

    let seq_task = start_rollup(
        seq_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        Some(sequencer_config),
        None,
        false,
    )
    .await;

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await.unwrap();

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &prover_db_dir,
        &da_db_dir,
        NodeMode::Prover(seq_port),
        None,
    );

    let prover_node_task = start_rollup(
        prover_node_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        Some(BatchProverConfig {
            proving_mode: citrea_common::ProverGuestRunConfig::Execute,
            // Make it impossible for proving to happen
            proof_sampling_number: 1_000_000,
            enable_recovery: true,
        }),
        None,
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let prover_node_port = prover_node_port_rx.await.unwrap();

    let prover_client = make_test_client(prover_node_port).await.unwrap();

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &fullnode_db_dir,
        &da_db_dir,
        NodeMode::FullNode(seq_port),
        None,
    );
    let full_node_task = start_rollup(
        full_node_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_client = make_test_client(full_node_port).await.unwrap();

    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_client, 4, None).await;

    // wait for commitment at block 3, mockda produces block when it receives a transaction, hence 3
    let commitments = wait_for_commitment(&da_service, 3, None).await;
    assert_eq!(commitments.len(), 1);
    assert_eq!(commitments[0].l2_end_block_number, 4);

    // wait for prover to see commitment, since sampling is too high, proving won't be triggered here
    wait_for_prover_l1_height(&prover_client, 3, None)
        .await
        .unwrap();

    // Trigger proving via the RPC endpoint
    let job_ids = prover_client.batch_prover_prove(None).await;
    assert_eq!(job_ids.len(), 1);
    let job_id = job_ids[0];

    // wait here until we see from prover's rpc that it finished proving
    let response = wait_for_prover_job(&prover_client, job_id, None)
        .await
        .unwrap();
    assert_eq!(response.id, job_id);
    assert_eq!(response.commitments.len(), 1);
    assert!(response.proof.is_some());

    let commitment = &response.commitments[0];
    assert_eq!(commitment.l2_end_block_number.to::<u64>(), 4);

    // produces 2 blocks due to 1 missing L1 block
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 6, None).await;

    // create a new commitment to manually override the previous one
    let mut l2_block_hashes = Vec::with_capacity(6);
    for block_num in 1..=6 {
        let l2_block = test_client
            .ledger_get_l2_block_by_number(block_num)
            .await
            .unwrap();
        l2_block_hashes.push(l2_block.header.hash);
    }

    let merkle_root = MerkleTree::<Sha256>::from_leaves(&l2_block_hashes)
        .root()
        .unwrap();
    let new_commitment = SequencerCommitmentRpcParam {
        merkle_root,
        index: commitment.index,
        l2_end_block_number: U64::from(6),
        l1_height: U64::from(da_service.get_height().await + 1),
    };

    // ensure that prover also syncs up to l2 block 6
    wait_for_l2_block(&prover_client, 6, None).await;
    // override prev commitment
    prover_client
        .batch_prover_set_commitments(vec![new_commitment])
        .await;

    // invoke proving from RPC
    let job_ids = prover_client.batch_prover_prove(None).await;
    assert_eq!(job_ids.len(), 1);
    let job_id = job_ids[0];

    let response = wait_for_prover_job(&prover_client, job_id, None)
        .await
        .unwrap();
    assert_eq!(response.id, job_id);
    assert_eq!(response.commitments.len(), 1);
    assert!(response.proof.is_some());

    let commitment = &response.commitments[0];
    assert_eq!(commitment.l2_end_block_number.to::<u64>(), 6);

    // pause proving
    prover_client.batch_prover_pause_proving().await;

    // generate another commitment. keep in mind that this commitment is for the block range 5-8,
    // while prover proved 1-6, so there will be a merkle root mismatch if it tried to prove.
    // but it is irrelevant for the purposes of this test since proving is paused.
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 8, None).await;
    wait_for_commitment(&da_service, 6, None).await;

    // invoke proving from RPC, since paused, should not start any job
    let job_ids = prover_client.batch_prover_prove(None).await;
    assert_eq!(job_ids.len(), 0);

    seq_task.graceful_shutdown();
    prover_node_task.graceful_shutdown();
    full_node_task.graceful_shutdown();
}

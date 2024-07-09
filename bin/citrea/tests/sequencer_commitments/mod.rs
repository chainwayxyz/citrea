use std::time::Duration;

use borsh::BorshDeserialize;
use citrea_stf::genesis_config::GenesisPaths;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use shared_backup_db::{PostgresConnector, SharedBackupDbConfig};
use sov_mock_da::{MockAddress, MockDaService, MockDaSpec};
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::DaData;
use sov_rollup_interface::services::da::DaService;
use sov_stf_runner::ProverConfig;

use crate::evm::make_test_client;
use crate::test_client::TestClient;
use crate::test_helpers::{
    create_default_sequencer_config, start_rollup, tempdir_with_children, wait_for_l1_block,
    wait_for_l2_block, wait_for_postgres_commitment, wait_for_prover_l1_height, NodeMode,
};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_PROOF_WAIT_DURATION, TEST_DATA_GENESIS_PATH,
};

#[tokio::test(flavor = "multi_thread")]
async fn sequencer_sends_commitments_to_da_layer() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let db_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async move {
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

    // publish 3 soft confirmations, no commitment should be sent
    for _ in 0..3 {
        test_client.send_publish_batch_request().await;
    }
    wait_for_l2_block(&test_client, 3, None).await;

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    let mut height = 1;
    let last_finalized = da_service
        .get_last_finalized_block_header()
        .await
        .unwrap()
        .height;

    // look over all available da_blocks and check that no commitment was sent
    while height <= last_finalized {
        let block = da_service.get_block_at(height).await.unwrap();

        let mut blobs = da_service.extract_relevant_blobs(&block);

        for mut blob in blobs.drain(0..) {
            let data = blob.full_data();

            assert_eq!(data, &[] as &[u8]); // empty blocks in mock da have blobs []
        }

        height += 1;
    }

    // Publish one more L2 block
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 4, None).await;

    // The previous L2 block triggers a commitment
    // which will create new L1 block.
    wait_for_l1_block(&da_service, 3, None).await;

    let start_l2_block: u64 = 1;
    let end_l2_block: u64 = 4;

    check_sequencer_commitment(
        test_client.as_ref(),
        &da_service,
        start_l2_block,
        end_l2_block,
    )
    .await;

    // publish 4 soft confirmations, no commitment should be sent
    for _ in 0..4 {
        test_client.send_publish_batch_request().await;
    }
    wait_for_l2_block(&test_client, 8, None).await;
    wait_for_l1_block(&da_service, 4, None).await;

    let start_l2_block: u64 = end_l2_block + 1;
    let end_l2_block: u64 = end_l2_block + 4; // can only be the block before the one comitment landed in

    check_sequencer_commitment(
        test_client.as_ref(),
        &da_service,
        start_l2_block,
        end_l2_block,
    )
    .await;

    seq_task.abort();
}

async fn check_sequencer_commitment(
    test_client: &TestClient,
    da_service: &MockDaService,
    start_l2_block: u64,
    end_l2_block: u64,
) {
    let last_finalized_height = da_service
        .get_last_finalized_block_header()
        .await
        .unwrap()
        .height;
    let block = da_service
        .get_block_at(last_finalized_height)
        .await
        .unwrap();

    let mut blobs = da_service.extract_relevant_blobs(&block);

    assert_eq!(blobs.len(), 1);

    let mut blob = blobs.pop().unwrap();

    let data = blob.full_data();

    let commitment = DaData::try_from_slice(data).unwrap();

    matches!(commitment, DaData::SequencerCommitment(_));

    let DaData::SequencerCommitment(commitment) = commitment else {
        panic!("Expected SequencerCommitment, got {:?}", commitment);
    };

    let mut batch_receipts = Vec::new();

    for i in start_l2_block..=end_l2_block {
        batch_receipts.push(
            test_client
                .ledger_get_soft_batch_by_number::<MockDaSpec>(i)
                .await
                .unwrap(),
        );
    }

    // create merkle tree
    let merkle_tree = MerkleTree::<Sha256>::from_leaves(
        batch_receipts
            .iter()
            .map(|x| x.hash)
            .collect::<Vec<_>>()
            .as_slice(),
    );

    assert_eq!(commitment.l2_start_block_number, start_l2_block);
    assert_eq!(commitment.l2_end_block_number, end_l2_block);
    assert_eq!(commitment.merkle_root, merkle_tree.root().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn check_commitment_in_offchain_db() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();
    let mut sequencer_config = create_default_sequencer_config(4, Some(true), 10);

    let db_name = "check_commitment_in_offchain_db".to_owned();
    sequencer_config.db_config = Some(SharedBackupDbConfig::default().set_db_name(db_name.clone()));

    // drops db if exists from previous test runs, recreates the db
    let db_test_client = PostgresConnector::new_test_client(db_name).await.unwrap();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async move {
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
            Some(sequencer_config),
            Some(true),
            10,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await;
    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    // publish 3 soft confirmations, no commitment should be sent
    for _ in 0..3 {
        test_client.send_publish_batch_request().await;
    }
    wait_for_l2_block(&test_client, 3, None).await;

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 3, None).await;

    // publish 4th block
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 4, None).await;

    // commitment should be published with this call
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 4, None).await;
    wait_for_l1_block(&da_service, 5, None).await;

    wait_for_postgres_commitment(
        &db_test_client,
        1,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    let commitments = db_test_client.get_all_commitments().await.unwrap();
    assert_eq!(commitments.len(), 1);
    assert_eq!(commitments[0].l2_start_height, 1);
    assert_eq!(commitments[0].l2_end_height, 4);

    seq_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ledger_get_commitments_on_slot() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = db_dir.path().join("full-node").to_path_buf();

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

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::FullNode(seq_port),
            fullnode_db_dir,
            da_db_dir,
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
    wait_for_l1_block(&da_service, 3, None).await;

    // full node gets the commitment
    test_client.send_publish_batch_request().await;

    wait_for_l2_block(&full_node_test_client, 5, None).await;

    let commitments = full_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(3)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments.len(), 1);

    assert_eq!(commitments[0].l2_start_block_number, 1);
    assert_eq!(commitments[0].l2_end_block_number, 4);

    assert_eq!(commitments[0].found_in_l1, 3);

    let third_block_hash = da_service.get_block_at(3).await.unwrap().header.hash;

    let commitments_hash = full_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_hash(third_block_hash.0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments_hash, commitments);

    seq_task.abort();
    full_node_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ledger_get_commitments_on_slot_prover() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let db_dir = tempdir_with_children(&["DA", "sequencer", "prover"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = db_dir.path().join("prover").to_path_buf();

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
            da_db_dir,
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

    seq_task.abort();
    prover_node_task.abort();
}

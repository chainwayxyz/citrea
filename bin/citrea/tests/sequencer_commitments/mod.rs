use std::time::Duration;

use borsh::BorshDeserialize;
use citrea_stf::genesis_config::GenesisPaths;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use shared_backup_db::{PostgresConnector, SharedBackupDbConfig};
use sov_mock_da::{MockAddress, MockDaService, MockDaSpec};
use sov_modules_api::{BlobReaderTrait, SignedSoftConfirmationBatch};
use sov_rollup_interface::da::DaData;
use sov_rollup_interface::services::da::DaService;
use sov_stf_runner::ProverConfig;
use tokio::time::sleep;

use crate::evm::make_test_client;
use crate::test_client::TestClient;
use crate::test_helpers::{create_default_sequencer_config, start_rollup, NodeMode};
use crate::DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT;

#[tokio::test(flavor = "multi_thread")]
async fn sequencer_sends_commitments_to_da_layer() {
    // citrea::initialize_logging();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            None,
            NodeMode::SequencerNode,
            None,
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
    let da_service = MockDaService::new(MockAddress::from([0; 32]));

    // publish 3 soft confirmations, no commitment should be sent
    for _ in 0..3 {
        test_client.send_publish_batch_request().await;
    }

    da_service.publish_test_block().await.unwrap();

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

    da_service.publish_test_block().await.unwrap();
    test_client.send_publish_batch_request().await;

    let start_l2_block: u64 = 1;
    let end_l2_block: u64 = 4; // can only be the block before the one comitment landed in
    let start_l1_block = 1;

    let end_l1_block = check_sequencer_commitment(
        test_client.as_ref(),
        &da_service,
        start_l2_block,
        end_l2_block,
        start_l1_block,
    )
    .await;

    // publish 4 soft confirmations, no commitment should be sent
    for _ in 0..4 {
        test_client.send_publish_batch_request().await;
    }
    da_service.publish_test_block().await.unwrap();

    test_client.send_publish_batch_request().await;
    sleep(Duration::from_secs(1)).await;

    let start_l2_block: u64 = end_l2_block + 1;
    let end_l2_block: u64 = end_l2_block + 5; // can only be the block before the one comitment landed in
    let start_l1_block = end_l1_block + 1;

    check_sequencer_commitment(
        test_client.as_ref(),
        &da_service,
        start_l2_block,
        end_l2_block,
        start_l1_block,
    )
    .await;

    seq_task.abort();
}

async fn check_sequencer_commitment(
    test_client: &TestClient,
    da_service: &MockDaService,
    start_l2_block: u64,
    end_l2_block: u64,
    start_l1_block: u64,
    // end_l1_block: u64,
) -> u64 {
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

    let height = test_client.eth_block_number().await;

    let commitments_last_soft_confirmation: SignedSoftConfirmationBatch = test_client
        .ledger_get_soft_batch_by_number::<MockDaSpec>(height - 1) // after commitment is sent another block is published
        .await
        .unwrap()
        .into();

    let start_l1_block = da_service.get_block_at(start_l1_block).await.unwrap();
    let end_l1_block = da_service
        .get_block_at(commitments_last_soft_confirmation.da_slot_height())
        .await
        .unwrap();

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

    assert_eq!(commitment.l1_start_block_hash, start_l1_block.header.hash.0);
    assert_eq!(commitment.l1_end_block_hash, end_l1_block.header.hash.0);
    assert_eq!(commitment.merkle_root, merkle_tree.root().unwrap());

    end_l1_block.header.height
}

#[tokio::test(flavor = "multi_thread")]
async fn check_commitment_in_offchain_db() {
    // citrea::initialize_logging();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();
    let mut sequencer_config = create_default_sequencer_config(4, Some(true), 10);

    sequencer_config.db_config = Some(SharedBackupDbConfig::default());

    // drops db if exists from previous test runs, recreates the db
    let db_test_client =
        PostgresConnector::new_test_client("check_commitment_in_offchain_db".to_string())
            .await
            .unwrap();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            None,
            NodeMode::SequencerNode,
            None,
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
    let da_service = MockDaService::new(MockAddress::from([0; 32]));

    da_service.publish_test_block().await.unwrap();

    // publish 3 soft confirmations, no commitment should be sent
    for _ in 0..3 {
        test_client.send_publish_batch_request().await;
    }

    da_service.publish_test_block().await.unwrap();

    // publish 4th block
    test_client.send_publish_batch_request().await;
    // new da block
    da_service.publish_test_block().await.unwrap();

    // commtiment should be published with this call
    test_client.send_publish_batch_request().await;

    sleep(Duration::from_secs(5)).await;

    let commitments = db_test_client.get_all_commitments().await.unwrap();
    assert_eq!(commitments.len(), 1);
    assert_eq!(commitments[0].l1_start_height, 2);
    assert_eq!(commitments[0].l1_end_height, 3);

    seq_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ledger_get_commitments_on_slot() {
    // citrea::initialize_logging();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            None,
            NodeMode::SequencerNode,
            None,
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
    let da_service = MockDaService::new(MockAddress::from([0; 32]));

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            None,
            NodeMode::FullNode(seq_port),
            None,
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
    sleep(Duration::from_secs(1)).await;

    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    da_service.publish_test_block().await.unwrap();
    // submits with new da block
    test_client.send_publish_batch_request().await;
    // full node gets the commitment
    test_client.send_publish_batch_request().await;
    // da_service.publish_test_block().await.unwrap();
    sleep(Duration::from_secs(4)).await;

    let commitments = full_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(4)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments.len(), 1);

    let second_hash = da_service.get_block_at(2).await.unwrap().header.hash;
    assert_eq!(
        commitments[0].l1_start_block_hash.to_vec(),
        second_hash.0.to_vec()
    );
    assert_eq!(
        commitments[0].l1_end_block_hash.to_vec(),
        second_hash.0.to_vec()
    );

    assert_eq!(commitments[0].found_in_l1, 4);

    let fourth_block_hash = da_service.get_block_at(4).await.unwrap().header.hash;

    let commitments_hash = full_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_hash(fourth_block_hash.0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments_hash, commitments);

    seq_task.abort();
    full_node_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ledger_get_commitments_on_slot_prover() {
    // citrea::initialize_logging();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            None,
            NodeMode::SequencerNode,
            None,
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
    let da_service = MockDaService::new(MockAddress::from([0; 32]));

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            Some(ProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                skip_proving_until_l1_height: None,
            }),
            NodeMode::Prover(seq_port),
            None,
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
    sleep(Duration::from_secs(1)).await;

    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    da_service.publish_test_block().await.unwrap();
    // submits with new da block
    test_client.send_publish_batch_request().await;
    // prover node gets the commitment
    test_client.send_publish_batch_request().await;
    // da_service.publish_test_block().await.unwrap();

    // wait here until we see from prover's rpc that it finished proving
    while prover_node_test_client
        .prover_get_last_scanned_l1_height()
        .await
        != 5
    {
        // sleep 2
        sleep(Duration::from_secs(2)).await;
    }
    sleep(Duration::from_secs(4)).await;

    let commitments = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(4)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments.len(), 1);

    let second_hash = da_service.get_block_at(2).await.unwrap().header.hash;
    assert_eq!(
        commitments[0].l1_start_block_hash.to_vec(),
        second_hash.0.to_vec()
    );
    assert_eq!(
        commitments[0].l1_end_block_hash.to_vec(),
        second_hash.0.to_vec()
    );

    assert_eq!(commitments[0].found_in_l1, 4);

    let fourth_block_hash = da_service.get_block_at(4).await.unwrap().header.hash;

    let commitments_hash = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_hash(fourth_block_hash.0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments_hash, commitments);

    seq_task.abort();
    prover_node_task.abort();
}

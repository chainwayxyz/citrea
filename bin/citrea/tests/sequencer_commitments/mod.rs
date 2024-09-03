use borsh::BorshDeserialize;
use citrea_stf::genesis_config::GenesisPaths;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_mock_da::{MockAddress, MockDaService, MockDaSpec};
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::DaData;
use sov_rollup_interface::services::da::DaService;
use sov_stf_runner::ProverConfig;

use crate::evm::make_test_client;
use crate::test_client::TestClient;
use crate::test_helpers::{
    start_rollup, tempdir_with_children, wait_for_l1_block, wait_for_l2_block,
    wait_for_prover_l1_height, NodeMode,
};
use crate::{DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, TEST_DATA_GENESIS_PATH};

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
    let test_client = make_test_client(seq_port).await.unwrap();

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
                .ledger_get_soft_confirmation_by_number::<MockDaSpec>(i)
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

/// Testing sycning behaviour of the full nodes and the prover node.
use std::str::FromStr;
use std::time::Duration;

use citrea_stf::genesis_config::GenesisPaths;
use ethereum_rpc::CitreaStatus;
use reth_primitives::{Address, BlockNumberOrTag};
use shared_backup_db::SharedBackupDbConfig;
use sov_mock_da::{MockAddress, MockDaService, MockDaSpec, MockHash};
use sov_rollup_interface::da::{DaData, DaSpec};
use sov_rollup_interface::services::da::DaService;
use sov_stf_runner::ProverConfig;
use tokio::time::sleep;

use crate::e2e::{execute_blocks, initialize_test, TestConfig};
use crate::evm::{init_test_rollup, make_test_client};
use crate::test_helpers::{
    start_rollup, tempdir_with_children, wait_for_l1_block, wait_for_l2_block,
    wait_for_prover_l1_height, NodeMode,
};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
    DEFAULT_PROOF_WAIT_DURATION, TEST_DATA_GENESIS_PATH,
};

/// Run the sequencer.
/// Publish blocks.
/// Run the full node.
/// Check if the full node has the same state as the sequencer.
#[tokio::test(flavor = "multi_thread")]
async fn test_delayed_sync_ten_blocks() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

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
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    for _ in 0..10 {
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&seq_test_client, 10, None).await;

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
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
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

    wait_for_l2_block(&full_node_test_client, 10, None).await;

    let seq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(10)))
        .await;
    let full_node_block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(10)))
        .await;

    assert_eq!(
        seq_block.header.state_root,
        full_node_block.header.state_root
    );
    assert_eq!(seq_block.header.hash, full_node_block.header.hash);

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

/// Run the sequencer.
/// Run the full node.
/// Publish blocks.
/// Check if the full node has the same state as the sequencer.
#[tokio::test(flavor = "multi_thread")]
async fn test_same_block_sync() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            sequencer_path: sequencer_db_dir,
            da_path: da_db_dir.clone(),
            fullnode_path: fullnode_db_dir,
            ..Default::default()
        })
        .await;

    let _ = execute_blocks(&seq_test_client, &full_node_test_client, &da_db_dir).await;

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

/// Run the sequencer.
/// Run the full node.
/// Publish blocks. But make sure that the soft confirmations are built on different DA blocks.
/// Check if the full node has the same values as the sequencer.
#[tokio::test(flavor = "multi_thread")]
async fn test_soft_confirmations_on_different_blocks() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir.clone(),
            sequencer_path: sequencer_db_dir.clone(),
            fullnode_path: fullnode_db_dir.clone(),
            ..Default::default()
        })
        .await;

    // first publish a few blocks fast make it land in the same da block
    for _ in 1..=6 {
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&seq_test_client, 6, None).await;
    wait_for_l2_block(&full_node_test_client, 6, None).await;

    let mut last_da_slot_height = 0;
    let mut last_da_slot_hash = <MockDaSpec as DaSpec>::SlotHash::from([0u8; 32]);

    // now retrieve soft confirmations from the sequencer and full node and check if they are the same
    for i in 1..=6 {
        let seq_soft_conf = seq_test_client
            .ledger_get_soft_batch_by_number::<MockDaSpec>(i)
            .await
            .unwrap();
        let full_node_soft_conf = full_node_test_client
            .ledger_get_soft_batch_by_number::<MockDaSpec>(i)
            .await
            .unwrap();

        if i != 1 {
            assert_eq!(last_da_slot_height, seq_soft_conf.da_slot_height);
            assert_eq!(last_da_slot_hash, MockHash(seq_soft_conf.da_slot_hash));
        }

        assert_eq!(
            seq_soft_conf.da_slot_height,
            full_node_soft_conf.da_slot_height
        );

        assert_eq!(seq_soft_conf.da_slot_hash, full_node_soft_conf.da_slot_hash);

        last_da_slot_height = seq_soft_conf.da_slot_height;
        last_da_slot_hash = MockHash(seq_soft_conf.da_slot_hash);
    }

    // publish new da block
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    for _ in 1..=6 {
        seq_test_client.spam_publish_batch_request().await.unwrap();
    }

    wait_for_l2_block(&seq_test_client, 12, None).await;
    wait_for_l2_block(&full_node_test_client, 12, None).await;

    for i in 7..=12 {
        let seq_soft_conf = seq_test_client
            .ledger_get_soft_batch_by_number::<MockDaSpec>(i)
            .await
            .unwrap();
        let full_node_soft_conf = full_node_test_client
            .ledger_get_soft_batch_by_number::<MockDaSpec>(i)
            .await
            .unwrap();

        if i != 7 {
            assert_eq!(last_da_slot_height, seq_soft_conf.da_slot_height);
            assert_eq!(last_da_slot_hash, MockHash(seq_soft_conf.da_slot_hash));
        } else {
            assert_ne!(last_da_slot_height, seq_soft_conf.da_slot_height);
            assert_ne!(last_da_slot_hash, MockHash(seq_soft_conf.da_slot_hash));
        }

        assert_eq!(
            seq_soft_conf.da_slot_height,
            full_node_soft_conf.da_slot_height
        );

        assert_eq!(seq_soft_conf.da_slot_hash, full_node_soft_conf.da_slot_hash);

        last_da_slot_height = seq_soft_conf.da_slot_height;
        last_da_slot_hash = MockHash(seq_soft_conf.da_slot_hash);
    }

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

/// Run the sequencer.
/// Run the prover.
/// Trigger sequencer commitments
/// Check if the prover syncs when it encounters a sequencer commmitment on DA.
///
/// Note: This test now obsolote, I don't know how it works.
#[tokio::test(flavor = "multi_thread")]
async fn test_prover_sync_with_commitments() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir);

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
    let seq_test_client = make_test_client(seq_port).await;

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(ProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                db_config: Some(SharedBackupDbConfig::default()),
                proof_sampling_number: 0,
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

    // prover should not have any blocks saved
    assert_eq!(prover_node_test_client.eth_block_number().await, 0);

    // publish 3 soft confirmations, no commitment should be sent
    for _ in 0..3 {
        seq_test_client.send_publish_batch_request().await;
    }

    // start l1 height = 1, end = 2
    seq_test_client.send_publish_batch_request().await;
    // sequencer commitment should be sent
    wait_for_l1_block(&da_service, 2, None).await;

    // Submit an L2 block to prevent sequencer from falling behind.
    seq_test_client.send_publish_batch_request().await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        3,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    // Submit an L2 block to prevent sequencer from falling behind.
    seq_test_client.send_publish_batch_request().await;

    // prover should have synced all 6 l2 blocks
    // ps there are 6 blocks because:
    // when a new proof is submitted in mock da a new empty da block is published
    // and for every empty da block sequencer publishes a new empty soft confirmation in order to not skip a block
    wait_for_l2_block(&prover_node_test_client, 6, None).await;
    sleep(Duration::from_secs(1)).await;
    assert_eq!(prover_node_test_client.eth_block_number().await, 6);

    // Trigger another commitment
    for _ in 7..=8 {
        seq_test_client.send_publish_batch_request().await;
    }
    wait_for_l2_block(&seq_test_client, 8, None).await;
    // Allow for the L2 block to be commited and stored
    // Otherwise, the L2 block height might be registered but it hasn't
    // been processed inside the EVM yet.
    sleep(Duration::from_secs(1)).await;
    assert_eq!(seq_test_client.eth_block_number().await, 8);
    wait_for_l1_block(&da_service, 4, None).await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        4,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    // Should now have 8 blocks = 2 commitments of blocks 1-4 and 5-9
    // there is an extra soft confirmation due to the prover publishing a proof. This causes
    // a new MockDa block, which in turn causes the sequencer to publish an extra soft confirmation
    // becase it must not skip blocks.
    wait_for_l2_block(&prover_node_test_client, 8, None).await;
    // Allow for the L2 block to be commited and stored
    // Otherwise, the L2 block height might be registered but it hasn't
    // been processed inside the EVM yet.
    sleep(Duration::from_secs(1)).await;
    assert_eq!(prover_node_test_client.eth_block_number().await, 8);
    // on the 8th DA block, we should have a proof
    let mut blobs = da_service.get_block_at(3).await.unwrap().blobs;

    assert_eq!(blobs.len(), 1);

    let mut blob = blobs.pop().unwrap();
    blob.data.advance(blob.data.total_len());

    let da_data = blob.data.accumulator();

    let proof: DaData = borsh::BorshDeserialize::try_from_slice(da_data).unwrap();

    assert!(matches!(proof, DaData::ZKProof(_)));

    // TODO: Also test with multiple commitments in single Mock DA Block
    seq_task.abort();
    prover_node_task.abort();
    Ok(())
}

/// Checks `citre_syncStatus` RPC call.
#[tokio::test(flavor = "multi_thread")]
async fn test_full_node_sync_status() {
    // citrea::initialize_logging();

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

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
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    for _ in 0..300 {
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&seq_test_client, 300, Some(Duration::from_secs(60))).await;

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
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
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

    wait_for_l2_block(&full_node_test_client, 5, Some(Duration::from_secs(60))).await;

    let status = full_node_test_client.citrea_sync_status().await;

    match status {
        CitreaStatus::Syncing(syncing) => {
            assert!(syncing.synced_block_number > 0 && syncing.synced_block_number < 300);
            assert_eq!(syncing.head_block_number, 300);
        }
        _ => panic!("Expected syncing status"),
    }

    wait_for_l2_block(&full_node_test_client, 300, Some(Duration::from_secs(60))).await;

    let status = full_node_test_client.citrea_sync_status().await;

    match status {
        CitreaStatus::Synced(synced_up_to) => assert_eq!(synced_up_to, 300),
        _ => panic!("Expected synced status"),
    }

    seq_task.abort();
    full_node_task.abort();
}

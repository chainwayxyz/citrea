use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::str::FromStr;

use alloy_primitives::Address;
/// Testing if the sequencer and full node can handle system transactions correctly (the full node should have the same system transactions as the sequencer)
use citrea_pruning::PruningConfig;
use futures::FutureExt;
use reth_primitives::BlockNumberOrTag;
use sov_mock_da::{MockAddress, MockDaService};

use crate::e2e::{initialize_test, TestConfig};
use crate::test_helpers::{tempdir_with_children, wait_for_l1_block, wait_for_l2_block};

/// Trigger pruning native DB data.
#[tokio::test(flavor = "multi_thread")]
async fn test_native_db_pruning() -> Result<(), anyhow::Error> {
    citrea::initialize_logging(tracing::Level::DEBUG);
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }
    wait_for_l1_block(&da_service, 3, None).await;

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir,
            sequencer_path: sequencer_db_dir,
            fullnode_path: fullnode_db_dir,
            pruning_config: Some(PruningConfig { distance: 20 }),
            ..Default::default()
        })
        .await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265").unwrap();
    let mut transactions = BTreeMap::new();
    let mut block_hashes = BTreeMap::new();

    for i in 1..=50 {
        // send one ether to some address
        let pending = seq_test_client
            .send_eth(addr, None, None, None, 1e18 as u128)
            .await
            .unwrap();

        seq_test_client.spam_publish_batch_request().await.unwrap();

        let tx_hash = pending.tx_hash();
        transactions.insert(i, *tx_hash);

        if i % 5 == 0 {
            wait_for_l2_block(&seq_test_client, i, None).await;

            // Get the hash of the latest block
            let block_hash = seq_test_client
                .eth_get_block_by_number(Some(BlockNumberOrTag::Number(i)))
                .await
                .header
                .hash;
            block_hashes.insert(i, block_hash);

            da_service.publish_test_block().await.unwrap();

            wait_for_l1_block(&da_service, 3 + (i / 5), None).await;
        }
    }

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 51, None).await;

    // ####################################
    // ROUND 1: FAIL
    // ###################################
    // This request is requesting data which has been pruned.
    let check_block_by_number_result = AssertUnwindSafe(
        full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(1))),
    )
    .catch_unwind()
    .await;
    assert!(check_block_by_number_result.is_err());

    let get_block_receipts_result = AssertUnwindSafe(full_node_test_client.eth_get_block_receipts(
        reth_primitives::BlockId::Number(BlockNumberOrTag::Number(1)),
    ))
    .catch_unwind()
    .await;
    assert!(get_block_receipts_result.is_err());

    let get_block_by_hash_result = AssertUnwindSafe(
        full_node_test_client.eth_get_block_by_hash(*block_hashes.get(&5).unwrap()),
    )
    .catch_unwind()
    .await;
    assert!(get_block_by_hash_result.is_err());

    let check_transaction_by_hash_result = AssertUnwindSafe(
        full_node_test_client.eth_get_transaction_by_hash(*transactions.get(&1).unwrap(), None),
    )
    .catch_unwind()
    .await;
    assert!(check_transaction_by_hash_result.unwrap().is_none());

    // ####################################
    // ROUND 2: FAIL
    // ###################################
    // This request is requesting data which has been pruned.
    let check_block_by_number_result = AssertUnwindSafe(
        full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(20))),
    )
    .catch_unwind()
    .await;
    assert!(check_block_by_number_result.is_err());

    let get_block_receipts_result = AssertUnwindSafe(full_node_test_client.eth_get_block_receipts(
        reth_primitives::BlockId::Number(BlockNumberOrTag::Number(20)),
    ))
    .catch_unwind()
    .await;
    assert!(get_block_receipts_result.is_err());

    let get_block_by_hash_result = AssertUnwindSafe(
        full_node_test_client.eth_get_block_by_hash(*block_hashes.get(&15).unwrap()),
    )
    .catch_unwind()
    .await;
    assert!(get_block_by_hash_result.is_err());

    let check_transaction_by_hash_result = AssertUnwindSafe(
        full_node_test_client.eth_get_transaction_by_hash(*transactions.get(&20).unwrap(), None),
    )
    .catch_unwind()
    .await;
    assert!(check_transaction_by_hash_result.unwrap().is_none());

    // ####################################
    // ROUND 3: Pass
    // ###################################
    // Should NOT panic as the data we're requesting here is correct
    full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(21)))
        .await;

    // Should NOT panic
    full_node_test_client
        .eth_get_block_by_hash(*block_hashes.get(&25).unwrap())
        .await;

    let receipts = full_node_test_client
        .eth_get_block_receipts(reth_primitives::BlockId::Number(BlockNumberOrTag::Number(
            21,
        )))
        .await;
    assert!(!receipts.is_empty());

    let tx = full_node_test_client
        .eth_get_transaction_by_hash(*transactions.get(&25).unwrap(), Some(false))
        .await;
    assert!(tx.is_some());

    for i in 52..=81 {
        // send one ether to some address
        let pending = seq_test_client
            .send_eth(addr, None, None, None, 1e18 as u128)
            .await
            .unwrap();

        seq_test_client.spam_publish_batch_request().await.unwrap();

        let tx_hash = pending.tx_hash();
        transactions.insert(i, *tx_hash);

        if i % 5 == 0 {
            wait_for_l2_block(&seq_test_client, i, None).await;

            // Get the hash of the latest block
            let block_hash = seq_test_client
                .eth_get_block_by_number(Some(BlockNumberOrTag::Number(i)))
                .await
                .header
                .hash;
            block_hashes.insert(i, block_hash);

            da_service.publish_test_block().await.unwrap();

            wait_for_l1_block(&da_service, 3 + (i / 5), None).await;
        }
    }

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 81, None).await;

    // ####################################
    // ROUND 1: FAIL
    // ###################################
    // This request is requesting data which has been pruned.
    let check_block_by_number_result = AssertUnwindSafe(
        full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(40))),
    )
    .catch_unwind()
    .await;
    assert!(check_block_by_number_result.is_err());

    let get_block_receipts_result = AssertUnwindSafe(full_node_test_client.eth_get_block_receipts(
        reth_primitives::BlockId::Number(BlockNumberOrTag::Number(40)),
    ))
    .catch_unwind()
    .await;
    assert!(get_block_receipts_result.is_err());

    let get_block_by_hash_result = AssertUnwindSafe(
        full_node_test_client.eth_get_block_by_hash(*block_hashes.get(&45).unwrap()),
    )
    .catch_unwind()
    .await;
    assert!(get_block_by_hash_result.is_err());

    let check_transaction_by_hash_result = AssertUnwindSafe(
        full_node_test_client.eth_get_transaction_by_hash(*transactions.get(&40).unwrap(), None),
    )
    .catch_unwind()
    .await;
    assert!(check_transaction_by_hash_result.unwrap().is_none());

    // ####################################
    // ROUND 2: FAIL
    // ###################################
    // This request is requesting data which has been pruned.
    let check_block_by_number_result = AssertUnwindSafe(
        full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(60))),
    )
    .catch_unwind()
    .await;
    assert!(check_block_by_number_result.is_err());

    let get_block_receipts_result = AssertUnwindSafe(full_node_test_client.eth_get_block_receipts(
        reth_primitives::BlockId::Number(BlockNumberOrTag::Number(60)),
    ))
    .catch_unwind()
    .await;
    assert!(get_block_receipts_result.is_err());

    let get_block_by_hash_result = AssertUnwindSafe(
        full_node_test_client.eth_get_block_by_hash(*block_hashes.get(&55).unwrap()),
    )
    .catch_unwind()
    .await;
    assert!(get_block_by_hash_result.is_err());

    let check_transaction_by_hash_result = AssertUnwindSafe(
        full_node_test_client.eth_get_transaction_by_hash(*transactions.get(&60).unwrap(), None),
    )
    .catch_unwind()
    .await;
    assert!(check_transaction_by_hash_result.unwrap().is_none());

    // ####################################
    // ROUND 3: Pass
    // ###################################
    // Should NOT panic as the data we're requesting here is correct
    full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(61)))
        .await;

    // Should NOT panic
    full_node_test_client
        .eth_get_block_by_hash(*block_hashes.get(&65).unwrap())
        .await;

    let receipts = full_node_test_client
        .eth_get_block_receipts(reth_primitives::BlockId::Number(BlockNumberOrTag::Number(
            61,
        )))
        .await;
    assert!(!receipts.is_empty());

    let tx = full_node_test_client
        .eth_get_transaction_by_hash(*transactions.get(&65).unwrap(), Some(false))
        .await;
    assert!(tx.is_some());

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

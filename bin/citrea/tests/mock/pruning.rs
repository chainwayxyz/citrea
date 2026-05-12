use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::str::FromStr;

use alloy_primitives::{Address, U256};
use alloy_rpc_types::{BlockId, BlockNumberOrTag};
use citrea_common::PruningConfig;
/// Testing if the sequencer and full node can handle system transactions correctly (the full node should have the same system transactions as the sequencer)
use futures::FutureExt;
use sov_mock_da::{MockAddress, MockDaService};

use super::{initialize_test, TestConfig};
use crate::common::helpers::{
    tempdir_with_children, wait_for_commitment, wait_for_l1_block, wait_for_l2_block,
    wait_for_prover_l1_height,
};

/// Trigger pruning state DB data.
#[tokio::test(flavor = "multi_thread")]
async fn test_state_db_pruning() -> Result<(), anyhow::Error> {
    citrea::initialize_logging(tracing::Level::INFO);
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

    let addr = Address::from_str("0xd39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir,
            sequencer_path: sequencer_db_dir,
            fullnode_path: fullnode_db_dir,
            pruning_config: Some(PruningConfig { distance: 20 }),
            ..Default::default()
        })
        .await;

    for i in 1..=50 {
        // send one ether to some address
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 1e18 as u128)
            .await
            .unwrap();

        seq_test_client.send_publish_batch_request().await;

        if i % 5 == 0 {
            wait_for_l2_block(&seq_test_client, i, None).await;
            da_service.publish_test_block().await.unwrap();
            wait_for_l1_block(&da_service, 3 + (i / 5), None).await;
        }
    }

    wait_for_l2_block(&full_node_test_client, 50, None).await;

    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    // Old blocks balance information should have been pruned
    let get_balance_result = full_node_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(2))))
        .await;
    assert!(get_balance_result.is_err());

    let get_balance_result = full_node_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(20))))
        .await;
    assert!(get_balance_result.is_err());

    // Non pruned block balances should be available
    let balance = full_node_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(21))))
        .await
        .unwrap();
    assert_eq!(balance, U256::from(21000000000000000000u128));

    let balance = full_node_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(50))))
        .await
        .unwrap();
    assert_eq!(balance, U256::from(50000000000000000000u128));

    // Continue block production
    for i in 51..=101 {
        // send one ether to some address
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 1e18 as u128)
            .await
            .unwrap();

        seq_test_client.send_publish_batch_request().await;

        if i % 5 == 0 {
            wait_for_l2_block(&seq_test_client, i, None).await;
            da_service.publish_test_block().await.unwrap();
            wait_for_l1_block(&da_service, 3 + (i / 5), None).await;
        }
    }
    wait_for_l2_block(&full_node_test_client, 101, None).await;

    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    // Old blocks balance information should have been pruned
    let get_balance_result = full_node_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(42))))
        .await;
    assert!(get_balance_result.is_err());

    let get_balance_result = full_node_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(60))))
        .await;
    assert!(get_balance_result.is_err());

    // Non pruned block balances should be available
    let balance = full_node_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(81))))
        .await
        .unwrap();
    assert_eq!(balance, U256::from(81000000000000000000u128));

    let balance = full_node_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(100))))
        .await
        .unwrap();
    assert_eq!(balance, U256::from(100000000000000000000u128));

    seq_task.graceful_shutdown();
    full_node_task.graceful_shutdown();

    Ok(())
}

/// Trigger pruning native DB data.
#[tokio::test(flavor = "multi_thread")]
async fn test_native_db_pruning() -> Result<(), anyhow::Error> {
    citrea::initialize_logging(tracing::Level::INFO);

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

    // Wait for pruning to complete
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

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

    let get_block_receipts_result = AssertUnwindSafe(
        full_node_test_client.eth_get_block_receipts(BlockId::Number(BlockNumberOrTag::Number(1))),
    )
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
    assert!(check_transaction_by_hash_result.is_err());

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

    let get_block_receipts_result = AssertUnwindSafe(
        full_node_test_client.eth_get_block_receipts(BlockId::Number(BlockNumberOrTag::Number(20))),
    )
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
    assert!(check_transaction_by_hash_result.is_err());

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
        .eth_get_block_receipts(BlockId::Number(BlockNumberOrTag::Number(21)))
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

    // Wait for pruning to complete
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

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

    let get_block_receipts_result = AssertUnwindSafe(
        full_node_test_client.eth_get_block_receipts(BlockId::Number(BlockNumberOrTag::Number(40))),
    )
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
    assert!(check_transaction_by_hash_result.is_err());

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

    let get_block_receipts_result = AssertUnwindSafe(
        full_node_test_client.eth_get_block_receipts(BlockId::Number(BlockNumberOrTag::Number(60))),
    )
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
    assert!(check_transaction_by_hash_result.is_err());

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
        .eth_get_block_receipts(BlockId::Number(BlockNumberOrTag::Number(61)))
        .await;
    assert!(!receipts.is_empty());

    let tx = full_node_test_client
        .eth_get_transaction_by_hash(*transactions.get(&65).unwrap(), Some(false))
        .await;
    assert!(tx.is_some());

    seq_task.graceful_shutdown();
    full_node_task.graceful_shutdown();

    Ok(())
}

/// Test that delayed commitment verification works after pruning.
///
/// This ensures that pruning doesn't break commitment verification for blocks
/// that were created before pruning occurred but arrive for verification after.
#[tokio::test(flavor = "multi_thread")]
async fn test_commitment_verification_after_pruning() -> Result<(), anyhow::Error> {
    citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }
    wait_for_l1_block(&da_service, 3, None).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265").unwrap();

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir.clone(),
            sequencer_path: sequencer_db_dir,
            fullnode_path: fullnode_db_dir,
            pruning_config: Some(PruningConfig { distance: 10 }),
            seq_max_l2_blocks: 5,
            ..Default::default()
        })
        .await;

    // Create blocks 1-25 with commitments every 5 blocks
    for i in 1..=25 {
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 1e18 as u128)
            .await
            .unwrap();

        seq_test_client.send_publish_batch_request().await;

        if i % 5 == 0 {
            wait_for_l2_block(&seq_test_client, i, None).await;
            let current_l1_height = 3 + (i / 5);
            wait_for_commitment(&da_service, current_l1_height, None).await;
        }
    }

    wait_for_l2_block(&full_node_test_client, 25, None).await;

    wait_for_prover_l1_height(&full_node_test_client, 8, None)
        .await
        .unwrap();

    let commitments = full_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(4)
        .await
        .unwrap();
    assert!(commitments.is_some());

    // Verify pruning happened (blocks 1-15 should be pruned, keeping only 16-25)
    let block_10_result = AssertUnwindSafe(
        full_node_test_client.eth_get_block_by_number(Some(BlockNumberOrTag::Number(10))),
    )
    .catch_unwind()
    .await;
    assert!(block_10_result.is_err());

    // Create blocks 26-50
    for i in 26..=50 {
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 1e18 as u128)
            .await
            .unwrap();

        seq_test_client.send_publish_batch_request().await;

        if i % 5 == 0 {
            wait_for_l2_block(&seq_test_client, i, None).await;
            let expected_l1_height = 3 + (i / 5);
            wait_for_commitment(&da_service, expected_l1_height, None).await;
        }
    }

    wait_for_l2_block(&full_node_test_client, 50, None).await;

    wait_for_prover_l1_height(&full_node_test_client, 13, None)
        .await
        .unwrap();

    // Verify delayed commitment processing works after pruning.
    let l1_height_15 = 3 + (15 / 5);
    let commitments = full_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(l1_height_15)
        .await
        .unwrap();

    assert!(commitments.is_some());

    let commitment_data = commitments.unwrap();
    assert_eq!(commitment_data.len(), 1);
    assert_eq!(commitment_data[0].l2_end_block_number.to::<u64>(), 15);

    // All commitments should remain after pruning
    for block_num in (5..=50).step_by(5) {
        let l1_height = 3 + (block_num / 5);
        let commitments = full_node_test_client
            .ledger_get_sequencer_commitments_on_slot_by_number(l1_height)
            .await
            .unwrap();

        assert!(commitments.is_some());

        let commitment_data = commitments.unwrap();
        assert_eq!(
            commitment_data[0].l2_end_block_number.to::<u64>(),
            block_num
        );
    }

    // Continue producing blocks to ensure everything still works
    for i in 51..=60 {
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 1e18 as u128)
            .await
            .unwrap();

        seq_test_client.send_publish_batch_request().await;

        if i % 5 == 0 {
            wait_for_l2_block(&seq_test_client, i, None).await;
            let expected_l1_height = 3 + (i / 5);
            wait_for_commitment(&da_service, expected_l1_height, None).await;
        }
    }

    wait_for_l2_block(&full_node_test_client, 60, None).await;

    let l1_height_60 = 3 + (60 / 5);
    wait_for_prover_l1_height(&full_node_test_client, l1_height_60, None)
        .await
        .unwrap();

    let final_commitments = full_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(l1_height_60)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(final_commitments[0].l2_end_block_number.to::<u64>(), 60);

    // Verify full node stays synced with sequencer
    let seq_height = seq_test_client.eth_block_number().await;
    let full_node_height = full_node_test_client.eth_block_number().await;
    assert_eq!(seq_height, full_node_height);

    seq_task.graceful_shutdown();
    full_node_task.graceful_shutdown();

    Ok(())
}

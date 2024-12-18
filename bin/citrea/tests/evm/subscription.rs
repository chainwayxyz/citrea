use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::FixedBytes;
// use citrea::initialize_logging;
use alloy_primitives::{keccak256, Address};
use alloy_sol_types::SolEvent;
use citrea_common::SequencerConfig;
use citrea_evm::smart_contracts::{AnotherLogEvent, LogEvent, LogsContract, TestContract};
use citrea_evm::{Filter, LogResponse};
use citrea_stf::genesis_config::GenesisPaths;
use tokio::time::sleep;

use crate::evm::make_test_client;
use crate::test_client::TestClient;
use crate::test_helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::{
    TEST_DATA_GENESIS_PATH, TEST_SEND_NO_COMMITMENT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_subscriptions() -> Result<(), Box<dyn std::error::Error>> {
    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let sequencer_config = SequencerConfig {
        min_soft_confirmations_per_commitment:
            TEST_SEND_NO_COMMITMENT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
        ..Default::default()
    };
    let seq_task = tokio::spawn(async {
        // Don't provide a prover since the EVM is not currently provable
        start_rollup(
            port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
        )
        .await;
    });

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();

    let test_client = make_test_client(port).await?;

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, None).await;

    // Spawn newHeads subscriber
    let new_block_rx = test_client.subscribe_new_heads().await;
    let last_received_block = Arc::new(Mutex::new(None));
    let last_received_block_clone = last_received_block.clone();
    tokio::spawn(async move {
        loop {
            let Ok(block) = new_block_rx.recv() else {
                return;
            };
            *(last_received_block_clone.lock().unwrap()) = Some(block);
        }
    });

    // Produce an empty block and receive it from subscription
    {
        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&test_client, 2, None).await;
        // Sleep in case of subscription delay
        sleep(Duration::from_millis(100)).await;

        let block = last_received_block.lock().unwrap();
        let block = block.as_ref().unwrap();
        assert_eq!(block.header.number, 2);
        assert!(block.transactions.is_empty());
    }

    // Produce a block with 1 send transaction and receive it from subscription
    {
        let pending_tx = test_client
            .send_eth(Address::random(), None, None, None, 10000)
            .await
            .unwrap();
        let tx_hash = *pending_tx.tx_hash();

        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&test_client, 3, None).await;
        // Sleep in case of subscription delay
        sleep(Duration::from_millis(100)).await;

        let block = last_received_block.lock().unwrap();
        let block = block.as_ref().unwrap();
        assert_eq!(block.header.number, 3);
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions.hashes().last().unwrap().clone(), tx_hash);
    }

    // Deploy 2 LogsContract
    let (logs_contract1, logs_contract_address1, logs_contract2, logs_contract_address2) = {
        let logs_contract1 = LogsContract::default();
        let deploy_logs_contract_req1 = test_client
            .deploy_contract(logs_contract1.byte_code(), None)
            .await?;
        let logs_contract2 = LogsContract::default();
        let deploy_logs_contract_req2 = test_client
            .deploy_contract(logs_contract2.byte_code(), None)
            .await?;

        test_client.send_publish_batch_request().await;

        let logs_contract_address1 = deploy_logs_contract_req1
            .get_receipt()
            .await?
            .contract_address
            .unwrap();
        let logs_contract_address2 = deploy_logs_contract_req2
            .get_receipt()
            .await?
            .contract_address
            .unwrap();

        (
            logs_contract1,
            logs_contract_address1,
            logs_contract2,
            logs_contract_address2,
        )
    };

    // Spawn logs subscriber with no filter
    let logs_by_tx_no_filter = spawn_logs_subscriber(&test_client, Filter::default()).await;
    // Spawn logs subscriber with logs_contract_address1 filter
    let mut filter = Filter::default();
    filter.address.0.insert(logs_contract_address1);
    let logs_by_tx_address1_filter = spawn_logs_subscriber(&test_client, filter).await;
    // Spawn logs subscriber with logs_contract_address2 filter and a topic
    let mut filter = Filter::default();
    filter.address.0.insert(logs_contract_address2);
    filter.topics[0].0.insert(AnotherLogEvent::SIGNATURE_HASH);
    let logs_by_tx_address2_filter = spawn_logs_subscriber(&test_client, filter).await;

    // Call logs_contract1 and logs_contract2 contracts once and observe that
    // each log subscription receives the respective events
    {
        // Send transaction to 1st contract
        let test_log_msg: String = "DRAGONBALLZ".into();
        let pending_tx1 = test_client
            .contract_transaction(
                logs_contract_address1,
                logs_contract1.publish_event(test_log_msg.clone()),
                None,
            )
            .await;
        let tx_hash1 = *pending_tx1.tx_hash();
        // Send transaction to 2nd contract
        let pending_tx2 = test_client
            .contract_transaction(
                logs_contract_address2,
                logs_contract2.publish_event(test_log_msg.clone()),
                None,
            )
            .await;
        let tx_hash2 = *pending_tx2.tx_hash();

        // Wait for them to be mined
        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&test_client, 5, None).await;
        // Sleep in case of subscription delay
        sleep(Duration::from_millis(100)).await;

        // Observe that we received a block and it contains 2 transactions
        let block = last_received_block.lock().unwrap();
        let block = block.as_ref().unwrap();
        let mut tx_hashes = block.transactions.hashes();
        assert_eq!(block.header.number, 5);
        assert_eq!(block.transactions.len(), 2);
        assert_eq!(tx_hashes.next().unwrap().clone(), tx_hash1);
        assert_eq!(tx_hashes.next().unwrap().clone(), tx_hash2);

        {
            // Observe that no filter logs subscription received all 4 events
            let logs_by_tx_no_filter = logs_by_tx_no_filter.lock().unwrap();
            let (log_payload1, another_log_payload1) =
                parse_log_contract_logs(logs_by_tx_no_filter.get(&tx_hash1).unwrap());
            let (log_payload2, another_log_payload2) =
                parse_log_contract_logs(logs_by_tx_no_filter.get(&tx_hash2).unwrap());

            // Verify tx1 events payload
            assert_eq!(log_payload1.address, logs_contract_address1);
            assert_eq!(log_payload1.sender, test_client.from_addr);
            assert_eq!(log_payload1.contractAddress, logs_contract_address1);
            assert_eq!(log_payload1.senderMessage, keccak256(test_log_msg.clone()));
            assert_eq!(log_payload1.message, "Hello World!");
            assert_eq!(another_log_payload1.contractAddress, logs_contract_address1);

            // Verify tx2 events payload
            assert_eq!(log_payload2.address, logs_contract_address2);
            assert_eq!(log_payload2.sender, test_client.from_addr);
            assert_eq!(log_payload2.contractAddress, logs_contract_address2);
            assert_eq!(log_payload2.senderMessage, keccak256(test_log_msg.clone()));
            assert_eq!(log_payload2.message, "Hello World!");
            assert_eq!(another_log_payload2.contractAddress, logs_contract_address2);
        }

        {
            // Observe that address1 filtered subscription received only 2 events from contract1
            let logs_by_tx_address1_filter = logs_by_tx_address1_filter.lock().unwrap();
            assert!(logs_by_tx_address1_filter.get(&tx_hash2).is_none());

            let (log_payload1, another_log_payload1) =
                parse_log_contract_logs(logs_by_tx_address1_filter.get(&tx_hash1).unwrap());

            // Verify tx1 events payload
            assert_eq!(log_payload1.address, logs_contract_address1);
            assert_eq!(log_payload1.sender, test_client.from_addr);
            assert_eq!(log_payload1.contractAddress, logs_contract_address1);
            assert_eq!(log_payload1.senderMessage, keccak256(test_log_msg.clone()));
            assert_eq!(log_payload1.message, "Hello World!");
            assert_eq!(another_log_payload1.contractAddress, logs_contract_address1);
        }

        {
            // Observe that address1 and topic filtered subscription received only 1 event from contract1
            let logs_by_tx_address2_filter = logs_by_tx_address2_filter.lock().unwrap();
            assert!(logs_by_tx_address2_filter.get(&tx_hash1).is_none());

            let logs = logs_by_tx_address2_filter.get(&tx_hash2).unwrap();
            assert_eq!(logs.len(), 1);

            let log: alloy_primitives::Log = logs[0].clone().try_into().unwrap();
            let another_log_payload = LogsContract::decode_another_log_event(&log).unwrap();

            // Verify tx1 events payload
            assert_eq!(another_log_payload.contractAddress, logs_contract_address2);
        }
    }

    seq_task.abort();
    Ok(())
}

async fn spawn_logs_subscriber(
    client: &TestClient,
    filter: Filter,
) -> Arc<Mutex<HashMap<FixedBytes<32>, Vec<LogResponse>>>> {
    let logs_rx = client.subscribe_logs(filter).await;
    let logs_by_tx = Arc::new(Mutex::new(HashMap::new()));
    let logs_by_tx_c = logs_by_tx.clone();
    tokio::spawn(async move {
        loop {
            let Ok(log) = logs_rx.recv() else {
                return;
            };
            let mut logs_by_tx_c = logs_by_tx_c.lock().unwrap();
            let logs = logs_by_tx_c
                .entry(log.transaction_hash.unwrap())
                .or_insert(vec![]);
            logs.push(log);
        }
    });

    logs_by_tx
}

fn parse_log_contract_logs(
    logs: &[LogResponse],
) -> (
    alloy_primitives::Log<LogEvent>,
    alloy_primitives::Log<AnotherLogEvent>,
) {
    assert_eq!(logs.len(), 2);

    let log1: alloy_primitives::Log = logs[0].clone().try_into().unwrap();
    let log2: alloy_primitives::Log = logs[1].clone().try_into().unwrap();

    let log_payload = LogsContract::decode_log_event(&log1).unwrap();
    let another_log_payload = LogsContract::decode_another_log_event(&log2).unwrap();

    (log_payload, another_log_payload)
}

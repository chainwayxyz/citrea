use std::sync::{Arc, Mutex};

// use citrea::initialize_logging;
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::Address;

use crate::evm::make_test_client;
use crate::test_helpers::{start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
    TEST_DATA_GENESIS_PATH,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_subscriptions() -> Result<(), Box<dyn std::error::Error>> {
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();
    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        // Don't provide a prover since the EVM is not currently provable
        start_rollup(
            port_tx,
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

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();

    let test_client = make_test_client(port).await;

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, None).await;

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

    {
        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&test_client, 2, None).await;

        let block = last_received_block.lock().unwrap();
        let block = block.as_ref().unwrap();
        assert_eq!(block.header.number, Some(2));
        assert!(block.transactions.is_empty());
    }

    {
        let pending_tx = test_client
            .send_eth(Address::random(), None, None, None, 10000)
            .await
            .unwrap();
        let tx_hash = *pending_tx.tx_hash();

        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&test_client, 3, None).await;

        let block = last_received_block.lock().unwrap();
        let block = block.as_ref().unwrap();
        assert_eq!(block.header.number, Some(3));
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions.hashes().last().unwrap().clone(), tx_hash);
    }

    seq_task.abort();
    Ok(())
}

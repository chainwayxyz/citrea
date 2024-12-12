/// Testing specific features of the sequencer
use std::str::FromStr;
use std::time::Duration;

use alloy::consensus::{Signed, TxEip1559, TxEnvelope};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy_rlp::{BytesMut, Encodable};
use citrea_common::{SequencerConfig, SequencerMempoolConfig};
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::{Address, BlockNumberOrTag};
use sov_mock_da::{MockAddress, MockDaService, MockDaSpec};
use tokio::time::sleep;

use crate::e2e::{initialize_test, TestConfig};
use crate::evm::{init_test_rollup, make_test_client};
use crate::test_client::TestClient;
use crate::test_helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_commitment,
    wait_for_l1_block, wait_for_l2_block, NodeMode,
};
use crate::TEST_DATA_GENESIS_PATH;

/// Run the sequencer.
/// Create some blocks.
/// Create more than one da blocks consecutively.
/// Check if the sequencer fills the missing DA blocks (don't skip any DA block. create an empty L2 block if needed)
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_fill_missing_da_blocks() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let sequencer_config = SequencerConfig {
        min_soft_confirmations_per_commitment: 1000,
        da_update_interval_ms: 500,
        block_production_interval_ms: 500,
        ..Default::default()
    };
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
    let seq_test_client = init_test_rollup(seq_port).await;

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 1, None).await;

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let to_be_filled_da_block_count = 5;
    let latest_da_block = 1 + to_be_filled_da_block_count;
    // publish da blocks back to back
    for _ in 0..to_be_filled_da_block_count {
        da_service.publish_test_block().await.unwrap();
    }
    wait_for_l1_block(&da_service, latest_da_block, None).await;
    sleep(Duration::from_secs(1)).await;

    // publish a block which will start filling of all missing da blocks
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 2, None).await;

    let first_filler_l2_block = 2;
    let last_filler_l2_block = first_filler_l2_block + to_be_filled_da_block_count - 1;
    // wait for all corresponding da blocks to be filled by sequencer
    wait_for_l2_block(&seq_test_client, last_filler_l2_block, None).await;

    let mut next_da_block = 2;
    // ensure that all the filled l2 blocks correspond to correct da blocks
    for filler_l2_block in first_filler_l2_block..=last_filler_l2_block {
        let soft_confirmation = seq_test_client
            .ledger_get_soft_confirmation_by_number::<MockDaSpec>(filler_l2_block)
            .await
            .unwrap();
        assert_eq!(soft_confirmation.da_slot_height, next_da_block);
        next_da_block += 1;
    }

    // publish an extra l2 block
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, last_filler_l2_block + 1, None).await;

    // Wait for storage
    sleep(Duration::from_secs(1)).await;

    // ensure that the latest l2 block points to latest da block and has correct height
    let head_soft_confirmation = seq_test_client
        .ledger_get_head_soft_confirmation()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head_soft_confirmation.da_slot_height, latest_da_block);
    let head_soft_confirmation_num = seq_test_client
        .ledger_get_head_soft_confirmation_height()
        .await
        .unwrap();
    assert_eq!(head_soft_confirmation_num, last_filler_l2_block + 1);

    seq_task.abort();
    Ok(())
}

/// Run the sequencer.
/// Send spam transactions.
/// Check if the sequencer triggers a commitment after a certain state diff size since it's last commitment.
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_commitment_threshold() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    // Put a large number for commitment threshold
    let min_soft_confirmations_per_commitment = 1_000_000;

    let sequencer_config = SequencerConfig {
        min_soft_confirmations_per_commitment,
        mempool_conf: SequencerMempoolConfig {
            max_account_slots: 4000,
            ..Default::default()
        },
        ..Default::default()
    };

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
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

    let seq_test_client = init_test_rollup(seq_port).await;

    seq_test_client.send_publish_batch_request().await;

    for i in 1..35 {
        for _ in 0..60 {
            let address = Address::random();
            let _pending = seq_test_client
                .send_eth(address, None, None, None, 1u128)
                .await
                .unwrap();
        }
        // give time for mempool to be filled
        tokio::time::sleep(Duration::from_millis(500)).await;
        seq_test_client.send_publish_batch_request().await;
        wait_for_l2_block(&seq_test_client, i, None).await;
    }

    wait_for_l2_block(&seq_test_client, 35, Some(Duration::from_secs(60))).await;

    // After block 35, the state diff should be large enough to trigger a commitment.
    let commitments = wait_for_commitment(&da_service, 2, Some(Duration::from_secs(60))).await;
    assert_eq!(commitments.len(), 1);

    for i in 35..70 {
        for _ in 0..60 {
            let address = Address::random();
            let _pending = seq_test_client
                .send_eth(address, None, None, None, 1u128)
                .await
                .unwrap();
        }
        // give time for mempool to be filled
        tokio::time::sleep(Duration::from_millis(500)).await;
        seq_test_client.send_publish_batch_request().await;
        wait_for_l2_block(&seq_test_client, i, None).await;
    }

    wait_for_l2_block(&seq_test_client, 70, Some(Duration::from_secs(60))).await;

    // After block 70, the state diff should be large enough to trigger a commitment.
    // But the remaining blocks state diff should NOT trigger a third.
    let commitments = wait_for_commitment(&da_service, 3, Some(Duration::from_secs(60))).await;
    assert_eq!(commitments.len(), 1);

    seq_task.abort();
}

/// Run the sequencer.
/// Send a traensaction that can cover base fee and prioiity fee but not the L1 fee.
/// Check if the transaction is removed from the mempool and not included in the block.
#[tokio::test(flavor = "multi_thread")]
async fn transaction_failing_on_l1_is_removed_from_mempool() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir.clone(),
            sequencer_path: sequencer_db_dir.clone(),
            fullnode_path: fullnode_db_dir.clone(),
            ..Default::default()
        })
        .await;

    let random_wallet = PrivateKeySigner::random().with_chain_id(Some(seq_test_client.chain_id));

    let random_wallet_address = random_wallet.address();

    let second_block_base_fee = 767969424;

    let _pending = seq_test_client
        .send_eth(
            random_wallet_address,
            None,
            None,
            None,
            // gas needed for transaction + 500 (to send) but this won't be enough for L1 fees
            21000 * second_block_base_fee + 500,
        )
        .await
        .unwrap();

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 1, None).await;

    let random_test_client = TestClient::new(
        seq_test_client.chain_id,
        random_wallet,
        random_wallet_address,
        seq_test_client.rpc_addr,
    )
    .await?;

    let tx = random_test_client
        .send_eth_with_gas(
            Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            Some(0),
            Some(second_block_base_fee),
            21000,
            500,
        )
        .await
        .unwrap();

    let tx_from_mempool = seq_test_client
        .eth_get_transaction_by_hash(*tx.tx_hash(), Some(true))
        .await;

    assert!(tx_from_mempool.is_some());

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 2, None).await;

    let block = seq_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(
        block.header.base_fee_per_gas.unwrap(),
        second_block_base_fee
    );

    let tx_from_mempool = seq_test_client
        .eth_get_transaction_by_hash(*tx.tx_hash(), Some(true))
        .await;

    let soft_confirmation = seq_test_client
        .ledger_get_soft_confirmation_by_number::<MockDaSpec>(block.header.number.unwrap())
        .await
        .unwrap();

    assert_eq!(block.transactions.len(), 0);
    assert!(tx_from_mempool.is_none());
    assert_eq!(soft_confirmation.txs.unwrap().len(), 0);

    wait_for_l2_block(&full_node_test_client, block.header.number.unwrap(), None).await;

    let block_from_full_node = full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(block_from_full_node, block);

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

/// Transactions with a high gas limit should be accounted for by using
/// their actual cumulative gas consumption to prevent them from reserving
/// whole blocks on their own.
#[tokio::test(flavor = "multi_thread")]
async fn test_gas_limit_too_high() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let db_dir: tempfile::TempDir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let full_node_db_dir = db_dir.path().join("full-node").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let target_gas_limit: u64 = 30_000_000;
    let transfer_gas_limit = 21_000;
    let system_txs_gas_used = 300621;
    let tx_count = (target_gas_limit - system_txs_gas_used).div_ceil(transfer_gas_limit);
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);

    // Increase max account slots to not stuck as spammer
    let sequencer_config = SequencerConfig {
        min_soft_confirmations_per_commitment: 1000,
        deposit_mempool_fetch_limit: 100,
        mempool_conf: SequencerMempoolConfig {
            max_account_slots: tx_count * 2,
            ..Default::default()
        },
        da_update_interval_ms: 1000,
        block_production_interval_ms: 1000,
        ..Default::default()
    };
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
    let seq_test_client = make_test_client(seq_port).await.unwrap();

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &full_node_db_dir,
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

    let mut tx_hashes = vec![];
    // Loop until tx_count.
    // This means that we are going to have 5 transactions which have not been included.
    for _ in 0..tx_count + 4 {
        let tx_hash = seq_test_client
            .send_eth_with_gas(addr, None, None, 10_000_000, 0u128)
            .await
            .unwrap();
        tx_hashes.push(tx_hash);
    }

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 1, Some(Duration::from_secs(60))).await;

    let block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let block_transactions = block.transactions.as_hashes().unwrap();
    // assert the block contains all txs apart from the last 5
    for tx_hash in tx_hashes[0..tx_hashes.len() - 5].iter() {
        assert!(block_transactions.contains(tx_hash.tx_hash()));
    }
    for tx_hash in tx_hashes[tx_hashes.len() - 5..].iter() {
        assert!(!block_transactions.contains(tx_hash.tx_hash()));
    }

    let block_from_sequencer = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(
        block_from_sequencer.header.state_root,
        block.header.state_root
    );
    assert_eq!(block_from_sequencer.header.hash, block.header.hash);

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 2, None).await;

    let block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let block_from_sequencer = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(!block.transactions.is_empty());
    assert_eq!(
        block_from_sequencer.header.state_root,
        block.header.state_root
    );
    assert_eq!(block_from_sequencer.header.hash, block.header.hash);

    seq_task.abort();
    full_node_task.abort();
}

/// Run the sequencer.
/// Fill the mempool with transactions.
/// Create a block with a system transaction.
/// Check if the sequencer selects the correct amount of transactions to fill the
/// gas limit left from the system transaction(s).
#[tokio::test(flavor = "multi_thread")]
async fn test_system_tx_effect_on_block_gas_limit() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let sequencer_config = SequencerConfig {
        min_soft_confirmations_per_commitment: 1000,
        mempool_conf: SequencerMempoolConfig {
            max_account_slots: 100,
            ..Default::default()
        },
        da_update_interval_ms: 1000,
        block_production_interval_ms: 500,
        ..Default::default()
    };
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(
                "../../resources/test-data/integration-tests-low-block-gas-limit",
            ),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await?;
    // sys tx use L1BlockHash(50751 + 80720) + Bridge(169150) = 300621 gas
    // the block gas limit is 1_500_000 because the system txs gas limit is 1_500_000 (decided with @eyusufatik and @okkothejawa as bridge init takes 1M gas)

    // 1500000 - 300621 = 1177464 gas left in block
    // 1107314 / 21000 = 57.13... so 57 ether transfer transactions can be included in the block

    // send 57 ether transfer transactions
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    for _ in 0..56 {
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
    }

    // 57th tx should be the last tx in the soft confirmation
    let last_in_tx = seq_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await;

    // 58th tx should not be in soft confirmation
    let not_in_tx = seq_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await;

    seq_test_client.send_publish_batch_request().await;

    da_service.publish_test_block().await.unwrap();

    let last_in_receipt = last_in_tx.unwrap().get_receipt().await.unwrap();

    wait_for_l2_block(&seq_test_client, 1, None).await;
    // Wait for storage
    sleep(Duration::from_secs(1)).await;

    let initial_soft_confirmation = seq_test_client
        .ledger_get_soft_confirmation_by_number::<MockDaSpec>(1)
        .await
        .unwrap();

    let last_tx_hash = last_in_receipt.transaction_hash;
    let last_tx = seq_test_client
        .eth_get_transaction_by_hash(last_tx_hash, Some(false))
        .await
        .unwrap();
    let signed_tx = Signed::<TxEip1559>::try_from(last_tx).unwrap();
    let envelope = TxEnvelope::Eip1559(signed_tx);
    let mut last_tx_raw = BytesMut::new();
    envelope.encode(&mut last_tx_raw);

    assert!(last_in_receipt.block_number.is_some());

    // last in tx byte array should be a subarray of txs[0]
    assert!(find_subarray(
        initial_soft_confirmation.clone().txs.unwrap()[0]
            .tx
            .as_slice(),
        &last_tx_raw[2..]
    )
    .is_some());

    seq_test_client.send_publish_batch_request().await;

    da_service.publish_test_block().await.unwrap();

    let not_in_receipt = not_in_tx.unwrap().get_receipt().await.unwrap();

    let not_in_hash = not_in_receipt.transaction_hash;

    let not_in_tx = seq_test_client
        .eth_get_transaction_by_hash(not_in_hash, Some(false))
        .await
        .unwrap();
    let signed_tx = Signed::<TxEip1559>::try_from(not_in_tx).unwrap();
    let envelope = TxEnvelope::Eip1559(signed_tx);
    let mut not_in_raw = BytesMut::new();
    envelope.encode(&mut not_in_raw);

    // not in tx byte array should not be a subarray of txs[0]
    assert!(find_subarray(
        initial_soft_confirmation.txs.unwrap()[0].tx.as_slice(),
        &not_in_raw[2..]
    )
    .is_none());

    seq_test_client.send_publish_batch_request().await;

    let second_soft_confirmation = seq_test_client
        .ledger_get_soft_confirmation_by_number::<MockDaSpec>(2)
        .await
        .unwrap();

    // should be in tx byte array of the soft confirmation after
    assert!(find_subarray(
        second_soft_confirmation.txs.unwrap()[0].tx.as_slice(),
        &not_in_raw[2..]
    )
    .is_some());

    let block1 = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(1)))
        .await;

    // the last in tx should be in the block
    let block1_transactions = block1.transactions.as_hashes().unwrap();
    assert!(block1_transactions.iter().any(|tx| tx == &last_tx_hash));
    // and the other tx should not be in
    assert!(!block1_transactions.iter().any(|tx| tx == &not_in_hash));

    let block2 = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(2)))
        .await;
    // the other tx should be in second block
    let block2_transactions = block2.transactions.as_hashes().unwrap();
    assert!(block2_transactions.iter().any(|tx| tx == &not_in_hash));

    seq_task.abort();

    Ok(())
}

fn find_subarray(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

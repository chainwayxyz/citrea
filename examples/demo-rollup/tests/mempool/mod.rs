use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use demo_stf::genesis_config::GenesisPaths;
use ethers::abi::Address;
use ethers_core::k256::elliptic_curve::point::NonIdentity;
use ethers_signers::{LocalWallet, Signer};
use reth_primitives::BlockNumberOrTag;
// use sov_demo_rollup::initialize_logging;
use sov_evm::{CoinbaseContract, SimpleStorageContract, TestContract};
use sov_modules_stf_blueprint::kernels::basic::BasicKernelGenesisPaths;
use sov_stf_runner::RollupProverConfig;
use tokio::time::sleep;

use crate::evm::{init_test_rollup, make_test_client};

use crate::test_client::TestClient;
use crate::test_helpers::{start_rollup, NodeMode};

/// Transaction with equal nonce to last tx should not be accepted by mempool.
#[tokio::test]
#[should_panic]
async fn test_nonce_tx_should_panic() -> () {
    // initialize_logging();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_contract = SimpleStorageContract::default();
    let seq_test_client = make_test_client(seq_port, seq_contract).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // send tx with nonce 0
    let tx_hash = seq_test_client
        .send_eth(addr, None, None, Some(0), None)
        .await;
    // send tx with nonce 1
    let tx_hash = seq_test_client
        .send_eth(addr, None, None, Some(1), None)
        .await;
    // send tx with nonce 1 again and expect it to be rejected
    seq_test_client
        .send_eth(addr, None, None, Some(1), None)
        .await;
}

///  Transaction with nonce lower then account's nonce on state should not be accepted by mempool.
#[tokio::test]
#[should_panic]
async fn test_nonce_too_low() -> () {
    // initialize_logging();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_contract = SimpleStorageContract::default();
    let seq_test_client = make_test_client(seq_port, seq_contract).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // send tx with nonce 0
    seq_test_client
        .send_eth(addr, None, None, Some(0), None)
        .await;
    // send tx with nonce 1
    seq_test_client
        .send_eth(addr, None, None, Some(1), None)
        .await;
    // send tx with nonce 0 expect it to be rejected
    seq_test_client
        .send_eth(addr, None, None, Some(0), None)
        .await;
}

/// Transaction with nonce higher then account's nonce should be accepted by the mempool
/// but shouldn't be received by the sequencer (so it doesn't end up in the block)
#[tokio::test]
async fn test_nonce_too_high() -> () {
    // initialize_logging();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_contract = SimpleStorageContract::default();
    let seq_test_client = make_test_client(seq_port, seq_contract).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // send tx with nonce 0
    let tx_hash = seq_test_client
        .send_eth(addr, None, None, Some(0), None)
        .await;
    // send tx with nonce 1
    let tx_hash1 = seq_test_client
        .send_eth(addr, None, None, Some(1), None)
        .await;
    // send tx with nonce 0 expect it to be rejected
    let tx_hash2 = seq_test_client
        .send_eth(addr, None, None, Some(3), None)
        .await;

    sleep(Duration::from_millis(100)).await;

    seq_test_client.send_publish_batch_request().await;

    sleep(Duration::from_millis(100)).await;

    let sq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    // assert the block does not contain the tx with nonce too high
    assert!(!sq_block.transactions.contains(&tx_hash2.tx_hash()));
}

#[tokio::test]
async fn test_order_by_fee() {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_contract = SimpleStorageContract::default();
    let seq_test_client = make_test_client(seq_port.clone(), seq_contract).await;

    let chain_id: u64 = 5655;
    let key = "0xdcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(chain_id);
    let poor_addr = key.address();

    let poor_seq_test_client = TestClient::new(
        chain_id,
        key,
        poor_addr,
        SimpleStorageContract::default(),
        seq_port,
    )
    .await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let sent_tx_hash1 = seq_test_client
        .send_eth(
            poor_addr,
            None,
            None,
            None,
            Some(5_000_000_000_000_000_000u128),
        )
        .await;
    sleep(Duration::from_millis(100)).await;
    seq_test_client.send_publish_batch_request().await;
    sleep(Duration::from_millis(100)).await;

    let sq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(sq_block.transactions.contains(&sent_tx_hash1.tx_hash()));

    // now make some txs  from different accounts with different fees and see which tx lands ffirst in block
    let tx_hash_poor = poor_seq_test_client
        .send_eth(
            seq_test_client.from_addr,
            Some(100u64),
            Some(100000000001u64),
            None,
            Some(2_000_000_000_000_000_000u128),
        )
        .await;

    let tx_hash_rich = seq_test_client
        .send_eth(
            poor_seq_test_client.from_addr,
            Some(1000u64),
            Some(1000000000001u64),
            Some(1),
            Some(2_000_000_000_000_000_000u128),
        )
        .await;

    sleep(Duration::from_millis(100)).await;
    seq_test_client.send_publish_batch_request().await;
    sleep(Duration::from_millis(100)).await;

    // the rich tx should be in the block before the poor tx
    let sq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(sq_block.transactions.contains(&tx_hash_rich.tx_hash()));
    assert!(sq_block.transactions.contains(&tx_hash_poor.tx_hash()));
    assert!(
        sq_block
            .transactions
            .iter()
            .position(|x| x == &tx_hash_rich.tx_hash())
            < sq_block
                .transactions
                .iter()
                .position(|x| x == &tx_hash_poor.tx_hash())
    );

    // now change the order the txs are sent, the assertions should be the same
    let tx_hash_rich = seq_test_client
        .send_eth(
            poor_seq_test_client.from_addr,
            Some(1000u64),
            Some(1000000000001u64),
            Some(2),
            Some(2_000_000_000_000_000_000u128),
        )
        .await;

    // now make some txs  from different accounts with different fees and see which tx lands ffirst in block
    let tx_hash_poor = poor_seq_test_client
        .send_eth(
            seq_test_client.from_addr,
            Some(100u64),
            Some(100000000001u64),
            Some(1),
            Some(2_000_000_000_000_000_000u128),
        )
        .await;

    sleep(Duration::from_millis(100)).await;
    seq_test_client.send_publish_batch_request().await;
    sleep(Duration::from_millis(100)).await;

    // the rich tx should be in the block before the poor tx
    let sq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(sq_block.transactions.contains(&tx_hash_rich.tx_hash()));
    assert!(sq_block.transactions.contains(&tx_hash_poor.tx_hash()));
    assert!(
        sq_block
            .transactions
            .iter()
            .position(|x| x == &tx_hash_rich.tx_hash())
            < sq_block
                .transactions
                .iter()
                .position(|x| x == &tx_hash_poor.tx_hash())
    );
}

/// Send a transaction that pays less base fee then required.
/// Publish block, tx should not be in block but should still be in the mempool.
#[tokio::test]
async fn test_tx_with_low_base_fee() {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_contract = SimpleStorageContract::default();
    let seq_test_client = make_test_client(seq_port.clone(), seq_contract).await;

    let chain_id: u64 = 5655;
    let key = "0xdcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(chain_id);
    let poor_addr = key.address();

    let poor_seq_test_client = TestClient::new(
        chain_id,
        key,
        poor_addr,
        SimpleStorageContract::default(),
        seq_port,
    )
    .await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let sent_tx_hash1 = seq_test_client
        .send_eth(
            poor_addr,
            None,
            None,
            None,
            Some(5_000_000_000_000_000_000u128),
        )
        .await;
    sleep(Duration::from_millis(100)).await;
    seq_test_client.send_publish_batch_request().await;
    sleep(Duration::from_millis(100)).await;

    let tx_hash_low_fee = seq_test_client
        .send_eth(
            poor_addr,
            Some(1u64),
            // normally base fee is 875 000 000
            Some(1_000_001u64),
            None,
            Some(5_000_000_000_000_000_000u128),
        )
        .await;

    sleep(Duration::from_millis(100)).await;
    seq_test_client.send_publish_batch_request().await;
    sleep(Duration::from_millis(100)).await;

    let sq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(!sq_block.transactions.contains(&tx_hash_low_fee.tx_hash()));
}

#[tokio::test]
async fn test_bribe_vs_priority_fee() -> Result<(), Box<dyn std::error::Error>> {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let coinbase_contract = CoinbaseContract::default();
    let seq_test_client = make_test_client(seq_port.clone(), coinbase_contract).await;

    let chain_id: u64 = 5655;
    let key = "0xdcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(chain_id);
    let poor_addr = key.address();

    let poor_seq_test_client = TestClient::new(
        chain_id,
        key,
        poor_addr,
        SimpleStorageContract::default(),
        seq_port,
    )
    .await;

    let deploy_contract_req = seq_test_client.deploy_contract().await?;

    sleep(Duration::from_millis(100)).await;

    // publish block
    seq_test_client.send_publish_batch_request().await;

    sleep(Duration::from_millis(100)).await;

    let contract_address = deploy_contract_req
        .await?
        .unwrap()
        .contract_address
        .unwrap();

    // firstly lets send some money to poor fellow
    let _ = seq_test_client
        .send_eth(
            poor_addr,
            None,
            None,
            None,
            Some(5_000_000_000_000_000_000u128),
        )
        .await;

    sleep(Duration::from_millis(100)).await;

    // publish block
    seq_test_client.send_publish_batch_request().await;

    sleep(Duration::from_millis(100)).await;

    // now lets send a tx with nice amount of priority fee and base fee
    let tx_hash_high_priority = poor_seq_test_client
        .send_eth(
            seq_test_client.from_addr,
            Some(10u64), // good amount of priority fee
            None,
            None,
            Some(2_000_000_000_000_000_000u128),
        )
        .await;

    // sends a tx with a bribe
    let tx_hash_0_priority_high_bribe = seq_test_client
        .reward_miner(
            contract_address,
            Some(0u64),
            None,
            None,
            10_000_000_000_000_000_000u64,
        )
        .await;

    sleep(Duration::from_millis(100)).await;

    // publish block
    seq_test_client.send_publish_batch_request().await;

    sleep(Duration::from_millis(100)).await;

    // the tx with high priority fee should be in the block
    let sq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(sq_block
        .transactions
        .contains(&tx_hash_high_priority.tx_hash()));
    assert!(sq_block
        .transactions
        .contains(&tx_hash_0_priority_high_bribe.tx_hash()));

    assert!(
        sq_block
            .transactions
            .iter()
            .position(|x| x == &tx_hash_0_priority_high_bribe.tx_hash())
            < sq_block
                .transactions
                .iter()
                .position(|x| x == &tx_hash_high_priority.tx_hash())
    );

    Ok(())
}

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use demo_stf::genesis_config::GenesisPaths;
use ethers::abi::Address;
use reth_primitives::BlockNumberOrTag;
use sov_evm::{SimpleStorageContract, TestContract};
use sov_stf_runner::RollupProverConfig;
use tokio::time::sleep;

use crate::evm::{init_test_rollup, make_test_client, TestClient};
use crate::test_helpers::{start_rollup, NodeMode};

#[tokio::test]
async fn test_full_node_send_tx() -> Result<(), anyhow::Error> {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let _seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_contract = SimpleStorageContract::default();
    let seq_test_client = make_test_client(seq_port, seq_contract).await;

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let _full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_contract = SimpleStorageContract::default();
    let full_node_test_client = make_test_client(full_node_port, full_node_contract).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let tx_hash = full_node_test_client
        .send_eth_to_self(addr, None, None)
        .await;

    sleep(Duration::from_millis(2000)).await;

    seq_test_client.send_publish_batch_request().await;

    sleep(Duration::from_millis(20000)).await;

    let sq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(sq_block.transactions.contains(&tx_hash.tx_hash()));
    assert!(full_node_block.transactions.contains(&tx_hash.tx_hash()));
    assert_eq!(sq_block.state_root, full_node_block.state_root);

    Ok(())
}

#[tokio::test]
async fn test_e2e_same_block_sync() -> Result<(), anyhow::Error> {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();

    setup_execute_four_blocks(seq_port, full_node_port)
        .await
        .unwrap();

    seq_task.abort();
    rollup_task.abort();

    Ok(())
}

#[tokio::test]
async fn test_delayed_sync_ten_blocks() -> Result<(), anyhow::Error> {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();

    let contract = SimpleStorageContract::default();
    let seq_test_client = init_test_rollup(seq_port, contract).await;
    for _ in 0..10 {
        seq_test_client.send_publish_batch_request().await;
    }

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_contract = SimpleStorageContract::default();
    let full_node_test_client = make_test_client(full_node_port, full_node_contract).await;

    sleep(Duration::from_secs(10)).await;

    let seq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(10)))
        .await;
    let full_node_block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(10)))
        .await;

    assert_eq!(seq_block.state_root, full_node_block.state_root);

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

async fn setup_execute_four_blocks(
    seq_port: SocketAddr,
    full_node_port: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let contract = SimpleStorageContract::default();
    let full_node_contract = SimpleStorageContract::default();

    let seq_test_client = init_test_rollup(seq_port, contract).await;
    let full_node_test_client = init_test_rollup(full_node_port, full_node_contract).await;

    let _ = execute_four_blocks(&seq_test_client, &full_node_test_client).await;

    Ok(())
}

async fn execute_four_blocks<T: TestContract>(
    client: &Box<TestClient<T>>,
    full_node_client: &Box<TestClient<T>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (contract_address, _runtime_code) = {
        let runtime_code = client.deploy_contract_call().await?;
        let deploy_contract_req = client.deploy_contract().await?;
        client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .await?
            .unwrap()
            .contract_address
            .unwrap();

        (contract_address, runtime_code)
    };

    // Nonce should be 1 after the deploy
    let nonce = client.eth_get_transaction_count(client.from_addr).await;
    assert_eq!(1, nonce);

    // Check that the first block has published
    // It should have a single transaction, deploying the contract
    let first_block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(1)))
        .await;
    assert_eq!(first_block.number.unwrap().as_u64(), 1);
    assert_eq!(first_block.transactions.len(), 1);

    {
        let set_value_req = client.set_value(contract_address, 42, None, None).await;
        client.send_publish_batch_request().await;
        set_value_req.await.unwrap().unwrap();
    }

    client.send_publish_batch_request().await;

    {
        for _ in 0..3 {
            let _set_value_req = client.set_value(contract_address, 78, None, None).await;
        }
        client.send_publish_batch_request().await;
        sleep(Duration::from_millis(1000)).await;
    }

    sleep(Duration::from_millis(10000)).await;

    for i in 0..4 {
        let seq_block = client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Number(i)))
            .await;
        let full_node_block = full_node_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Number(i)))
            .await;

        assert_eq!(seq_block.number.unwrap().as_u64(), i);
        assert_eq!(full_node_block.number.unwrap().as_u64(), i);

        assert_eq!(seq_block.state_root, full_node_block.state_root);
    }

    let seq_last_block = client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_last_block = full_node_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    sleep(Duration::from_millis(10000)).await;

    assert_eq!(seq_last_block.number.unwrap().as_u64(), 4);
    assert_eq!(full_node_last_block.number.unwrap().as_u64(), 4);

    assert_eq!(seq_last_block.state_root, full_node_last_block.state_root);

    Ok(())
}

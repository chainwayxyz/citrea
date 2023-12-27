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
    let seq_contract = SimpleStorageContract::default();
    let seq_test_client = make_test_client(seq_port, seq_contract).await;

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

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let tx_hash = full_node_test_client.send_eth(addr, None, None).await;

    sleep(Duration::from_millis(2000)).await;

    seq_test_client.send_publish_batch_request().await;

    sleep(Duration::from_millis(2000)).await;

    let sq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(sq_block.transactions.contains(&tx_hash.tx_hash()));
    assert!(full_node_block.transactions.contains(&tx_hash.tx_hash()));
    assert_eq!(sq_block.state_root, full_node_block.state_root);

    seq_task.abort();
    full_node_task.abort();

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
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    for _ in 0..10 {
        seq_test_client.send_eth(addr, None, None).await;
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
    assert_eq!(seq_block.hash, full_node_block.hash);

    seq_task.abort();
    full_node_task.abort();

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

    let contract = SimpleStorageContract::default();
    let full_node_contract = SimpleStorageContract::default();

    let seq_test_client = init_test_rollup(seq_port, contract).await;
    let full_node_test_client = init_test_rollup(full_node_port, full_node_contract).await;

    let _ = execute_blocks(&seq_test_client, &full_node_test_client).await;

    seq_task.abort();
    rollup_task.abort();

    Ok(())
}

async fn execute_blocks<T: TestContract>(
    sequencer_client: &Box<TestClient<T>>,
    full_node_client: &Box<TestClient<T>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (contract_address, _runtime_code) = {
        let runtime_code = sequencer_client.deploy_contract_call().await?;
        let deploy_contract_req = sequencer_client.deploy_contract().await?;
        sequencer_client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .await?
            .unwrap()
            .contract_address
            .unwrap();

        (contract_address, runtime_code)
    };

    {
        let set_value_req = sequencer_client
            .set_value(contract_address, 42, None, None)
            .await;
        sequencer_client.send_publish_batch_request().await;
        set_value_req.await.unwrap().unwrap();
    }

    sequencer_client.send_publish_batch_request().await;

    {
        for temp in 0..10 {
            let _set_value_req = sequencer_client
                .set_value(contract_address, 78 + temp, None, None)
                .await;
        }
        sequencer_client.send_publish_batch_request().await;
    }

    {
        for _ in 0..200 {
            sequencer_client.send_publish_batch_request().await;
        }
    }

    {
        let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

        for _ in 0..300 {
            sequencer_client.send_eth(addr, None, None).await;
            sequencer_client.send_publish_batch_request().await;
        }
    }

    sleep(Duration::from_millis(5000)).await;

    let seq_last_block = sequencer_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_last_block = full_node_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_last_block.number.unwrap().as_u64(), 504);
    assert_eq!(full_node_last_block.number.unwrap().as_u64(), 504);

    assert_eq!(seq_last_block.state_root, full_node_last_block.state_root);
    assert_eq!(seq_last_block.hash, full_node_last_block.hash);

    Ok(())
}

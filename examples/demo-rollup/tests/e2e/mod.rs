use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use demo_stf::genesis_config::GenesisPaths;
use ethers::abi::Address;
use ethers_core::abi::Bytes;
use reth_primitives::BlockNumberOrTag;
// use sov_demo_rollup::initialize_logging;
use sov_evm::SimpleStorageContract;
use sov_modules_stf_blueprint::kernels::basic::BasicKernelGenesisPaths;
use sov_stf_runner::RollupProverConfig;
use tokio::time::sleep;

use crate::evm::{init_test_rollup, make_test_client};
use crate::test_client::TestClient;
use crate::test_helpers::{start_rollup, NodeMode};

#[tokio::test]
async fn test_full_node_send_tx() -> Result<(), anyhow::Error> {
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
    let seq_test_client = make_test_client(seq_port).await;

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
            None,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await;

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
async fn test_archival_state() -> Result<(), anyhow::Error> {
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

    let seq_test_client = init_test_rollup(seq_port).await;
    let addr = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();

    assert_eq!(
        seq_test_client
            .eth_get_balance(addr, BlockNumberOrTag::Latest)
            .await,
        0u64.into()
    );

    assert_eq!(
        seq_test_client
            .eth_get_storage_at(addr, 0u64.into(), BlockNumberOrTag::Latest)
            .await,
        0u64.into()
    );

    assert_eq!(
        seq_test_client
            .eth_get_code(addr, BlockNumberOrTag::Latest)
            .await,
        Bytes::from([])
    );

    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(addr, BlockNumberOrTag::Latest)
            .await,
        0
    );

    for _ in 0..8 {
        seq_test_client.send_eth(addr, None, None).await;
        seq_test_client.send_publish_batch_request().await;

        println!(
            "---> {:?}\n",
            seq_test_client
                .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
                .await
        );
    }

    assert_eq!(
        seq_test_client
            .eth_get_balance(addr, BlockNumberOrTag::Latest)
            .await,
        8u64.into()
    );

    // assert_eq!(
    //     seq_test_client
    //         .eth_get_balance(addr, BlockNumberOrTag::Number(5))
    //         .await,
    //     5u64.into()
    // );

    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                BlockNumberOrTag::Latest
            )
            .await,
        8
    );

    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                BlockNumberOrTag::Number(7)
            )
            .await,
        6 // ???
    );

    assert_eq!(
        seq_test_client
            .eth_get_storage_at(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                0u64.into(),
                BlockNumberOrTag::Latest
            )
            .await,
        0u64.into()
    );

    assert_eq!(
        seq_test_client
            .eth_get_code(addr, BlockNumberOrTag::Latest)
            .await,
        Bytes::from(vec![])
    );

    Ok(())
}

#[tokio::test]
async fn test_delayed_sync_ten_blocks() -> Result<(), anyhow::Error> {
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

    let seq_test_client = init_test_rollup(seq_port).await;
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
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
            None,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await;

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

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
            None,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;
    let full_node_test_client = init_test_rollup(full_node_port).await;

    let _ = execute_blocks(&seq_test_client, &full_node_test_client).await;

    seq_task.abort();
    rollup_task.abort();

    Ok(())
}

#[tokio::test]
async fn test_close_and_reopen_full_node() -> Result<(), anyhow::Error> {
    // initialize_logging();

    // Remove temp db directories if they exist
    let _ = fs::remove_dir_all(Path::new("demo_data_test_close_and_reopen_full_node_copy"));
    let _ = fs::remove_dir_all(Path::new("demo_data_test_close_and_reopen_full_node"));

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

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    // starting full node with db path
    let rollup_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
            Some("demo_data_test_close_and_reopen_full_node"),
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;
    let full_node_test_client = init_test_rollup(full_node_port).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // create 10 blocks
    for _ in 0..10 {
        seq_test_client.send_eth(addr, None, None).await;
        seq_test_client.send_publish_batch_request().await;
    }

    // wait for full node to sync
    sleep(Duration::from_secs(5)).await;

    // check if latest blocks are the same
    let seq_last_block = seq_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_last_block = full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_last_block.number.unwrap().as_u64(), 10);
    assert_eq!(full_node_last_block.number.unwrap().as_u64(), 10);

    assert_eq!(seq_last_block.state_root, full_node_last_block.state_root);
    assert_eq!(seq_last_block.hash, full_node_last_block.hash);

    // close full node
    rollup_task.abort();

    sleep(Duration::from_secs(2)).await;

    // create 100 more blocks
    for _ in 0..100 {
        seq_test_client.send_eth(addr, None, None).await;
        seq_test_client.send_publish_batch_request().await;
    }

    // start full node again
    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    // Copy the db to a new path with the same contents because
    // the lock is not released on the db directory even though the task is aborted

    let _ = copy_dir_recursive(
        Path::new("demo_data_test_close_and_reopen_full_node"),
        Path::new("demo_data_test_close_and_reopen_full_node_copy"),
    );

    sleep(Duration::from_secs(5)).await;

    // spin up the full node again with the same data where it left of only with different path to not stuck on lock
    let rollup_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
            Some("demo_data_test_close_and_reopen_full_node_copy"),
        )
        .await;
    });

    // TODO: There should be a better way to test this?
    sleep(Duration::from_secs(30)).await;
    let full_node_port = full_node_port_rx.await.unwrap();

    let full_node_test_client = make_test_client(full_node_port).await;

    // check if the latest block state roots are same
    let seq_last_block = seq_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_last_block = full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_last_block.number.unwrap().as_u64(), 110);
    assert_eq!(full_node_last_block.number.unwrap().as_u64(), 110);

    assert_eq!(seq_last_block.state_root, full_node_last_block.state_root);
    assert_eq!(seq_last_block.hash, full_node_last_block.hash);

    fs::remove_dir_all(Path::new("demo_data_test_close_and_reopen_full_node_copy")).unwrap();
    fs::remove_dir_all(Path::new("demo_data_test_close_and_reopen_full_node")).unwrap();

    seq_task.abort();
    rollup_task.abort();

    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() {
        fs::create_dir(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let entry_path = entry.path();
        let target_path = dst.join(entry.file_name());

        if entry_path.is_dir() {
            copy_dir_recursive(&entry_path, &target_path)?;
        } else {
            fs::copy(&entry_path, &target_path)?;
        }
    }
    Ok(())
}

async fn execute_blocks(
    sequencer_client: &TestClient,
    full_node_client: &TestClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let (contract_address, contract) = {
        let contract = SimpleStorageContract::default();
        let deploy_contract_req = sequencer_client
            .deploy_contract(contract.byte_code())
            .await?;
        sequencer_client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .await?
            .unwrap()
            .contract_address
            .unwrap();

        (contract_address, contract)
    };

    {
        let set_value_req = sequencer_client
            .contract_transaction(contract_address, contract.set_call_data(42))
            .await;
        sequencer_client.send_publish_batch_request().await;
        set_value_req.await.unwrap().unwrap();
    }

    sequencer_client.send_publish_batch_request().await;

    {
        for temp in 0..10 {
            let _set_value_req = sequencer_client
                .contract_transaction(contract_address, contract.set_call_data(78 + temp))
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

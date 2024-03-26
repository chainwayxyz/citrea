use std::net::SocketAddr;
use std::str::FromStr;

use citrea_stf::genesis_config::GenesisPaths;
use ethers_core::abi::Address;
use ethers_core::types::{BlockId, Bytes, U256};
use ethers_signers::{LocalWallet, Signer};
use reth_primitives::BlockNumberOrTag;
use sov_evm::smart_contracts::{LogsContract, SimpleStorageContract, TestContract};
use sov_modules_stf_blueprint::kernels::basic::BasicKernelGenesisPaths;
use sov_stf_runner::RollupProverConfig;

use crate::test_client::TestClient;
use crate::test_helpers::{start_rollup, NodeMode};
use crate::DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT;

mod archival_state;
mod gas_price;
mod tracing;

#[tokio::test]
async fn web3_rpc_tests() -> Result<(), anyhow::Error> {
    // sov_demo_rollup::initialize_logging();
    let (port_tx, port_rx) = tokio::sync::oneshot::channel();
    let rollup_task = tokio::spawn(async {
        // Don't provide a prover since the EVM is not currently provable
        start_rollup(
            port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Skip,
            NodeMode::SequencerNode,
            None,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
        )
        .await;
    });

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();

    let test_client = make_test_client(port).await;

    let tag = sov_ethereum::get_latest_git_tag().unwrap_or_else(|_| "unknown".to_string());
    let arch = std::env::consts::ARCH;

    assert_eq!(
        test_client.web3_client_version().await,
        format!("citrea/{}/{}/rust-1.77.0", tag, arch)
    );
    assert_eq!(
        test_client
            .web3_sha3("0x68656c6c6f20776f726c64".to_string())
            .await,
        "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad".to_string()
    );

    rollup_task.abort();
    Ok(())
}

#[tokio::test]
async fn evm_tx_tests() -> Result<(), anyhow::Error> {
    // sov_demo_rollup::initialize_logging();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_task = tokio::spawn(async {
        // Don't provide a prover since the EVM is not currently provable
        start_rollup(
            port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Skip,
            NodeMode::SequencerNode,
            None,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
        )
        .await;
    });

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();
    send_tx_test_to_eth(port).await.unwrap();
    rollup_task.abort();
    Ok(())
}

async fn send_tx_test_to_eth(rpc_address: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let test_client = init_test_rollup(rpc_address).await;
    execute(&test_client).await
}

#[tokio::test]
async fn test_eth_get_logs() -> Result<(), anyhow::Error> {
    use crate::test_helpers::start_rollup;

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_task = tokio::spawn(async {
        // Don't provide a prover since the EVM is not currently provable
        start_rollup(
            port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            RollupProverConfig::Skip,
            NodeMode::SequencerNode,
            None,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
        )
        .await;
    });

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();

    let test_client = init_test_rollup(port).await;

    test_getlogs(&test_client).await.unwrap();

    rollup_task.abort();
    Ok(())
}

#[allow(clippy::borrowed_box)]
async fn test_getlogs(client: &Box<TestClient>) -> Result<(), Box<dyn std::error::Error>> {
    let (contract_address, contract) = {
        let contract = LogsContract::default();
        let deploy_contract_req = client.deploy_contract(contract.byte_code(), None).await?;

        client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .await?
            .unwrap()
            .contract_address
            .unwrap();

        (contract_address, contract)
    };

    client
        .contract_transaction(
            contract_address,
            contract.publish_event("hello".to_string()),
            None,
        )
        .await;
    client.send_publish_batch_request().await;

    let empty_filter = serde_json::json!({});
    // supposed to get all the logs
    let logs = client.eth_get_logs(empty_filter).await;

    assert_eq!(logs.len(), 2);

    let one_topic_filter = serde_json::json!({
        "topics": [
            "0xa9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7"
        ]
    });
    // supposed to get the first log only
    let logs = client.eth_get_logs(one_topic_filter).await;

    assert_eq!(logs.len(), 1);
    assert_eq!(
        hex::encode(logs[0].topics[0]).to_string(),
        "a9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7"
    );

    let sepolia_log_data = "\"0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c48656c6c6f20576f726c64210000000000000000000000000000000000000000\"".to_string();
    let len = sepolia_log_data.len();
    assert_eq!(sepolia_log_data[1..len - 1], logs[0].data.to_string());

    // Deploy another contract
    let contract_address2 = {
        let deploy_contract_req = client.deploy_contract(contract.byte_code(), None).await?;
        client.send_publish_batch_request().await;

        deploy_contract_req
            .await?
            .unwrap()
            .contract_address
            .unwrap()
    };

    // call the second contract again
    let _pending_tx = client
        .contract_transaction(
            contract_address2,
            contract.publish_event("second contract".to_string()),
            None,
        )
        .await;
    client.send_publish_batch_request().await;

    // make sure the two contracts have different addresses
    assert_ne!(contract_address, contract_address2);

    // without any range or blockhash default behaviour is checking the latest block
    let just_address_filter = serde_json::json!({
        "address": contract_address
    });

    let logs = client.eth_get_logs(just_address_filter).await;
    // supposed to get both the logs coming from the contract
    assert_eq!(logs.len(), 0);

    // now we need to get all the logs with the first contract address
    let address_and_range_filter = serde_json::json!({
        "address": contract_address,
        "fromBlock": "0x1",
        "toBlock": "0x4"
    });

    let logs = client.eth_get_logs(address_and_range_filter).await;
    assert_eq!(logs.len(), 2);
    // make sure the address is the old one and not the new one
    assert_eq!(logs[0].address.as_slice(), contract_address.as_ref());
    assert_eq!(logs[1].address.as_slice(), contract_address.as_ref());

    Ok(())
}

#[allow(clippy::borrowed_box)]
async fn execute(client: &Box<TestClient>) -> Result<(), Box<dyn std::error::Error>> {
    // Nonce should be 0 in genesis
    let nonce = client
        .eth_get_transaction_count(client.from_addr, None)
        .await
        .unwrap();
    assert_eq!(0, nonce);

    // Balance should be > 0 in genesis
    let balance = client
        .eth_get_balance(client.from_addr, None)
        .await
        .unwrap();
    assert!(balance > U256::zero());

    let (contract_address, contract, runtime_code) = {
        let contract = SimpleStorageContract::default();

        let runtime_code = client
            .deploy_contract_call(contract.byte_code(), None)
            .await?;
        let deploy_contract_req = client.deploy_contract(contract.byte_code(), None).await?;
        client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .await?
            .unwrap()
            .contract_address
            .unwrap();

        (contract_address, contract, runtime_code)
    };

    // Assert contract deployed correctly
    let code = client.eth_get_code(contract_address, None).await.unwrap();
    // code has natural following 0x00 bytes, so we need to trim it
    assert_eq!(code.to_vec()[..runtime_code.len()], runtime_code.to_vec());

    // Nonce should be 1 after the deploy
    let nonce = client
        .eth_get_transaction_count(client.from_addr, None)
        .await
        .unwrap();
    assert_eq!(1, nonce);

    // Check that the first block has published
    // It should have a single transaction, deploying the contract
    let first_block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(1)))
        .await;
    assert_eq!(first_block.number.unwrap().as_u64(), 1);
    assert_eq!(first_block.transactions.len(), 1);

    let set_arg = 923;
    let tx_hash = {
        let set_value_req = client
            .contract_transaction(contract_address, contract.set_call_data(set_arg), None)
            .await;
        client.send_publish_batch_request().await;
        set_value_req.await.unwrap().unwrap().transaction_hash
    };
    // Now we have a second block
    let second_block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(2)))
        .await;
    assert_eq!(second_block.number.unwrap().as_u64(), 2);

    // Assert getTransactionByBlockHashAndIndex
    let tx_by_hash = client
        .eth_get_tx_by_block_hash_and_index(
            second_block.hash.unwrap(),
            ethereum_types::U256::from(0),
        )
        .await;
    assert_eq!(tx_by_hash.hash, tx_hash);

    // Assert getTransactionByBlockNumberAndIndex
    let tx_by_number = client
        .eth_get_tx_by_block_number_and_index(
            BlockNumberOrTag::Number(2),
            ethereum_types::U256::from(0),
        )
        .await;
    let tx_by_number_tag = client
        .eth_get_tx_by_block_number_and_index(
            BlockNumberOrTag::Latest,
            ethereum_types::U256::from(0),
        )
        .await;
    assert_eq!(tx_by_number.hash, tx_hash);
    assert_eq!(tx_by_number_tag.hash, tx_hash);

    let get_arg: U256 = client
        .contract_call(contract_address, contract.get_call_data(), None)
        .await?;

    assert_eq!(set_arg, get_arg.as_u32());

    // Assert storage slot is set
    let storage_slot = 0x0;
    let storage_value = client
        .eth_get_storage_at(contract_address, storage_slot.into(), None)
        .await
        .unwrap();
    assert_eq!(storage_value, ethereum_types::U256::from(set_arg));

    // Check that the second block has published
    // None should return the latest block
    // It should have a single transaction, setting the value
    let latest_block = client.eth_get_block_by_number_with_detail(None).await;
    assert_eq!(latest_block.number.unwrap().as_u64(), 2);
    assert_eq!(latest_block.transactions.len(), 1);
    assert_eq!(latest_block.transactions[0].hash, tx_hash);

    // This should just pass without error
    let _: Bytes = client
        .contract_call(contract_address, contract.set_call_data(set_arg), None)
        .await?;

    // This call should fail because function does not exist
    let failing_call: Result<Bytes, _> = client
        .contract_call(
            contract_address,
            contract.failing_function_call_data(),
            None,
        )
        .await;
    assert!(failing_call.is_err());

    // Create a blob with multiple transactions.
    client.sync_nonce().await; // sync nonce because of failed call
    let mut requests = Vec::default();
    for value in 150..153 {
        let set_value_req = client
            .contract_transaction(contract_address, contract.set_call_data(value), None)
            .await;
        requests.push(set_value_req);
    }

    client.send_publish_batch_request().await;
    client.send_publish_batch_request().await;
    for req in requests {
        req.await.unwrap();
    }

    {
        let get_arg: U256 = client
            .contract_call(contract_address, contract.get_call_data(), None)
            .await?;
        // should be one of three values sent in a single block. 150, 151, or 152
        assert!((150..=152).contains(&get_arg.as_u32()));
    }

    {
        let value = 103;

        let tx_hash = {
            let set_value_req = client
                .contract_transaction(contract_address, contract.set_call_data(value), None)
                .await;

            client.send_publish_batch_request().await;
            set_value_req.await.unwrap().unwrap().transaction_hash
        };

        let latest_block = client.eth_get_block_by_number(None).await;
        assert_eq!(latest_block.transactions.len(), 1);
        assert_eq!(latest_block.transactions[0], tx_hash);

        let latest_block_receipts = client
            .eth_get_block_receipts(BlockId::Number(ethers_core::types::BlockNumber::Latest))
            .await;
        let latest_block_receipt_by_number = client
            .eth_get_block_receipts(BlockId::Number(ethers_core::types::BlockNumber::Number(
                latest_block.number.unwrap(),
            )))
            .await;
        assert_eq!(latest_block_receipts, latest_block_receipt_by_number);
        assert_eq!(latest_block_receipts.len(), 1);
        assert_eq!(latest_block_receipts[0].transaction_hash, tx_hash);
        let tx_receipt = client.eth_get_transaction_receipt(tx_hash).await.unwrap();
        assert_eq!(tx_receipt, latest_block_receipts[0]);

        let get_arg: ethereum_types::U256 = client
            .contract_call(contract_address, contract.get_call_data(), None)
            .await?;

        assert_eq!(value, get_arg.as_u32());
    }

    let first_block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(0)))
        .await;
    let second_block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(1)))
        .await;

    // assert parent hash works correctly
    assert_eq!(
        first_block.hash.unwrap(),
        second_block.parent_hash,
        "Parent hash should be the hash of the previous block"
    );

    Ok(())
}

#[allow(clippy::borrowed_box)]
pub async fn init_test_rollup(rpc_address: SocketAddr) -> Box<TestClient> {
    let test_client = make_test_client(rpc_address).await;

    let etc_accounts = test_client.eth_accounts().await;
    assert_eq!(
        vec![Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap()],
        etc_accounts
    );

    let eth_chain_id = test_client.eth_chain_id().await;
    assert_eq!(5655, eth_chain_id);

    // No block exists yet
    let latest_block = test_client.eth_get_block_by_number(None).await;
    let earliest_block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Earliest))
        .await;

    assert_eq!(latest_block, earliest_block);
    assert_eq!(latest_block.number.unwrap().as_u64(), 0);
    test_client
}

#[allow(clippy::borrowed_box)]
pub async fn make_test_client(rpc_address: SocketAddr) -> Box<TestClient> {
    let chain_id: u64 = 5655;
    let key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(chain_id);

    let from_addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    Box::new(TestClient::new(chain_id, key, from_addr, rpc_address).await)
}

use std::net::SocketAddr;
use std::str::FromStr;

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
// use citrea::initialize_logging;
use alloy_primitives::{Address, Bytes, U256};
use citrea_common::SequencerConfig;
use citrea_evm::smart_contracts::{LogsContract, SimpleStorageContract, TestContract};
use citrea_evm::system_contracts::BitcoinLightClient;
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::{BlockId, BlockNumberOrTag};
use sov_rollup_interface::CITREA_VERSION;

// use sov_demo_rollup::initialize_logging;
use crate::test_client::TestClient;
use crate::test_helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::{
    TEST_DATA_GENESIS_PATH, TEST_SEND_NO_COMMITMENT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
};

mod archival_state;
mod fee;
mod gas_price;
mod subscription;
mod tracing;

#[tokio::test(flavor = "multi_thread")]
async fn web3_rpc_tests() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let sequener_config = SequencerConfig::default();
    let rollup_task = tokio::spawn(async {
        start_rollup(
            port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequener_config),
        )
        .await;
    });

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();

    let test_client = make_test_client(port).await?;

    let arch = std::env::consts::ARCH;

    assert_eq!(
        test_client.web3_client_version().await,
        format!(
            "citrea/{}/{}/rust-{}",
            CITREA_VERSION,
            arch,
            rustc_version_runtime::version()
        )
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

#[tokio::test(flavor = "multi_thread")]
async fn evm_tx_tests() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
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
    let rollup_task = tokio::spawn(async {
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
    send_tx_test_to_eth(port).await.unwrap();
    rollup_task.abort();
    Ok(())
}

async fn send_tx_test_to_eth(rpc_address: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let test_client = init_test_rollup(rpc_address).await;
    execute(&test_client).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_eth_get_logs() -> Result<(), anyhow::Error> {
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let sequencer_config = SequencerConfig::default();

    let rollup_task = tokio::spawn(async {
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

    let test_client = init_test_rollup(port).await;

    test_getlogs(&test_client).await.unwrap();

    rollup_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_genesis_contract_call() -> Result<(), Box<dyn std::error::Error>> {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let sequencer_config = SequencerConfig {
        min_soft_confirmations_per_commitment: 123456,
        ..Default::default()
    };
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../../resources/genesis/mock-dockerized/"),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await?;
    // call the contract with address 0x3100000000000000000000000000000000000001
    let contract_address = Address::from_str("0x3100000000000000000000000000000000000001").unwrap();

    let code = seq_test_client
        .eth_get_code(contract_address, None)
        .await
        .unwrap();

    let expected_code = "60806040523661001357610011610017565b005b6100115b61001f610169565b6001600160a01b0316330361015f5760606001600160e01b0319600035166364d3180d60e11b810161005a5761005361019c565b9150610157565b63587086bd60e11b6001600160e01b031982160161007a576100536101f3565b63070d7c6960e41b6001600160e01b031982160161009a57610053610239565b621eb96f60e61b6001600160e01b03198216016100b95761005361026a565b63a39f25e560e01b6001600160e01b03198216016100d9576100536102aa565b60405162461bcd60e51b815260206004820152604260248201527f5472616e73706172656e745570677261646561626c6550726f78793a2061646d60448201527f696e2063616e6e6f742066616c6c6261636b20746f2070726f78792074617267606482015261195d60f21b608482015260a4015b60405180910390fd5b815160208301f35b6101676102be565b565b60007fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b546001600160a01b0316919050565b60606101a66102ce565b60006101b53660048184610683565b8101906101c291906106c9565b90506101df816040518060200160405280600081525060006102d9565b505060408051602081019091526000815290565b60606000806102053660048184610683565b81019061021291906106fa565b91509150610222828260016102d9565b604051806020016040528060008152509250505090565b60606102436102ce565b60006102523660048184610683565b81019061025f91906106c9565b90506101df81610305565b60606102746102ce565b600061027e610169565b604080516001600160a01b03831660208201529192500160405160208183030381529060405291505090565b60606102b46102ce565b600061027e61035c565b6101676102c961035c565b61036b565b341561016757600080fd5b6102e28361038f565b6000825111806102ef5750805b15610300576102fe83836103cf565b505b505050565b7f7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f61032e610169565b604080516001600160a01b03928316815291841660208301520160405180910390a1610359816103fb565b50565b60006103666104a4565b905090565b3660008037600080366000845af43d6000803e80801561038a573d6000f35b3d6000fd5b610398816104cc565b6040516001600160a01b038216907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a250565b60606103f4838360405180606001604052806027815260200161083860279139610560565b9392505050565b6001600160a01b0381166104605760405162461bcd60e51b815260206004820152602660248201527f455243313936373a206e65772061646d696e20697320746865207a65726f206160448201526564647265737360d01b606482015260840161014e565b807fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b80546001600160a01b0319166001600160a01b039290921691909117905550565b60007f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61018d565b6001600160a01b0381163b6105395760405162461bcd60e51b815260206004820152602d60248201527f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60448201526c1bdd08184818dbdb9d1c9858dd609a1b606482015260840161014e565b807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc610483565b6060600080856001600160a01b03168560405161057d91906107e8565b600060405180830381855af49150503d80600081146105b8576040519150601f19603f3d011682016040523d82523d6000602084013e6105bd565b606091505b50915091506105ce868383876105d8565b9695505050505050565b60608315610647578251600003610640576001600160a01b0385163b6106405760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000604482015260640161014e565b5081610651565b6106518383610659565b949350505050565b8151156106695781518083602001fd5b8060405162461bcd60e51b815260040161014e9190610804565b6000808585111561069357600080fd5b838611156106a057600080fd5b5050820193919092039150565b80356001600160a01b03811681146106c457600080fd5b919050565b6000602082840312156106db57600080fd5b6103f4826106ad565b634e487b7160e01b600052604160045260246000fd5b6000806040838503121561070d57600080fd5b610716836106ad565b9150602083013567ffffffffffffffff81111561073257600080fd5b8301601f8101851361074357600080fd5b803567ffffffffffffffff81111561075d5761075d6106e4565b604051601f8201601f19908116603f0116810167ffffffffffffffff8111828210171561078c5761078c6106e4565b6040528181528282016020018710156107a457600080fd5b816020840160208301376000602083830101528093505050509250929050565b60005b838110156107df5781810151838201526020016107c7565b50506000910152565b600082516107fa8184602087016107c4565b9190910192915050565b60208152600082518060208401526108238160408501602087016107c4565b601f01601f1916919091016040019291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564";
    assert_eq!(code.to_vec(), hex::decode(expected_code).unwrap());

    let res: String = seq_test_client
        .contract_call(
            contract_address,
            BitcoinLightClient::get_system_caller().into(),
            None,
        )
        .await
        .unwrap();
    let expected_res = "0x000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead";
    assert_eq!(res, expected_res);

    let storage_value = seq_test_client
        .eth_get_storage_at(
            contract_address,
            U256::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
                .unwrap(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        storage_value,
        U256::from_str("0x0000000000000000000000003200000000000000000000000000000000000001")
            .unwrap()
    );

    seq_task.abort();
    Ok(())
}

#[allow(clippy::borrowed_box)]
async fn test_getlogs(client: &Box<TestClient>) -> Result<(), Box<dyn std::error::Error>> {
    let (contract_address, contract) = {
        let contract = LogsContract::default();
        let deploy_contract_req = client.deploy_contract(contract.byte_code(), None).await?;

        client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .get_receipt()
            .await?
            .contract_address
            .unwrap();

        (contract_address, contract)
    };

    let _pending_tx = client
        .contract_transaction(
            contract_address,
            contract.publish_event("hello".to_string()),
            None,
        )
        .await;
    client.send_publish_batch_request().await;
    wait_for_l2_block(client, 2, None).await;

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
        wait_for_l2_block(client, 2, None).await;

        deploy_contract_req
            .get_receipt()
            .await?
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
    wait_for_l2_block(client, 3, None).await;

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
    assert_eq!(logs[0].address, contract_address);
    assert_eq!(logs[1].address, contract_address);

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
    assert!(balance > U256::from(0));

    let (contract_address, contract, runtime_code) = {
        let contract = SimpleStorageContract::default();

        let runtime_code = client
            .deploy_contract_call(contract.byte_code(), None)
            .await?;
        let deploy_contract_req = client.deploy_contract(contract.byte_code(), None).await?;
        client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .get_receipt()
            .await?
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
    assert_eq!(first_block.header.number, 1);
    assert_eq!(first_block.transactions.len(), 4);

    let set_arg = 923;
    let tx_hash = {
        let set_value_req = client
            .contract_transaction(contract_address, contract.set_call_data(set_arg), None)
            .await;
        client.send_publish_batch_request().await;
        set_value_req.get_receipt().await.unwrap().transaction_hash
    };
    // Now we have a second block
    let second_block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(2)))
        .await;
    assert_eq!(second_block.header.number, 2);

    // Assert getTransactionByBlockHashAndIndex
    let tx_by_hash = client
        .eth_get_tx_by_block_hash_and_index(second_block.header.hash, U256::from(0))
        .await;
    assert_eq!(tx_by_hash.hash, tx_hash);

    // Assert getTransactionByBlockNumberAndIndex
    let tx_by_number = client
        .eth_get_tx_by_block_number_and_index(BlockNumberOrTag::Number(2), U256::from(0))
        .await;
    let tx_by_number_tag = client
        .eth_get_tx_by_block_number_and_index(BlockNumberOrTag::Latest, U256::from(0))
        .await;
    assert_eq!(tx_by_number.hash, tx_hash);
    assert_eq!(tx_by_number_tag.hash, tx_hash);

    let get_arg: U256 = client
        .contract_call(contract_address, contract.get_call_data(), None)
        .await?;

    assert_eq!(set_arg, get_arg.saturating_to::<u32>());

    // Assert storage slot is set
    let storage_slot = 0x0;
    let storage_value = client
        .eth_get_storage_at(contract_address, U256::from(storage_slot), None)
        .await
        .unwrap();
    assert_eq!(storage_value, U256::from(set_arg));

    // Check that the second block has published
    // None should return the latest block
    // It should have a single transaction, setting the value
    let latest_block = client.eth_get_block_by_number_with_detail(None).await;
    let block_transactions: Vec<_> = latest_block.transactions.hashes().clone().collect();
    assert_eq!(latest_block.header.number, 2);
    assert_eq!(block_transactions.len(), 1);
    assert_eq!(block_transactions[0], tx_hash);

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
        req.get_receipt().await.unwrap();
    }

    {
        let get_arg: U256 = client
            .contract_call(contract_address, contract.get_call_data(), None)
            .await?;
        // should be one of three values sent in a single block. 150, 151, or 152
        assert!((150..=152).contains(&get_arg.saturating_to()));
    }

    {
        let value = 103;

        let tx_hash = {
            let set_value_req = client
                .contract_transaction(contract_address, contract.set_call_data(value), None)
                .await;

            client.send_publish_batch_request().await;
            set_value_req.get_receipt().await.unwrap().transaction_hash
        };

        let latest_block = client.eth_get_block_by_number(None).await;
        let block_transactions = latest_block.transactions.as_hashes().unwrap();
        assert_eq!(block_transactions.len(), 1);
        assert_eq!(block_transactions[0], tx_hash);

        let latest_block_receipts = client
            .eth_get_block_receipts(BlockId::Number(BlockNumberOrTag::Latest))
            .await;
        let latest_block_receipt_by_number = client
            .eth_get_block_receipts(BlockId::Number(BlockNumberOrTag::Number(
                latest_block.header.number,
            )))
            .await;
        assert_eq!(latest_block_receipts, latest_block_receipt_by_number);
        assert_eq!(latest_block_receipts.len(), 1);
        assert_eq!(latest_block_receipts[0].transaction_hash, tx_hash);
        let tx_receipt = client.eth_get_transaction_receipt(tx_hash).await.unwrap();
        assert_eq!(tx_receipt, latest_block_receipts[0]);

        let get_arg: U256 = client
            .contract_call(contract_address, contract.get_call_data(), None)
            .await?;

        assert_eq!(value, get_arg.saturating_to::<u32>());
    }

    let first_block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(0)))
        .await;
    let second_block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(1)))
        .await;

    // assert parent hash works correctly
    assert_eq!(
        first_block.header.hash, second_block.header.parent_hash,
        "Parent hash should be the hash of the previous block"
    );

    Ok(())
}

#[allow(clippy::borrowed_box)]
pub async fn init_test_rollup(rpc_address: SocketAddr) -> Box<TestClient> {
    let test_client = make_test_client(rpc_address).await.unwrap();

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
    assert_eq!(latest_block.header.number, 0);
    test_client
}

#[allow(clippy::borrowed_box)]
pub async fn make_test_client(rpc_address: SocketAddr) -> anyhow::Result<Box<TestClient>> {
    let chain_id: u64 = 5655;
    let key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        .parse::<PrivateKeySigner>()
        .unwrap()
        .with_chain_id(Some(chain_id));

    let from_addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    Ok(Box::new(
        TestClient::new(chain_id, key, from_addr, rpc_address).await?,
    ))
}

use std::net::SocketAddr;
use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy_primitives::U256;
use citrea_common::SequencerConfig;
use citrea_evm::smart_contracts::SimpleStorageContract;
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::BlockNumberOrTag;

use crate::evm::init_test_rollup;
use crate::test_client::TestClient;
use crate::test_helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::TEST_DATA_GENESIS_PATH;

#[tokio::test(flavor = "multi_thread")]
async fn test_gas_price_increase() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let sequencer_config = SequencerConfig::default();

    let rollup_task = tokio::spawn(async {
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
    let test_client = init_test_rollup(port).await;
    execute(&test_client, port).await.unwrap();
    rollup_task.abort();
    Ok(())
}

#[allow(clippy::borrowed_box)]
async fn execute(
    client: &Box<TestClient>,
    port: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let (contract_address, contract) = {
        let contract = SimpleStorageContract::default();

        let deploy_contract_req = client.deploy_contract(contract.byte_code(), None).await?;
        client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .get_receipt()
            .await?
            .contract_address
            .unwrap();

        (contract_address, contract)
    };

    // get initial fee history
    let initial_fee_history = client
        .eth_fee_history(
            // block count hex
            "0x100".to_string(),
            BlockNumberOrTag::Latest,
            None,
        )
        .await;
    assert_eq!(initial_fee_history.oldest_block, U256::from(0));

    let mut block_index = 2;

    // Create 100 wallets and send them some eth
    let wallets_count = 100u32;
    let tx_count_from_single_address = 15u32;
    let one_eth = u128::pow(10, 18);
    let mut wallets = Vec::with_capacity(wallets_count as usize);
    for i in 0..wallets_count {
        let mut wallet = PrivateKeySigner::random();
        wallet.set_chain_id(Some(client.chain_id));
        let address = wallet.address();
        let _pending = client
            .send_eth(address, None, None, None, one_eth)
            .await
            .unwrap();
        wallets.push(wallet);

        if i % tx_count_from_single_address == 0 {
            client.send_publish_batch_request().await;
            wait_for_l2_block(client, block_index, Some(Duration::from_secs(60))).await;
            block_index += 1;
        }
    }
    client.send_publish_batch_request().await;
    wait_for_l2_block(client, block_index, Some(Duration::from_secs(60))).await;
    block_index += 1;

    // send 15 transactions from each wallet
    for wallet in wallets {
        let address = wallet.address();
        let wallet_client = TestClient::new(client.chain_id, wallet, address, port).await?;
        for i in 0..tx_count_from_single_address {
            let _pending = wallet_client
                .contract_transaction(contract_address, contract.set_call_data(i), None)
                .await;
        }
    }
    client.send_publish_batch_request().await;
    wait_for_l2_block(client, block_index, Some(Duration::from_secs(60))).await;
    block_index += 1;

    let block = client.eth_get_block_by_number(None).await;
    assert!(
        block.header.gas_used as u64 <= reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT,
        "Block has gas limit"
    );
    assert!(
        block.transactions.len() < (wallets_count * tx_count_from_single_address) as usize,
        "Some of the transactions should be dropped because of gas limit"
    );

    // get initial gas price from the last committed block. I.e. the price before the transactions
    let initial_gas_price = client.eth_gas_price().await;

    client.send_publish_batch_request().await;
    wait_for_l2_block(client, block_index, None).await;

    // get new gas price after the transactions that was adjusted in the last block
    let latest_gas_price = client.eth_gas_price().await;

    assert!(
        latest_gas_price > initial_gas_price,
        "Gas price should increase {} > {}",
        latest_gas_price,
        initial_gas_price
    );

    // get fee history
    let latest_fee_history = client
        .eth_fee_history(
            // block count hex
            "0x100".to_string(),
            BlockNumberOrTag::Latest,
            None,
        )
        .await;
    assert_eq!(latest_fee_history.oldest_block, U256::from(0));

    // there are 10 blocks in between
    assert_eq!(
        latest_fee_history.gas_used_ratio.len() - initial_fee_history.gas_used_ratio.len(),
        10
    );

    assert!(client
        .eth_fee_history(
            // block count hex
            "0x100".to_string(),
            BlockNumberOrTag::Latest,
            Some(vec![0.01, 0.2]), // totally random
        )
        .await
        .reward
        .is_some());

    assert!(client
        .eth_fee_history(
            // block count hex
            "0x100".to_string(),
            BlockNumberOrTag::Latest,
            Some(vec![]), // totally random
        )
        .await
        .reward
        .is_some());

    Ok(())
}

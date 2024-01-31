use std::net::SocketAddr;

use demo_stf::genesis_config::GenesisPaths;
use ethers_core::rand::thread_rng;
use ethers_core::types::U256;
use ethers_core::utils::Units::Ether;
use ethers_signers::{LocalWallet, Signer};
use reth_primitives::BlockNumberOrTag;
use sov_evm::SimpleStorageContract;
use sov_modules_stf_blueprint::kernels::basic::BasicKernelGenesisPaths;
use sov_stf_runner::RollupProverConfig;

use crate::evm::init_test_rollup;
use crate::test_client::TestClient;
use crate::test_helpers::{start_rollup, NodeMode};

#[tokio::test]
async fn test_gas_price_increase() -> Result<(), anyhow::Error> {
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
            .await?
            .unwrap()
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
    assert_eq!(initial_fee_history.oldest_block, U256::zero());

    // Create 100 wallets and send them some eth
    let one_eth = u128::pow(10, Ether.as_num());
    let mut rng = thread_rng();
    let mut wallets = Vec::with_capacity(100);
    for i in 0..100 {
        let wallet = LocalWallet::new(&mut rng).with_chain_id(client.chain_id);
        let address = wallet.address();
        client
            .send_eth(address, None, None, None, one_eth)
            .await
            .unwrap();
        wallets.push(wallet);

        if i % 15 == 0 {
            client.send_publish_batch_request().await;
        }
    }
    client.send_publish_batch_request().await;

    // get initial gas price
    let initial_gas_price = client.eth_gas_price().await;

    // send 15 transactions from each wallet
    for wallet in wallets {
        let address = wallet.address();
        let wallet_client = TestClient::new(client.chain_id, wallet, address, port).await;
        for i in 0u32..15 {
            wallet_client
                .contract_transaction(contract_address, contract.set_call_data(i), None)
                .await;
        }
    }
    client.send_publish_batch_request().await;
    client.send_publish_batch_request().await; // if this isn't here gas fees don't increase, why?

    // get new gas price
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
    assert_eq!(latest_fee_history.oldest_block, U256::zero());

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

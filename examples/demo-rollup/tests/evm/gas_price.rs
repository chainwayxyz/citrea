use std::net::SocketAddr;
use std::str::FromStr;

use demo_stf::genesis_config::GenesisPaths;
use ethers_core::abi::Address;
use ethers_core::rand::thread_rng;
use ethers_core::types::transaction::eip2718::TypedTransaction;
use ethers_core::types::{BlockId, Bytes, Eip1559TransactionRequest, U256};
use ethers_core::utils::Units::{Ether, Gwei, Pwei, Wei};
use ethers_middleware::SignerMiddleware;
use ethers_providers::{Middleware, Provider};
use ethers_signers::{LocalWallet, Signer};
use reth_primitives::BlockNumberOrTag;
// use sov_demo_rollup::initialize_logging;
use sov_evm::{LogsContract, SimpleStorageContract, TestContract};
use sov_modules_stf_blueprint::kernels::basic::BasicKernelGenesisPaths;
use sov_stf_runner::RollupProverConfig;
use tokio::time::{sleep, Duration};

use crate::evm::init_test_rollup;
use crate::test_client::{TestClient, MAX_FEE_PER_GAS};
use crate::test_helpers::{start_rollup, NodeMode};

#[tokio::test]
async fn test_gas_price_increase() -> Result<(), anyhow::Error> {
    // initialize_logging();
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
    rpc_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
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
    let one_eth = 1 * u128::pow(10, 18);
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
        let provider = Provider::try_from(&client.host).unwrap();
        let signer = SignerMiddleware::new_with_provider_chain(provider, wallet)
            .await
            .unwrap();
        let nonce = client
            .eth_get_transaction_count(address, None)
            .await
            .unwrap();
        for i in 0u32..15 {
            let req = Eip1559TransactionRequest::new()
                .from(address)
                .to(contract_address)
                .chain_id(client.chain_id)
                .nonce(nonce + u64::from(i))
                .max_priority_fee_per_gas(10u64)
                .max_fee_per_gas(MAX_FEE_PER_GAS)
                .gas(crate::test_client::GAS)
                .data(contract.set_call_data(i));
            let typed_transaction = TypedTransaction::Eip1559(req);

            signer
                .send_transaction(typed_transaction, None)
                .await
                .unwrap();
        }
    }
    client.send_publish_batch_request().await;
    client.send_publish_batch_request().await; // if this isnt here gas fees don't increase, why?

    // get new gas price
    let latest_gas_price = client.eth_gas_price().await;

    assert!(
        latest_gas_price > initial_gas_price,
        "Gas price should increase {} > {}",
        latest_gas_price,
        initial_gas_price
    );

    // // get fee history
    // let latest_fee_history = main_client
    //     .eth_fee_history(
    //         // block count hex
    //         "0x100".to_string(),
    //         BlockNumberOrTag::Latest,
    //         None,
    //     )
    //     .await;
    // assert_eq!(latest_fee_history.oldest_block, U256::zero());
    //
    // // there are 4 blocks in between
    // assert_eq!(
    //     latest_fee_history.gas_used_ratio.len() - initial_fee_history.gas_used_ratio.len(),
    //     4
    // );
    //
    // assert!(main_client
    //     .eth_fee_history(
    //         // block count hex
    //         "0x100".to_string(),
    //         BlockNumberOrTag::Latest,
    //         Some(vec![0.01, 0.2]), // totally random
    //     )
    //     .await
    //     .reward
    //     .is_some());
    //
    // assert!(main_client
    //     .eth_fee_history(
    //         // block count hex
    //         "0x100".to_string(),
    //         BlockNumberOrTag::Latest,
    //         Some(vec![]), // totally random
    //     )
    //     .await
    //     .reward
    //     .is_some());
    //
    // let first_block = main_client
    //     .eth_get_block_by_number(Some(BlockNumberOrTag::Number(0)))
    //     .await;
    // let second_block = main_client
    //     .eth_get_block_by_number(Some(BlockNumberOrTag::Number(1)))
    //     .await;
    //
    // // assert parent hash works correctly
    // assert_eq!(
    //     first_block.hash.unwrap(),
    //     second_block.parent_hash,
    //     "Parent hash should be the hash of the previous block"
    // );

    Ok(())
}

/// Testing if the sequencer and full node can handle system transactions correctly (the full node should have the same system transactions as the sequencer)
use std::str::FromStr;

use alloy_primitives::Address;
use citrea_evm::system_contracts::BitcoinLightClient;
use citrea_evm::SYSTEM_SIGNER;
use reth_primitives::BlockNumberOrTag;
use sov_mock_da::{MockAddress, MockDaService};
use sov_rollup_interface::services::da::DaService;

use crate::e2e::{initialize_test, TestConfig};
use crate::test_helpers::{tempdir_with_children, wait_for_l1_block, wait_for_l2_block};

/// Trigger system transactions.
/// Ask the sequencer and the full node for blocks.
/// Check if the system transactions are included in the blocks.
#[tokio::test(flavor = "multi_thread")]
async fn test_system_transactions() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let system_contract_address =
        Address::from_str("0x3100000000000000000000000000000000000001").unwrap();
    let system_signer_address = Address::from_slice(SYSTEM_SIGNER.as_slice());

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }
    wait_for_l1_block(&da_service, 3, None).await;

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir,
            sequencer_path: sequencer_db_dir,
            fullnode_path: fullnode_db_dir,
            ..Default::default()
        })
        .await;

    // publish some blocks with system transactions
    for i in 0..10 {
        for _ in 0..5 {
            seq_test_client.spam_publish_batch_request().await.unwrap();
        }
        wait_for_l2_block(&seq_test_client, 5 * (i + 1), None).await;

        da_service.publish_test_block().await.unwrap();

        wait_for_l1_block(&da_service, 4 + i, None).await;
    }

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 51, None).await;

    // check block 1-6-11-16-21-26-31-36-41-46-51 has system transactions
    for i in 0..=10 {
        let block_num = 1 + i * 5;

        let block = full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(block_num)))
            .await;

        if block_num == 1 {
            let block_transactions = block.transactions.as_transactions().unwrap();
            assert_eq!(block_transactions.len(), 3);

            let init_tx = &block_transactions[0];
            let set_tx = &block_transactions[1];

            assert_eq!(init_tx.from, system_signer_address);
            assert_eq!(init_tx.to.unwrap(), system_contract_address);
            assert_eq!(
                init_tx.input[..],
                *hex::decode(
                    "1f5783330000000000000000000000000000000000000000000000000000000000000003"
                )
                .unwrap()
                .as_slice()
            );

            assert_eq!(set_tx.from, system_signer_address);
            assert_eq!(set_tx.to.unwrap(), system_contract_address);
            assert_eq!(
                set_tx.input[0..4],
                *hex::decode("0e27bc11").unwrap().as_slice()
            );
        } else {
            let block_transactions = block.transactions.as_transactions().unwrap();
            assert_eq!(block_transactions.len(), 1);

            let tx = &block_transactions[0];

            assert_eq!(tx.from, system_signer_address);
            assert_eq!(tx.to.unwrap(), system_contract_address);
            assert_eq!(tx.input[0..4], *hex::decode("0e27bc11").unwrap().as_slice());
        }
    }

    // and other blocks don't have
    for i in 0..=51 {
        if i % 5 == 1 {
            continue;
        }

        let block = full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(i)))
            .await;

        assert_eq!(block.transactions.len(), 0);
    }

    // now check hashes
    for i in 3..=13 {
        let da_block = da_service.get_block_at(i).await.unwrap();

        let hash_on_chain: String = full_node_test_client
            .contract_call(
                system_contract_address,
                BitcoinLightClient::get_block_hash(i).to_vec(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            &da_block.header.hash.0,
            hex::decode(hash_on_chain.clone().split_off(2))
                .unwrap()
                .as_slice()
        );

        // check block response as well
        let block = full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number((i - 3) * 5 + 1)))
            .await;

        assert_eq!(block.other.get("l1Hash"), Some(&hash_on_chain.into()));
    }

    let seq_last_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    let node_last_block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_last_block, node_last_block);

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

use std::str::FromStr;
use std::time::Duration;

use alloy_primitives::{Address, Bytes, B256, U256};
use citrea_common::SequencerConfig;
use citrea_evm::smart_contracts::SimpleStorageContract;
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::{BlockId, BlockNumberOrTag};
use tokio::time::sleep;

use crate::evm::init_test_rollup;
use crate::test_client::TestClient;
use crate::test_helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::TEST_DATA_GENESIS_PATH;

#[tokio::test(flavor = "multi_thread")]
async fn test_archival_state() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let sequencer_config = SequencerConfig::default();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;
    let addr = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();

    run_archival_valid_tests(addr, &seq_test_client).await;
    run_archival_fail_tests(addr, &seq_test_client).await;

    seq_task.abort();
    Ok(())
}

async fn run_archival_fail_tests(addr: Address, seq_test_client: &TestClient) {
    let invalid_block_hash = B256::random();
    let invalid_block_balance = seq_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(722))))
        .await
        .unwrap_err();

    assert!(invalid_block_balance
        .to_string()
        .contains("block not found: number 0x2d2"));

    let invalid_block_balance = seq_test_client
        .eth_get_balance(addr, Some(BlockId::Hash(invalid_block_hash.into())))
        .await
        .unwrap_err();

    assert!(invalid_block_balance
        .to_string()
        .contains("unknown block or tx index"));

    let invalid_block_storage = seq_test_client
        .eth_get_storage_at(
            addr,
            U256::from(0),
            Some(BlockId::Number(BlockNumberOrTag::Number(722))),
        )
        .await
        .unwrap_err();
    assert!(invalid_block_storage
        .to_string()
        .contains("block not found:"));

    let invalid_block_storage = seq_test_client
        .eth_get_storage_at(
            addr,
            U256::from(0),
            Some(BlockId::Hash(invalid_block_hash.into())),
        )
        .await
        .unwrap_err();
    assert!(invalid_block_storage
        .to_string()
        .contains("unknown block or tx index"));

    let invalid_block_code = seq_test_client
        .eth_get_code(addr, Some(BlockId::Number(BlockNumberOrTag::Number(722))))
        .await
        .unwrap_err();
    assert!(invalid_block_code.to_string().contains("block not found:"));

    let invalid_block_code = seq_test_client
        .eth_get_code(addr, Some(BlockId::Hash(invalid_block_hash.into())))
        .await
        .unwrap_err();
    assert!(invalid_block_code
        .to_string()
        .contains("unknown block or tx index"));

    let invalid_block_tx_count = seq_test_client
        .eth_get_transaction_count(addr, Some(BlockId::Number(BlockNumberOrTag::Number(722))))
        .await
        .unwrap_err();
    assert!(invalid_block_tx_count
        .to_string()
        .contains("block not found:"));

    let invalid_block_tx_count = seq_test_client
        .eth_get_transaction_count(addr, Some(BlockId::Hash(invalid_block_hash.into())))
        .await
        .unwrap_err();
    assert!(invalid_block_tx_count
        .to_string()
        .contains("unknown block or tx index"));
}

async fn run_archival_valid_tests(addr: Address, seq_test_client: &TestClient) {
    let latest_block_hash = seq_test_client
        .eth_get_block_by_number(None)
        .await
        .header
        .hash;
    assert_eq!(
        seq_test_client
            .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Latest)))
            .await
            .unwrap(),
        U256::from(0)
    );

    assert_eq!(
        seq_test_client
            .eth_get_balance(addr, Some(BlockId::Hash(latest_block_hash.into())))
            .await
            .unwrap(),
        U256::from(0)
    );

    assert_eq!(
        seq_test_client
            .eth_get_storage_at(
                addr,
                U256::from(0),
                Some(BlockId::Number(BlockNumberOrTag::Latest))
            )
            .await
            .unwrap(),
        U256::from(0)
    );
    assert_eq!(
        seq_test_client
            .eth_get_storage_at(
                addr,
                U256::from(0),
                Some(BlockId::Hash(latest_block_hash.into()))
            )
            .await
            .unwrap(),
        U256::from(0)
    );

    assert_eq!(
        seq_test_client
            .eth_get_code(addr, Some(BlockId::Number(BlockNumberOrTag::Latest)))
            .await
            .unwrap(),
        Bytes::from([])
    );
    assert_eq!(
        seq_test_client
            .eth_get_code(addr, Some(BlockId::Hash(latest_block_hash.into())))
            .await
            .unwrap(),
        Bytes::from([])
    );

    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(addr, Some(BlockId::Number(BlockNumberOrTag::Latest)))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(addr, Some(BlockId::Hash(latest_block_hash.into())))
            .await
            .unwrap(),
        0
    );

    for i in 1..=8 {
        let _t = seq_test_client
            .send_eth(addr, None, None, None, 1u128)
            .await;
        seq_test_client.send_publish_batch_request().await;
        wait_for_l2_block(seq_test_client, i, None).await;
    }
    let latest_block_hash = seq_test_client
        .eth_get_block_by_number(None)
        .await
        .header
        .hash;
    // Wait for changeset storage
    sleep(Duration::from_secs(2)).await;

    assert_eq!(
        seq_test_client
            .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Latest)))
            .await
            .unwrap(),
        U256::from(8)
    );
    assert_eq!(
        seq_test_client
            .eth_get_balance(addr, Some(BlockId::Hash(latest_block_hash.into())))
            .await
            .unwrap(),
        U256::from(8)
    );

    assert_eq!(
        seq_test_client.eth_get_balance(addr, None).await.unwrap(),
        U256::from(8)
    );

    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                Some(BlockId::Number(BlockNumberOrTag::Latest))
            )
            .await
            .unwrap(),
        8
    );
    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                Some(BlockId::Hash(latest_block_hash.into()))
            )
            .await
            .unwrap(),
        8
    );

    for i in 1..=8 {
        assert_eq!(
            seq_test_client
                .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(i))))
                .await
                .unwrap(),
            U256::from(i)
        );

        let block_hash_i = seq_test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Number(i)))
            .await
            .header
            .hash;

        assert_eq!(
            seq_test_client
                .eth_get_balance(addr, Some(BlockId::Hash(block_hash_i.into())))
                .await
                .unwrap(),
            U256::from(i)
        );

        assert_eq!(
            seq_test_client
                .eth_get_transaction_count(
                    Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                    Some(BlockId::Number(BlockNumberOrTag::Number(i)))
                )
                .await
                .unwrap(),
            i
        );

        assert_eq!(
            seq_test_client
                .eth_get_transaction_count(
                    Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                    Some(BlockId::Hash(block_hash_i.into()))
                )
                .await
                .unwrap(),
            i
        );
    }

    assert_eq!(
        seq_test_client
            .eth_get_storage_at(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                U256::from(0),
                Some(BlockId::Number(BlockNumberOrTag::Latest))
            )
            .await
            .unwrap(),
        U256::from(0)
    );

    assert_eq!(
        seq_test_client
            .eth_get_storage_at(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                U256::from(0),
                Some(BlockId::Hash(latest_block_hash.into()))
            )
            .await
            .unwrap(),
        U256::from(0)
    );

    assert_eq!(
        seq_test_client
            .eth_get_code(addr, Some(BlockId::Number(BlockNumberOrTag::Latest)))
            .await
            .unwrap(),
        Bytes::from(vec![])
    );
    assert_eq!(
        seq_test_client
            .eth_get_code(addr, Some(BlockId::Hash(latest_block_hash.into())))
            .await
            .unwrap(),
        Bytes::from(vec![])
    );

    assert_eq!(
        seq_test_client
            .eth_get_code(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                Some(BlockId::Number(BlockNumberOrTag::Latest))
            )
            .await
            .unwrap(),
        Bytes::from(vec![])
    );
    assert_eq!(
        seq_test_client
            .eth_get_code(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                Some(BlockId::Hash(latest_block_hash.into()))
            )
            .await
            .unwrap(),
        Bytes::from(vec![])
    );

    let (contract_address, contract, runtime_code) = {
        let contract = SimpleStorageContract::default();

        let runtime_code = seq_test_client
            .deploy_contract_call(contract.byte_code(), None)
            .await
            .unwrap();

        let deploy_contract_req = seq_test_client
            .deploy_contract(contract.byte_code(), None)
            .await
            .unwrap();

        seq_test_client.send_publish_batch_request().await;
        wait_for_l2_block(seq_test_client, 9, None).await;

        let contract_address = deploy_contract_req
            .get_receipt()
            .await
            .unwrap()
            .contract_address
            .unwrap();

        (contract_address, contract, runtime_code)
    };

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(seq_test_client, 11, None).await;

    let code = seq_test_client
        .eth_get_code(
            contract_address,
            Some(BlockId::Number(BlockNumberOrTag::Number(9))),
        )
        .await
        .unwrap();

    assert_eq!(code.to_vec()[..runtime_code.len()], runtime_code.to_vec());

    let block_hash_9 = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await
        .header
        .hash;

    let code = seq_test_client
        .eth_get_code(contract_address, Some(BlockId::Hash(block_hash_9.into())))
        .await
        .unwrap();

    assert_eq!(code.to_vec()[..runtime_code.len()], runtime_code.to_vec());

    let block_hash_8 = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(8)))
        .await
        .header
        .hash;

    let non_existent_code = seq_test_client
        .eth_get_code(contract_address, Some(BlockId::Hash(block_hash_8.into())))
        .await
        .unwrap();
    assert_eq!(non_existent_code, Bytes::from(vec![]));

    let non_existent_code = seq_test_client
        .eth_get_code(
            contract_address,
            Some(BlockId::Number(BlockNumberOrTag::Number(8))),
        )
        .await
        .unwrap();
    assert_eq!(non_existent_code, Bytes::from(vec![]));

    let set_arg = 923;
    let _pending = seq_test_client
        .contract_transaction(contract_address, contract.set_call_data(set_arg), None)
        .await;

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(seq_test_client, 13, None).await;

    let storage_slot = U256::from(0);
    let storage_value = seq_test_client
        .eth_get_storage_at(
            contract_address,
            storage_slot,
            Some(BlockId::Number(BlockNumberOrTag::Latest)),
        )
        .await
        .unwrap();
    assert_eq!(storage_value, U256::from(set_arg));

    let latest_block_hash = seq_test_client
        .eth_get_block_by_number(None)
        .await
        .header
        .hash;

    let storage_value = seq_test_client
        .eth_get_storage_at(
            contract_address,
            storage_slot,
            Some(BlockId::Hash(latest_block_hash.into())),
        )
        .await
        .unwrap();
    assert_eq!(storage_value, U256::from(set_arg));

    let previous_storage_value = seq_test_client
        .eth_get_storage_at(
            contract_address,
            storage_slot,
            Some(BlockId::Number(BlockNumberOrTag::Number(11))),
        )
        .await
        .unwrap();

    assert_eq!(previous_storage_value, U256::from(0));

    let block_hash_11 = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(11)))
        .await
        .header
        .hash;

    let previous_storage_value = seq_test_client
        .eth_get_storage_at(
            contract_address,
            storage_slot,
            Some(BlockId::Hash(block_hash_11.into())),
        )
        .await
        .unwrap();

    assert_eq!(previous_storage_value, U256::from(0));
}

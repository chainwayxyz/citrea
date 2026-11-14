use std::str::FromStr;

use alloy_primitives::{Address, U64};
use citrea_common::SequencerConfig;
use citrea_evm::smart_contracts::{
    SimpleStorageContract, SimpleStorageDuplicatorContract, TouchEmptyAccountsContract,
};
use citrea_stf::genesis_config::GenesisPaths;

use super::init_test_rollup;
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, NodeMode,
};
use crate::common::TEST_DATA_GENESIS_PATH;

#[tokio::test(flavor = "multi_thread")]
async fn diff_sizes() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig::default();

    let seq_task = start_rollup(
        seq_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        Some(sequencer_config),
        None,
        false,
    )
    .await;

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;

    // compare sending cBTC to the same address
    // resulting in different sizes because in the first tx address was just created
    // so on the second tx we don't pay for setting address index
    {
        let receiver_address = Address::random();

        let first_send = seq_test_client
            .send_eth(receiver_address, None, None, None, 1_000_000)
            .await
            .unwrap();

        let second_send = seq_test_client
            .send_eth(receiver_address, None, None, None, 1_000_000)
            .await
            .unwrap();

        seq_test_client.send_publish_batch_request().await;

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let first_send_receipt = seq_test_client
            .eth_get_transaction_receipt(*first_send.tx_hash())
            .await
            .unwrap();

        let second_send_receipt = seq_test_client
            .eth_get_transaction_receipt(*second_send.tx_hash())
            .await
            .unwrap();

        // (2 * 53 * 32 // 100 + 32) * 48 // 100 + 2
        assert_eq!(
            U64::from_str(
                first_send_receipt
                    .other
                    .get("l1DiffSize")
                    .unwrap()
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
            U64::from(33)
        );
        // (2 * 53 * 32 // 100) * 48 // 100 + 2
        assert_eq!(
            U64::from_str(
                second_send_receipt
                    .other
                    .get("l1DiffSize")
                    .unwrap()
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
            U64::from(17)
        );
    }

    let simple_storage_address = seq_test_client.from_addr.create(2);

    // call a smart contract and see storages were charged
    {
        let deploy_tx = seq_test_client
            .deploy_contract(SimpleStorageContract::default().byte_code(), None)
            .await
            .unwrap();

        seq_test_client.send_publish_batch_request().await;
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let set_storage_tx = seq_test_client
            .contract_transaction(
                simple_storage_address,
                SimpleStorageContract::default().set_call_data(100),
                None,
            )
            .await;

        seq_test_client.send_publish_batch_request().await;
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // sanity check
        assert_eq!(
            seq_test_client
                .contract_call::<U64>(
                    simple_storage_address,
                    SimpleStorageContract::default().get_call_data(),
                    None,
                )
                .await
                .unwrap(),
            U64::from(100),
        );

        let deploy_receipt = seq_test_client
            .eth_get_transaction_receipt(*deploy_tx.tx_hash())
            .await
            .unwrap();

        let set_storage_receipt = seq_test_client
            .eth_get_transaction_receipt(*set_storage_tx.tx_hash())
            .await
            .unwrap();

        // ((53 * 32 + 85 * 32) // 100 + 32) * 48 // 100 + 2
        assert_eq!(
            U64::from_str(
                deploy_receipt
                    .other
                    .get("l1DiffSize")
                    .unwrap()
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
            U64::from(38)
        );

        // ((53 * 32 // 100) + (1 * 68 * 66 // 100)) * 48 // 100 + 2
        assert_eq!(
            U64::from_str(
                set_storage_receipt
                    .other
                    .get("l1DiffSize")
                    .unwrap()
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
            U64::from(30)
        );
    }

    // make a transaction to a contract that calls another contract
    // resulting in storage changes in both
    // all storage changes should be charged
    // as there is a separate Journal for each call in the tx
    // we must make sure we include all Journals in the tx
    {
        let deploy_tx = seq_test_client
            .deploy_contract(SimpleStorageDuplicatorContract::default().byte_code(), None)
            .await
            .unwrap();

        let duplicator_address = seq_test_client.from_addr.create(4);

        seq_test_client.send_publish_batch_request().await;
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let set_storage_tx = seq_test_client
            .contract_transaction(
                duplicator_address,
                SimpleStorageDuplicatorContract::default()
                    .set_call_data(500, simple_storage_address),
                None,
            )
            .await;

        seq_test_client.send_publish_batch_request().await;
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // sanity check
        assert_eq!(
            seq_test_client
                .contract_call::<U64>(
                    simple_storage_address,
                    SimpleStorageContract::default().get_call_data(),
                    None,
                )
                .await
                .unwrap(),
            U64::from(500),
        );

        assert_eq!(
            seq_test_client
                .contract_call::<U64>(
                    duplicator_address,
                    SimpleStorageDuplicatorContract::default().get_call_data(),
                    None,
                )
                .await
                .unwrap(),
            U64::from(500),
        );

        let deploy_receipt = seq_test_client
            .eth_get_transaction_receipt(*deploy_tx.tx_hash())
            .await
            .unwrap();

        let set_storage_receipt = seq_test_client
            .eth_get_transaction_receipt(*set_storage_tx.tx_hash())
            .await
            .unwrap();

        // ((53 * 32 + 85 * 32) // 100 + 32) * 48 // 100 + 2
        assert_eq!(
            U64::from_str(
                deploy_receipt
                    .other
                    .get("l1DiffSize")
                    .unwrap()
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
            U64::from(38)
        );

        // ((53 * 32 // 100) + (2 * 68 * 66 // 100)) * 48 // 100 + 2
        assert_eq!(
            U64::from_str(
                set_storage_receipt
                    .other
                    .get("l1DiffSize")
                    .unwrap()
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
            U64::from(52)
        );
    }

    seq_task.graceful_shutdown();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn diff_sizes_touched_empty_accounts() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig::default();

    let seq_task = start_rollup(
        seq_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        Some(sequencer_config),
        None,
        false,
    )
    .await;

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = init_test_rollup(seq_port).await;

    let contract = TouchEmptyAccountsContract::default();
    let deploy_tx = seq_test_client
        .deploy_contract(contract.byte_code(), None)
        .await
        .unwrap();

    seq_test_client.send_publish_batch_request().await;
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let contract_address = deploy_tx.get_receipt().await?.contract_address.unwrap();

    let touched_accounts = [
        Address::from([0x11; 20]),
        Address::from([0x12; 20]),
        Address::from([0x13; 20]),
        Address::from([0x14; 20]),
        Address::from([0x15; 20]),
        Address::from([0x16; 20]),
        Address::from([0x17; 20]),
        Address::from([0x18; 20]),
        Address::from([0x19; 20]),
        Address::from([0x1a; 20]),
    ];

    let account_proof_before = seq_test_client
        .eth_get_proof(touched_accounts[0], vec![], None)
        .await
        .unwrap();
    let account_exists_before = account_proof_before
        .account_proof
        .last()
        .map(|b| b.as_ref() == b"y")
        .unwrap_or(false);

    let first_touch_tx = seq_test_client
        .contract_transaction(
            contract_address,
            contract.touch_call_data(&touched_accounts),
            None,
        )
        .await;

    seq_test_client.send_publish_batch_request().await;
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let _first_touch_receipt = seq_test_client
        .eth_get_transaction_receipt(*first_touch_tx.tx_hash())
        .await
        .unwrap();

    let account_proof_after = seq_test_client
        .eth_get_proof(touched_accounts[0], vec![], None)
        .await
        .unwrap();
    let account_exists_after = account_proof_after
        .account_proof
        .last()
        .map(|b| b.as_ref() == b"y")
        .unwrap_or(false);

    // Zero-value touches do not currently materialize accounts in this flow.
    assert!(!account_exists_before);
    assert!(!account_exists_after);

    seq_task.graceful_shutdown();
    Ok(())
}

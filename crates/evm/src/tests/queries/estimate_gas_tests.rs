use std::str::FromStr;

use alloy_eips::eip2930::{AccessList, AccessListItem, AccessListWithGasUsed};
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{address, b256, Address, TxKind, U256};
use alloy_rpc_types::{TransactionInput, TransactionRequest};
use jsonrpsee::core::RpcResult;
use reth_rpc_eth_types::RpcInvalidTransactionError;
use serde_json::json;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::fork::Fork;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, Spec, WorkingSet};

use crate::call::CallMessage;
use crate::query::MIN_TRANSACTION_GAS;
use crate::smart_contracts::{CallerContract, SimpleProxyContract, SimpleStorageContract};
use crate::tests::get_test_seq_pub_key;
use crate::tests::queries::{init_evm, init_evm_single_block, init_evm_with_caller_contract};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{commit, create_contract_message_with_bytecode, get_fork_fn_latest};
use crate::{EstimatedDiffSize, Evm};

type C = DefaultContext;

fn deploy_simple_proxy(
    evm: &mut Evm<C>,
    mut working_set: WorkingSet<<C as Spec>::Storage>,
    prover_storage: <C as Spec>::Storage,
    signer: &TestSigner,
    ledger_db: &LedgerDB,
    l2_height: u64,
    implementation: Address,
) -> (Address, WorkingSet<<C as Spec>::Storage>) {
    let proxy = SimpleProxyContract::default();
    let proxy_deployment_bytecode = proxy.deployment_bytecode(implementation);

    let current_nonce = evm
        .get_transaction_count(signer.address(), None, &mut working_set, ledger_db)
        .unwrap();

    let proxy_address = signer.address().create(current_nonce.to::<u64>());

    let l1_fee_rate = 1;
    let spec_id = sov_modules_api::SpecId::Fork3;
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: spec_id,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 24,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    let deploy_tx = create_contract_message_with_bytecode(
        signer,
        current_nonce.to::<u64>(),
        proxy_deployment_bytecode,
        None,
    );

    let sender_address = generate_address::<C>("sender");
    let context = C::new(sender_address, l2_height, spec_id, l1_fee_rate);

    evm.call(
        CallMessage {
            txs: vec![deploy_tx],
        },
        &context,
        &mut working_set,
    )
    .expect("Deployment should succeed");

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[101u8; 32], &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    (proxy_address, WorkingSet::new(prover_storage))
}

#[test]
fn test_payable_contract_value() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::Tangerine);

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(address!(
            "819c5497b157177315e1204f52e588b393771719"
        ))), // Address of the payable contract.
        gas: Some(100000),
        gas_price: Some(100000000),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        value: Some(U256::from(3100000)),
        input: TransactionInput {
            input: None,
            data: None,
        },
        nonce: Some(1u64),
        chain_id: Some(1u64),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        transaction_type: None,
        sidecar: None,
        authorization_list: None,
    };

    let result = evm.eth_estimate_gas_inner(
        tx_req,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(result.unwrap(), U256::from_str("0xab13").unwrap());
}

#[test]
fn test_tx_request_fields_gas_fork1() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::Tangerine);

    let tx_req_contract_call = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(address!(
            "819c5497b157177315e1204f52e588b393771719"
        ))),
        gas: Some(10000000),
        gas_price: Some(100),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        value: None,
        input: TransactionInput {
            input: None,
            data: None,
        },
        nonce: Some(1u64),
        chain_id: Some(1u64),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        transaction_type: None,
        sidecar: None,
        authorization_list: None,
    };

    let result_contract_call = evm.eth_estimate_gas_inner(
        tx_req_contract_call.clone(),
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(
        result_contract_call.unwrap(),
        U256::from_str("0x6602").unwrap()
    );
    let contract_diff_size = evm.eth_estimate_diff_size_inner(
        tx_req_contract_call.clone(),
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(
        contract_diff_size.unwrap(),
        serde_json::from_value::<EstimatedDiffSize>(json![{"gas":"0x6601","l1DiffSize":"0x9"}])
            .unwrap()
    );

    let tx_req_no_gas = TransactionRequest {
        gas: None,
        ..tx_req_contract_call.clone()
    };

    let contract_diff_size = evm.eth_estimate_diff_size_inner(
        tx_req_no_gas.clone(),
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(
        contract_diff_size.unwrap(),
        serde_json::from_value::<EstimatedDiffSize>(json![{"gas":"0x6601","l1DiffSize":"0x9"}])
            .unwrap()
    );

    let tx_req_no_sender = TransactionRequest {
        from: None,
        nonce: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_sender = evm.eth_estimate_gas_inner(
        tx_req_no_sender,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(result_no_sender.unwrap(), U256::from_str("0x6602").unwrap());
    working_set.unset_archival_version();

    let tx_req_no_recipient = TransactionRequest {
        to: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_recipient = evm.eth_estimate_gas_inner(
        tx_req_no_recipient,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(
        result_no_recipient.unwrap(),
        U256::from_str("0xd0ad").unwrap()
    );
    working_set.unset_archival_version();

    let tx_req_no_gas = TransactionRequest {
        gas: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_gas = evm.eth_estimate_gas_inner(
        tx_req_no_gas,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(result_no_gas.unwrap(), U256::from_str("0x6602").unwrap());
    working_set.unset_archival_version();

    let tx_req_no_gas_price = TransactionRequest {
        gas_price: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_gas_price = evm.eth_estimate_gas_inner(
        tx_req_no_gas_price,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(
        result_no_gas_price.unwrap(),
        U256::from_str("0x6602").unwrap()
    );
    working_set.unset_archival_version();

    let tx_req_no_chain_id = TransactionRequest {
        chain_id: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_chain_id = evm.eth_estimate_gas_inner(
        tx_req_no_chain_id,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(
        result_no_chain_id.unwrap(),
        U256::from_str("0x6602").unwrap()
    );
    working_set.unset_archival_version();

    let tx_req_invalid_chain_id = TransactionRequest {
        chain_id: Some(3u64),
        ..tx_req_contract_call.clone()
    };

    let result_invalid_chain_id = evm.eth_estimate_gas_inner(
        tx_req_invalid_chain_id,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(
        result_invalid_chain_id,
        Err(RpcInvalidTransactionError::InvalidChainId.into())
    );
    working_set.unset_archival_version();

    // We don't have EIP-4844 now, so this is just to see if it's working.
    let tx_req_no_blob_versioned_hashes = TransactionRequest {
        blob_versioned_hashes: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_blob_versioned_hashes = evm.eth_estimate_gas_inner(
        tx_req_no_blob_versioned_hashes,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(
        result_no_blob_versioned_hashes.unwrap(),
        U256::from_str("0x6602").unwrap()
    );
    working_set.unset_archival_version();

    let no_access_list_req = TransactionRequest {
        access_list: None,
        ..tx_req_contract_call.clone()
    };

    let create_no_access_list_test = evm.create_access_list_inner(
        no_access_list_req,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(
        create_no_access_list_test.unwrap(),
        AccessListWithGasUsed {
            access_list: AccessList(vec![AccessListItem {
                address: address!("819c5497b157177315e1204f52e588b393771719"),
                storage_keys: vec![b256!(
                    "d17c80a661d193357ea7c5311e029471883989438c7bcae8362437311a764685"
                )]
            }]),
            gas_used: U256::from_str("0x6e67").unwrap()
        }
    );

    let access_list_req = TransactionRequest {
        access_list: Some(AccessList(vec![AccessListItem {
            address: address!("819c5497b157177315e1204f52e588b393771719"),
            storage_keys: vec![b256!(
                "d17c80a661d193357ea7c5311e029471883989438c7bcae8362437311a764685"
            )],
        }])),
        ..tx_req_contract_call.clone()
    };

    let access_list_gas_test = evm.eth_estimate_gas_inner(
        access_list_req.clone(),
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    // Wrong access punishment.
    assert_eq!(
        access_list_gas_test.unwrap(),
        U256::from_str("0x6e67").unwrap()
    );

    let already_formed_list = evm.create_access_list_inner(
        access_list_req,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(
        already_formed_list.unwrap(),
        AccessListWithGasUsed {
            access_list: AccessList(vec![AccessListItem {
                address: address!("819c5497b157177315e1204f52e588b393771719"),
                storage_keys: vec![b256!(
                    "d17c80a661d193357ea7c5311e029471883989438c7bcae8362437311a764685"
                )]
            }]),
            gas_used: U256::from_str("0x6e67").unwrap()
        }
    );
}

#[test]
fn test_access_list() {
    // 0x819c5497b157177315e1204f52e588b393771719 -- Storage contract
    // 0x5ccda3e6d071a059f00d4f3f25a1adc244eb5c93 -- Caller contract

    let (evm, mut working_set, signer, _, ledger_db) = init_evm_with_caller_contract();

    let caller = CallerContract::default();
    let input_data = caller.call_set_call_data(
        Address::from_str("0x819c5497b157177315e1204f52e588b393771719").unwrap(),
        42,
    );

    let tx_req_contract_call = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(address!(
            "5ccda3e6d071a059f00d4f3f25a1adc244eb5c93"
        ))),
        gas: Some(10000000),
        gas_price: Some(100),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        value: None,
        input: TransactionInput::new(input_data.into()),
        nonce: Some(3u64),
        chain_id: Some(1u64),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        transaction_type: None,
        sidecar: None,
        authorization_list: None,
    };

    let no_access_list = evm.eth_estimate_gas_inner(
        tx_req_contract_call.clone(),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(no_access_list.unwrap(), U256::from_str("0x788c").unwrap());

    let form_access_list = evm.create_access_list_inner(
        tx_req_contract_call.clone(),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(
        form_access_list.unwrap(),
        AccessListWithGasUsed {
            access_list: AccessList(vec![AccessListItem {
                address: address!("819c5497b157177315e1204f52e588b393771719"),
                storage_keys: vec![b256!(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                )]
            }]),
            gas_used: U256::from_str("0x775e").unwrap()
        }
    );

    let tx_req_with_access_list = TransactionRequest {
        access_list: Some(AccessList(vec![AccessListItem {
            address: address!("819c5497b157177315e1204f52e588b393771719"),
            storage_keys: vec![b256!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )],
        }])),
        ..tx_req_contract_call.clone()
    };

    let with_access_list = evm.eth_estimate_gas_inner(
        tx_req_with_access_list,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(with_access_list.unwrap(), U256::from_str("0x775e").unwrap());
}

#[test]
fn estimate_gas_with_varied_inputs_test() {
    let (evm, mut working_set, _, signer, _, ledger_db) =
        init_evm(sov_modules_api::SpecId::Tangerine);

    let simple_call_data = 0;
    let simple_result = test_estimate_gas_with_input(
        &evm,
        &mut working_set,
        &ledger_db,
        &signer,
        simple_call_data,
    );

    assert_eq!(simple_result.unwrap(), U256::from_str("0x684e").unwrap());

    let simple_call_data = 131;
    let simple_result = test_estimate_gas_with_input(
        &evm,
        &mut working_set,
        &ledger_db,
        &signer,
        simple_call_data,
    );

    assert_eq!(simple_result.unwrap(), U256::from_str("0x68cd").unwrap());

    // Testing with non-zero value transfer EOA
    let value_transfer_result = test_estimate_gas_with_value(
        &evm,
        &mut working_set,
        &ledger_db,
        &signer,
        U256::from(1_000_000),
    );

    assert_eq!(
        value_transfer_result.unwrap(),
        U256::from(MIN_TRANSACTION_GAS + 1)
    );
}

#[test]
fn test_pending_env() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::Tangerine);

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(address!(
            "819c5497b157177315e1204f52e588b393771719"
        ))), // Address of the payable contract.
        gas: Some(100000),
        gas_price: Some(100000000),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        value: Some(U256::from(3100000)),
        input: TransactionInput {
            input: None,
            data: None,
        },
        nonce: Some(1u64),
        chain_id: Some(1u64),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        transaction_type: None,
        sidecar: None,
        authorization_list: None,
    };

    let result = evm
        .eth_estimate_gas_inner(
            tx_req.clone(),
            Some(BlockNumberOrTag::Latest),
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    let result_pending = evm.eth_estimate_gas_inner(
        tx_req.clone(),
        Some(BlockNumberOrTag::Pending),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(result_pending.unwrap(), result);

    let result = evm
        .create_access_list_inner(
            tx_req.clone(),
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    let result_pending = evm
        .create_access_list_inner(
            tx_req.clone(),
            Some(BlockNumberOrTag::Pending),
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    assert_eq!(result_pending, result);
}

fn test_estimate_gas_with_input(
    evm: &Evm<C>,
    working_set: &mut WorkingSet<<C as Spec>::Storage>,
    ledger_db: &LedgerDB,
    signer: &TestSigner,
    input_data: u32,
) -> RpcResult<U256> {
    let input_data = SimpleStorageContract::default().set_call_data(input_data);
    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(address!(
            "eeb03d20dae810f52111b853b31c8be6f30f4cd3"
        ))),
        gas: Some(100_000),
        input: TransactionInput::new(input_data.into()),
        ..Default::default()
    };

    evm.eth_estimate_gas_inner(
        tx_req,
        Some(BlockNumberOrTag::Latest),
        working_set,
        ledger_db,
        get_fork_fn_latest(),
    )
}

fn test_estimate_gas_with_value(
    evm: &Evm<C>,
    working_set: &mut WorkingSet<<C as Spec>::Storage>,
    ledger_db: &LedgerDB,
    signer: &TestSigner,
    value: U256,
) -> RpcResult<U256> {
    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(address!(
            "abababababababababababababababababababab"
        ))),
        value: Some(value),
        ..Default::default()
    };

    evm.eth_estimate_gas_inner(
        tx_req,
        Some(BlockNumberOrTag::Latest),
        working_set,
        ledger_db,
        get_fork_fn_latest(),
    )
}

#[test]
fn test_eip7702_execute_revert() {
    // This test reproduces the EIP-7702 gas estimation bug found on testnet:
    // Transaction hash: 0xb3083c96053a046f85b5990b0eaeffd386f1d79a271aa8d9e0db7ba680a041fd
    //
    // When an EIP-7702 transaction calls a function that reverts,
    // eth_estimateGas returns a gas estimate instead of returning an error.
    //
    // Expected: eth_estimateGas returns Err(revert)
    // Actual (bug): eth_estimateGas returns Ok(gas_estimate)

    let (mut evm, working_set, prover_storage, signer, l2_height, ledger_db) =
        init_evm(sov_modules_api::SpecId::Fork3);

    // Deploy SimpleProxy with zero address as implementation
    let (proxy_address, mut working_set) = deploy_simple_proxy(
        &mut evm,
        working_set,
        prover_storage,
        &signer,
        &ledger_db,
        l2_height,
        Address::ZERO,
    );

    let proxy = SimpleProxyContract::default();

    let nonce_after_deploy = evm
        .get_transaction_count(signer.address(), None, &mut working_set, &ledger_db)
        .unwrap();

    let auth = signer
        .get_signed_authorization(proxy_address, nonce_after_deploy.to::<u64>())
        .expect("Should create signed authorization");

    let reverting_call_data = proxy.reverting_execute_call_data();

    // Create transaction that will REVERT:
    // - EOA delegates to SimpleProxy via EIP-7702 authorization
    // - Self-call (from == to) with the authorization active
    // - Calls revertingExecute which always reverts
    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(signer.address())), // Self-call!
        value: None,
        input: TransactionInput::new(reverting_call_data.into()),
        chain_id: Some(1u64),
        gas: None, // Let estimator determine gas
        gas_price: Some(100_000_000),
        nonce: Some(nonce_after_deploy.to::<u64>()),
        access_list: None,
        authorization_list: Some(vec![auth]),
        ..Default::default()
    };

    let fork = Fork::new(sov_modules_api::SpecId::Tangerine, 0);

    // Call eth_estimate_gas_inner
    // Expected: Returns Err(revert)
    // Bug: Returns Ok(gas_estimate)
    let result = evm.eth_estimate_gas_inner(
        tx_req,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        |_| fork,
    );

    match result {
        Ok(gas_estimate) => {
            panic!(
                "BUG REPRODUCED! eth_estimateGas returned gas estimate {gas_estimate} for a transaction that ALWAYS reverts. Should return Err(revert)."
            );
        }
        Err(_err) => {
            panic!("SHOULD NOT HAPPEN because even with contract reverting, the bug should exist and gas estimation should pass");
        }
    }
}

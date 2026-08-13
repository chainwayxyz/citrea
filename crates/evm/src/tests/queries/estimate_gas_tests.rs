use std::str::FromStr;

use alloy_eips::eip2930::{AccessList, AccessListItem, AccessListWithGasUsed};
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::map::AddressMap;
use alloy_primitives::{address, b256, TxKind, U256};
use alloy_rpc_types::state::AccountOverride;
use alloy_rpc_types::{TransactionInput, TransactionRequest};
use jsonrpsee::core::RpcResult;
use reth_rpc_eth_types::RpcInvalidTransactionError;
use serde_json::json;
use sov_db::ledger_db::{LedgerDB, NodeLedgerOps};
use sov_db::schema::types::{L2HeightAndIndex, L2HeightStatus};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, Spec, WorkingSet};

use crate::call::CallMessage;
use crate::query::MIN_TRANSACTION_GAS;
use crate::smart_contracts::{CallerContract, SimpleStorageContract};
use crate::tests::get_test_seq_pub_key;
use crate::tests::queries::{init_evm, init_evm_single_block, init_evm_with_caller_contract};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{
    commit, create_contract_transaction, get_fork_fn_latest, set_arg_message,
};
use crate::{EstimatedDiffSize, Evm};

type C = DefaultContext;

#[test]
fn test_payable_contract_value() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(signer.address().create(0))), // Address of the payable contract.
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
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(result.unwrap(), U256::from_str("0xab13").unwrap());
}

#[test]
fn test_tx_request_fields_gas_fork1() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    let tx_req_contract_call = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(signer.address().create(0))),
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(
        create_no_access_list_test.unwrap(),
        AccessListWithGasUsed {
            access_list: AccessList(vec![AccessListItem {
                address: signer.address().create(0),
                storage_keys: vec![b256!(
                    "d17c80a661d193357ea7c5311e029471883989438c7bcae8362437311a764685"
                )]
            }]),
            gas_used: U256::from_str("0x6e67").unwrap()
        }
    );

    let access_list_req = TransactionRequest {
        access_list: Some(AccessList(vec![AccessListItem {
            address: signer.address().create(0),
            storage_keys: vec![b256!(
                "d17c80a661d193357ea7c5311e029471883989438c7bcae8362437311a764685"
            )],
        }])),
        ..tx_req_contract_call.clone()
    };

    let access_list_gas_test = evm.eth_estimate_gas_inner(
        access_list_req.clone(),
        Some(BlockNumberOrTag::Latest),
        None,
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
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(
        already_formed_list.unwrap(),
        AccessListWithGasUsed {
            access_list: AccessList(vec![AccessListItem {
                address: signer.address().create(0),
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
    let input_data = caller.call_set_call_data(signer.address().create(0), 42);

    let tx_req_contract_call = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(signer.address().create(2))),
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
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(no_access_list.unwrap(), U256::from_str("0x788c").unwrap());

    let form_access_list = evm.create_access_list_inner(
        tx_req_contract_call.clone(),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(
        form_access_list.unwrap(),
        AccessListWithGasUsed {
            access_list: AccessList(vec![AccessListItem {
                address: signer.address().create(0),
                storage_keys: vec![b256!(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                )]
            }]),
            gas_used: U256::from_str("0x775e").unwrap()
        }
    );

    let tx_req_with_access_list = TransactionRequest {
        access_list: Some(AccessList(vec![AccessListItem {
            address: signer.address().create(0),
            storage_keys: vec![b256!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )],
        }])),
        ..tx_req_contract_call.clone()
    };

    let with_access_list = evm.eth_estimate_gas_inner(
        tx_req_with_access_list,
        None,
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
        init_evm(sov_modules_api::SpecId::latest());

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
        init_evm_single_block(sov_modules_api::SpecId::latest());

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(signer.address().create(0))), // Address of the payable contract.
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
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    let result_pending = evm.eth_estimate_gas_inner(
        tx_req.clone(),
        Some(BlockNumberOrTag::Pending),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(result_pending.unwrap(), result);

    let result = evm
        .create_access_list_inner(
            tx_req.clone(),
            None,
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
            None,
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
        to: Some(TxKind::Call(signer.address().create(7))),
        gas: Some(100_000),
        input: TransactionInput::new(input_data.into()),
        ..Default::default()
    };

    evm.eth_estimate_gas_inner(
        tx_req,
        Some(BlockNumberOrTag::Latest),
        None,
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
        None,
        working_set,
        ledger_db,
        get_fork_fn_latest(),
    )
}

#[test]
fn test_estimate_gas_no_balance() {
    let (evm, mut working_set, _, signer, _, ledger_db) =
        init_evm(sov_modules_api::SpecId::latest());

    let contract = SimpleStorageContract::default();
    let contract_address = signer.address().create(7);

    // Random address that has no balance
    let no_balance_address = address!("0x1234567890123456789012345678901234567890");

    // Assert that the address has no balance
    let balance = evm.get_balance(no_balance_address, None, &mut working_set, &ledger_db);
    assert_eq!(balance.unwrap(), U256::ZERO);

    // Test 1: Simple transfer to an EOA (no data)
    let result = evm
        .eth_estimate_gas_inner(
            TransactionRequest {
                from: Some(no_balance_address),
                to: Some(TxKind::Call(signer.address())),
                input: TransactionInput::default(),
                ..Default::default()
            },
            Some(BlockNumberOrTag::Latest),
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .expect("simple transfer to EOA should succeed");
    assert!(result >= U256::from(MIN_TRANSACTION_GAS));

    // Test 2: Call to a contract with data field populated (getter function)
    evm.eth_estimate_gas_inner(
        TransactionRequest {
            from: Some(no_balance_address),
            to: Some(TxKind::Call(contract_address)),
            input: TransactionInput::new(contract.get_call_data().into()),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    )
    .expect("call to getter function should succeed");

    // Test 3: Call to a contract with data field populated (setter function)
    evm.eth_estimate_gas_inner(
        TransactionRequest {
            from: Some(no_balance_address),
            to: Some(TxKind::Call(contract_address)),
            input: TransactionInput::new(contract.set_call_data(42).into()),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    )
    .expect("call to setter function should succeed");

    // Test 4: Estimate gas with value transfer should still fail
    let result = evm.eth_estimate_gas_inner(
        TransactionRequest {
            from: Some(no_balance_address),
            to: Some(TxKind::Call(signer.address())),
            value: Some(U256::from(1000)),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(
        result,
        Err(RpcInvalidTransactionError::InsufficientFunds {
            cost: U256::from(1000),
            balance: U256::from(0)
        }
        .into())
    );

    // Test 5: Estimate gas with no from address should succeed
    let result = evm.eth_estimate_gas_inner(
        TransactionRequest {
            to: Some(TxKind::Call(signer.address())),
            input: TransactionInput::default(),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert!(result.is_ok());

    // Test 6: Estimate gas from account with 1 wei balance should fail
    let mut state_override = AddressMap::default();
    state_override.insert(
        no_balance_address,
        AccountOverride {
            balance: Some(U256::from(1)),
            ..Default::default()
        },
    );
    let result = evm.eth_estimate_gas_inner(
        TransactionRequest {
            from: Some(no_balance_address),
            to: Some(TxKind::Call(signer.address())),
            input: TransactionInput::default(),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        Some(state_override),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert!(result.is_err());
}

#[test]
fn test_estimate_tx_expenses_honors_block_tag() {
    let (mut evm, _, prover_storage, signer, l2_height, ledger_db) =
        init_evm(sov_modules_api::SpecId::latest());
    assert_eq!(l2_height, 4);

    let spec_id = sov_modules_api::SpecId::latest();
    let l1_fee_rate = 1;

    let contract = SimpleStorageContract::default();
    let contract_address = signer.address().create(9);

    // Block 4 deploys the contract
    // Block 5 sets a storage slot
    let blocks = [
        (
            4,
            [102u8; 32],
            vec![create_contract_transaction(
                &signer,
                9,
                SimpleStorageContract::default(),
            )],
        ),
        (
            5,
            [103u8; 32],
            vec![set_arg_message(contract_address, &signer, 10, 478)],
        ),
    ];

    let mut pre_state_root = [101u8; 32];
    for (height, post_state_root, txs) in blocks {
        let mut working_set = WorkingSet::new(prover_storage.clone());

        let l2_block_info = HookL2BlockInfo {
            l2_height: height,
            pre_state_root,
            current_spec: spec_id,
            sequencer_pub_key: get_test_seq_pub_key(),
            l1_fee_rate,
            timestamp: 24,
        };

        evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, height, spec_id, l1_fee_rate);
        evm.call(CallMessage { txs }, &context, &mut working_set)
            .unwrap();

        evm.end_l2_block_hook(&l2_block_info, &mut working_set);
        evm.finalize_hook(&post_state_root, &mut working_set.accessory_state());

        commit(working_set, prover_storage.clone());
        pre_state_root = post_state_root;
    }

    let set_storage_tx_request = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(contract_address)),
        input: TransactionInput::new(contract.set_call_data(5).into()),
        ..Default::default()
    };

    // Helper functions to estimate gas and diff size at a given block tag.
    let estimate_at = |tag: BlockNumberOrTag| {
        evm.eth_estimate_gas_inner(
            set_storage_tx_request.clone(),
            Some(tag),
            None,
            &mut WorkingSet::new(prover_storage.clone()),
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap()
    };

    let diff_size_at = |tag: BlockNumberOrTag| {
        evm.eth_estimate_diff_size_inner(
            set_storage_tx_request.clone(),
            Some(tag),
            None,
            &mut WorkingSet::new(prover_storage.clone()),
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap()
    };

    // Helper function to manipulate safe and finalized tags to point to a given block number.
    let point_tag_at = |status: L2HeightStatus, l1_height: u64, height: u64| {
        ledger_db
            .set_l2_height_status(
                status,
                l1_height,
                L2HeightAndIndex {
                    height,
                    commitment_index: 1,
                },
            )
            .unwrap()
    };

    // A request for block N rewinds to archival version N + 1, which is right in production
    // where genesis is committed on its own. `init_evm` commits genesis together with block 1,
    // so every version here holds one block more: a request for block N observes the state
    // after block N + 1. That is why block 3 already sees the contract deployed in block 4.
    let no_contract = estimate_at(BlockNumberOrTag::Number(2));
    let slot_unset = estimate_at(BlockNumberOrTag::Number(3));
    let slot_set = estimate_at(BlockNumberOrTag::Latest);

    // No contract is just a plain call to an empty account. Beyond that, SSTORE is priced off the
    // slot's current value: overwriting one that already holds a value pays less than
    // writing one that is still zero (cold write).
    assert!(no_contract < slot_set);
    assert!(slot_set < slot_unset);
    // Other tags landing in the same states agree with them.
    assert_eq!(estimate_at(BlockNumberOrTag::Earliest), no_contract);
    assert_eq!(estimate_at(BlockNumberOrTag::Number(4)), slot_set);
    assert_eq!(estimate_at(BlockNumberOrTag::Pending), slot_set);

    let diff_no_contract = diff_size_at(BlockNumberOrTag::Number(2));
    let diff_slot_unset = diff_size_at(BlockNumberOrTag::Number(3));
    let diff_slot_set = diff_size_at(BlockNumberOrTag::Latest);

    // The same three-way split applies to the diff size's gas field.
    assert!(diff_no_contract.gas < diff_slot_set.gas);
    assert!(diff_slot_set.gas < diff_slot_unset.gas);

    // The diff size only splits two ways: touching no contract writes no storage, while writing
    // a slot costs the same diff whether or not it already held a value.
    assert!(diff_no_contract.l1_diff_size < diff_slot_unset.l1_diff_size);
    assert_eq!(diff_slot_unset.l1_diff_size, diff_slot_set.l1_diff_size);

    // Point safe tag to block 4, finalized tag to block 3
    // Safe should see the slot set, finalized should see the slot unset.
    point_tag_at(L2HeightStatus::Committed, 1, 4);
    point_tag_at(L2HeightStatus::Proven, 1, 3);

    assert_eq!(estimate_at(BlockNumberOrTag::Safe), slot_set);
    assert_eq!(estimate_at(BlockNumberOrTag::Finalized), slot_unset);
    assert_eq!(diff_size_at(BlockNumberOrTag::Safe), diff_slot_set);
    assert_eq!(diff_size_at(BlockNumberOrTag::Finalized), diff_slot_unset);
}

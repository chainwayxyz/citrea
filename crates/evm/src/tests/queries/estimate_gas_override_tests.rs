use std::str::FromStr;

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::map::{AddressMap, B256HashMap};
use alloy_primitives::{Address, TxKind, B256, U256};
use alloy_rpc_types::state::{AccountOverride, StateOverride};
use alloy_rpc_types::{TransactionInput, TransactionRequest};
use revm::primitives::KECCAK_EMPTY;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, WorkingSet};
use sov_rollup_interface::spec::SpecId as SovSpecId;

use super::get_test_seq_pub_key;
use crate::call::CallMessage;
use crate::smart_contracts::SimpleStorageContract;
use crate::tests::queries::{init_evm, init_evm_single_block};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{
    commit, create_contract_transaction, get_evm, get_evm_config, get_evm_with_storage,
    get_fork_fn_latest,
};
use crate::{AccountData, EvmConfig};

type C = DefaultContext;

#[test]
fn test_estimates_and_access_list_use_replacement_storage() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SovSpecId::latest());
    let address = signer.address().create(7);
    let request = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(address)),
        input: TransactionInput::new(SimpleStorageContract::default().set_call_data(478).into()),
        ..Default::default()
    };
    let block = Some(BlockNumberOrTag::Latest);
    let mut estimate = |state_overrides: Option<StateOverride>| {
        let gas = evm
            .eth_estimate_gas_inner(
                request.clone(),
                block,
                state_overrides.clone(),
                &mut working_set,
                &ledger_db,
                get_fork_fn_latest(),
            )
            .unwrap();
        let diff = evm
            .eth_estimate_diff_size_inner(
                request.clone(),
                block,
                state_overrides.clone(),
                &mut working_set,
                &ledger_db,
                get_fork_fn_latest(),
            )
            .unwrap();
        let access = evm
            .create_access_list_inner(
                request.clone(),
                block,
                state_overrides,
                &mut working_set,
                &ledger_db,
                get_fork_fn_latest(),
            )
            .unwrap();
        (gas, diff, access)
    };

    // Writing the stored value is a no-op. In a replacement with no slot 0, it initializes storage.
    let (original_gas, original_diff, original_access) = estimate(None);
    let replacement = AccountOverride::default().with_state([]);
    let (gas, diff, access) = estimate(Some(AddressMap::from_iter([(address, replacement)])));
    assert!(gas > original_gas);
    assert!(diff.gas > original_diff.gas);
    assert!(diff.l1_diff_size > original_diff.l1_diff_size);
    assert_eq!(access.access_list, original_access.access_list);
    assert!(access.gas_used > original_access.gas_used);
    assert_eq!(
        estimate(None),
        (original_gas, original_diff, original_access)
    );
}

#[test]
fn test_estimated_diff_size_treats_overridden_account_as_existing() {
    let (mut config, signer) = get_evm_config(U256::from(1_000_000_000_000_000_000_u128), None);
    let existing = Address::repeat_byte(0x41);
    let simulated = Address::repeat_byte(0x42);
    let balance = U256::from(10);
    config.data.push(AccountData::new(
        existing,
        balance,
        Default::default(),
        0,
        Default::default(),
    ));
    let (evm, mut working_set, _, ledger_db) = get_evm(&config);
    let mut estimate = |address, overrides| {
        evm.eth_estimate_diff_size_inner(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(address)),
                value: Some(U256::from(1)),
                ..Default::default()
            },
            Some(BlockNumberOrTag::Latest),
            overrides,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap()
        .l1_diff_size
    };

    let canonical = estimate(existing, None);
    let missing = estimate(simulated, None);
    let overrides =
        AddressMap::from_iter([(simulated, AccountOverride::default().with_balance(balance))]);
    assert!(missing > canonical);
    assert_eq!(estimate(simulated, Some(overrides)), canonical);
    assert_eq!(estimate(simulated, None), missing);
    assert!(!evm.account_exists(&simulated, &mut working_set));
}

/// Test eth_estimateGas with state overrides (storage only)
/// This test deploys a contract properly, then compares gas estimation
/// with and without storage overrides
#[test]
fn test_eth_estimate_gas_with_state_override() {
    let signer: TestSigner = TestSigner::new_default();

    let config = EvmConfig {
        data: vec![AccountData {
            address: signer.address(),
            balance: U256::from_str("100000000000000000000").unwrap(),
            code_hash: KECCAK_EMPTY,
            code: alloy_primitives::Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        ..Default::default()
    };

    let (mut evm, mut working_set, prover_storage, ledger_db) = get_evm_with_storage(&config);

    let l1_fee_rate = 1;
    let l2_height = 1;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [0u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let contract = SimpleStorageContract::default();
        let transactions = vec![create_contract_transaction(&signer, 0, contract)];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    let contract_address = signer.address().create(0);

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[2u8; 32], &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let mut working_set = WorkingSet::new(prover_storage);
    let contract = SimpleStorageContract::default();
    let input_data = contract.set_call_data(5);

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(contract_address)),
        gas: Some(100_000),
        gas_price: Some(100_000_000),
        input: TransactionInput::new(input_data.into()),
        ..Default::default()
    };

    // Estimate gas without storage override
    // This simulates calling set(5) on a contract where storage is empty
    let gas_without_storage_override = evm
        .eth_estimate_gas_inner(
            tx_req.clone(),
            Some(BlockNumberOrTag::Latest),
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    let mut state_override_with_storage = AddressMap::default();
    let storage: B256HashMap<B256> =
        vec![(B256::ZERO, B256::from(U256::from(100).to_be_bytes::<32>()))]
            .into_iter()
            .collect();

    state_override_with_storage.insert(
        contract_address,
        AccountOverride {
            state_diff: Some(storage),
            ..Default::default()
        },
    );

    // Estimate gas with storage override
    // This simulates calling set(5) on a contract where storage is not empty
    let gas_with_storage_override = evm
        .eth_estimate_gas_inner(
            tx_req,
            Some(BlockNumberOrTag::Latest),
            Some(state_override_with_storage),
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    assert_ne!(
        gas_without_storage_override, gas_with_storage_override,
        "Gas estimates should be different with storage overrides"
    );

    // Higher gas estimate is expected from initializing an empty storage
    assert!(
        gas_with_storage_override < gas_without_storage_override,
        "Gas with storage override should be less"
    );
}

/// Test eth_estimateGas with balance override
#[test]
fn test_eth_estimate_gas_with_balance_override() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    // Create a transaction that would fail because of insufficient balance
    let large_value = U256::from_str("999999999999999999999999999999").unwrap();

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
        )),
        value: Some(large_value),
        gas: Some(100_000),
        gas_price: Some(1_000_000_000),
        ..Default::default()
    };

    let result_without_override = evm.eth_estimate_gas_inner(
        tx_req.clone(),
        Some(BlockNumberOrTag::Latest),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert!(
        result_without_override.is_err(),
        "Should fail with insufficient funds"
    );

    // Create state override with sufficient balance
    let mut state_override = AddressMap::default();
    state_override.insert(
        signer.address(),
        AccountOverride {
            balance: Some(U256::from_str("2000000000000000000000000000000").unwrap()),
            ..Default::default()
        },
    );

    // With balance override, it should succeed
    let result_with_override = evm.eth_estimate_gas_inner(
        tx_req,
        Some(BlockNumberOrTag::Latest),
        Some(state_override),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert!(
        result_with_override.is_ok(),
        "Balance override should make transaction succeed, but got error: {:?}",
        result_with_override.unwrap_err()
    );
}

/// Test eth_estimateDiffSize with state overrides (storage only)
#[test]
fn test_eth_estimate_diff_size_with_state_override() {
    let signer: TestSigner = TestSigner::new_default();

    let config = EvmConfig {
        data: vec![AccountData {
            address: signer.address(),
            balance: U256::from_str("100000000000000000000").unwrap(),
            code_hash: KECCAK_EMPTY,
            code: alloy_primitives::Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        ..Default::default()
    };

    let (mut evm, mut working_set, prover_storage, ledger_db) = get_evm_with_storage(&config);

    let l1_fee_rate = 1;
    let l2_height = 1;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [0u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let contract = SimpleStorageContract::default();
        let transactions = vec![create_contract_transaction(&signer, 0, contract)];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    let contract_address = signer.address().create(0);

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[2u8; 32], &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let mut working_set = WorkingSet::new(prover_storage);
    let contract = SimpleStorageContract::default();
    let input_data = contract.set_call_data(5);

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(contract_address)),
        gas: Some(100_000),
        gas_price: Some(100_000_000),
        input: TransactionInput::new(input_data.into()),
        ..Default::default()
    };

    let diff_size_without_override = evm
        .eth_estimate_diff_size_inner(
            tx_req.clone(),
            Some(BlockNumberOrTag::Latest),
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    let mut state_override_with_storage = AddressMap::default();
    let storage: B256HashMap<B256> =
        vec![(B256::ZERO, B256::from(U256::from(100).to_be_bytes::<32>()))]
            .into_iter()
            .collect();

    state_override_with_storage.insert(
        contract_address,
        AccountOverride {
            state_diff: Some(storage),
            ..Default::default()
        },
    );

    let diff_size_with_override = evm
        .eth_estimate_diff_size_inner(
            tx_req,
            Some(BlockNumberOrTag::Latest),
            Some(state_override_with_storage),
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    assert_ne!(
        diff_size_without_override, diff_size_with_override,
        "Diff size estimates should differ with storage overrides"
    );

    // Writing to non-empty storage is cheaper (update vs. init)
    assert!(
        diff_size_with_override.gas < diff_size_without_override.gas,
        "Gas with storage override should be less"
    );
}

/// Test eth_estimateDiffSize with balance override
#[test]
fn test_eth_estimate_diff_size_with_balance_override() {
    let (evm, mut working_set, signer, ledger_db) =
        init_evm_single_block(sov_modules_api::SpecId::latest());

    let large_value = U256::from_str("999999999999999999999999999999").unwrap();

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
        )),
        value: Some(large_value),
        gas: Some(100_000),
        gas_price: Some(1_000_000_000),
        ..Default::default()
    };

    let result_without_override = evm.eth_estimate_diff_size_inner(
        tx_req.clone(),
        Some(BlockNumberOrTag::Latest),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert!(
        result_without_override.is_err(),
        "Should fail with insufficient funds"
    );

    let mut state_override = AddressMap::default();
    state_override.insert(
        signer.address(),
        AccountOverride {
            balance: Some(U256::from_str("2000000000000000000000000000000").unwrap()),
            ..Default::default()
        },
    );

    let result_with_override = evm.eth_estimate_diff_size_inner(
        tx_req,
        Some(BlockNumberOrTag::Latest),
        Some(state_override),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert!(
        result_with_override.is_ok(),
        "Balance override should make transaction succeed, but got error: {:?}",
        result_with_override.unwrap_err()
    );
}

/// Test eth_createAccessList with state overrides
#[test]
fn test_create_access_list_with_override() {
    let signer: TestSigner = TestSigner::new_default();

    let config = EvmConfig {
        data: vec![AccountData {
            address: signer.address(),
            balance: U256::from_str("100000000000000000000").unwrap(),
            code_hash: KECCAK_EMPTY,
            code: alloy_primitives::Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        ..Default::default()
    };

    let (mut evm, mut working_set, prover_storage, ledger_db) = get_evm_with_storage(&config);

    let l1_fee_rate = 1;
    let l2_height = 1;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [0u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let contract = SimpleStorageContract::default();
        let transactions = vec![create_contract_transaction(&signer, 0, contract)];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    let contract_address = signer.address().create(0);

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[2u8; 32], &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    // Create transaction to call set(42) on the deployed contract
    let mut working_set = WorkingSet::new(prover_storage);
    let contract = SimpleStorageContract::default();
    let input_data = contract.set_call_data(42);

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(contract_address)),
        gas: Some(100_000),
        gas_price: Some(100_000_000),
        input: TransactionInput::new(input_data.into()),
        ..Default::default()
    };

    // Create access list without storage override (storage is empty)
    let access_list_without = evm
        .create_access_list_inner(
            tx_req.clone(),
            Some(BlockNumberOrTag::Latest),
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    // Create state override with storage
    let mut state_override_with_storage = AddressMap::default();
    let storage: B256HashMap<B256> =
        vec![(B256::ZERO, B256::from(U256::from(99).to_be_bytes::<32>()))]
            .into_iter()
            .collect();

    state_override_with_storage.insert(
        contract_address,
        AccountOverride {
            state_diff: Some(storage),
            ..Default::default()
        },
    );

    // Create access list with storage override
    let access_list_with = evm
        .create_access_list_inner(
            tx_req,
            Some(BlockNumberOrTag::Latest),
            Some(state_override_with_storage),
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    assert_eq!(
        access_list_without.access_list, access_list_with.access_list,
        "Access lists should be the same"
    );

    assert!(
        access_list_with.gas_used != access_list_without.gas_used,
        "Gas used should differ due to storage state differences"
    );
}

use std::collections::BTreeMap;
use std::str::FromStr;

use alloy_eips::eip1559::ETHEREUM_BLOCK_GAS_LIMIT_30M;
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::map::AddressMap;
use alloy_primitives::{keccak256, Address, Bytes, TxKind, B256};
use alloy_rpc_types::state::{AccountOverride, StateOverride};
use alloy_rpc_types::{BlockId, BlockOverrides, TransactionInput, TransactionRequest};
use alloy_rpc_types_trace::geth::GethDebugTracingCallOptions;
use jsonrpsee::core::RpcResult;
use reth_rpc_eth_types::revm_utils::apply_state_overrides as apply_reth_state_overrides;
use reth_rpc_eth_types::{EthApiError, RpcInvalidTransactionError};
use revm::database::{CacheDB, EmptyDBTyped};
use revm::primitives::{BLOCK_HASH_HISTORY, U256};
use revm::Database;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, Spec, WorkingSet};
use sov_rollup_interface::spec::SpecId;

use crate::db::DBError;
use crate::smart_contracts::{BlockHashContract, SimpleStorageContract};
use crate::tests::get_test_seq_pub_key;
use crate::tests::queries::{init_evm, init_evm_single_block};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{
    commit, create_contract_message, get_evm, get_evm_config, get_evm_with_storage,
    get_fork_fn_latest, remove_native_header, set_arg_message,
};
use crate::{CallMessage, Evm, RpcGasCap, RPC_DEFAULT_GAS_CAP};

type C = DefaultContext;

#[test]
fn call_contract_without_value() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SpecId::latest());

    let contract = SimpleStorageContract::default();
    let contract_address = signer.address().create(7);

    let call_result = evm.get_call_inner(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(TxKind::Call(contract_address)),
            gas: Some(100000),
            gas_price: Some(100000000),
            value: None,
            input: TransactionInput::new(contract.set_call_data(5).into()),
            ..Default::default()
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(call_result.unwrap(), Bytes::from_str("0x").unwrap());

    let call_result = evm.get_call_inner(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(TxKind::Call(contract_address)),
            gas: Some(100000),
            gas_price: Some(100000000),
            value: None,
            input: TransactionInput::new(contract.get_call_data().into()),
            ..Default::default()
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(
        call_result.unwrap(),
        Bytes::from_str("0x00000000000000000000000000000000000000000000000000000000000001de")
            .unwrap()
    );
}

#[test]
fn test_state_change() {
    let (mut evm, mut working_set, _, signer, l2_height, ledger_db) = init_evm(SpecId::latest());

    let balance_1 = evm.get_balance(signer.address(), None, &mut working_set, &ledger_db);

    let random_address = Address::from_str("0x000000000000000000000000000000000000dead").unwrap();

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate: 1,
        timestamp: 0,
    };
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    let call_result = evm.get_call_inner(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(TxKind::Call(random_address)),
            gas: Some(100000),
            gas_price: Some(100000000),
            value: Some(U256::from(123134235)),
            ..Default::default()
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(call_result.unwrap(), Bytes::from_str("0x").unwrap());

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    let balance_2 = evm.get_balance(signer.address(), None, &mut working_set, &ledger_db);
    assert_eq!(balance_1, balance_2);
}

#[test]
fn call_contract_with_value_transfer() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SpecId::latest());

    let contract = SimpleStorageContract::default();
    let contract_address = signer.address().create(7);

    let call_result = evm.get_call_inner(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(TxKind::Call(contract_address)),
            gas: Some(100000),
            gas_price: Some(100000000),
            value: Some(U256::from(100000000)), // reverts here.
            input: TransactionInput::new(contract.set_call_data(5).into()),
            ..Default::default()
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert!(call_result.is_err());
}

#[test]
fn call_contract_with_invalid_nonce() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SpecId::latest());

    let contract = SimpleStorageContract::default();
    let contract_address = signer.address().create(7);

    let contract_call_data = contract.set_call_data(5);

    let invalid_nonce = 100u64;

    let call_result = evm.get_call_inner(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(TxKind::Call(contract_address)),
            gas: Some(100000),
            gas_price: Some(100000000),
            nonce: Some(invalid_nonce),
            input: TransactionInput::new(contract_call_data.clone().into()),
            ..Default::default()
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(call_result, Ok(Bytes::from_str("0x").unwrap()));

    let low_nonce = 2u64;

    let call_result = evm.get_call_inner(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(TxKind::Call(contract_address)),
            gas: Some(100000),
            gas_price: Some(100000000),
            nonce: Some(low_nonce),
            input: TransactionInput::new(contract_call_data.into()),
            ..Default::default()
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(call_result, Ok(Bytes::from_str("0x").unwrap()));
}

#[test]
fn call_to_nonexistent_contract() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SpecId::latest());

    let nonexistent_contract_address =
        Address::from_str("0x000000000000000000000000000000000000dead").unwrap();

    let call_result = evm.get_call_inner(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(TxKind::Call(nonexistent_contract_address)),
            gas: Some(100000),
            gas_price: Some(100000000),
            input: TransactionInput {
                input: None,
                data: None,
            },
            ..Default::default()
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(call_result.unwrap(), Bytes::from_str("0x").unwrap());
}

#[test]
fn call_with_high_gas_price() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SpecId::latest());

    let contract = SimpleStorageContract::default();
    let contract_address = signer.address().create(7);

    let high_gas_price = 1000u128 * 10_000_000_000_000_000_000_u128; // A very high gas price

    let call_result = evm.get_call_inner(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(TxKind::Call(contract_address)),
            gas: Some(100000),
            gas_price: Some(high_gas_price),
            input: TransactionInput::new(contract.set_call_data(5).into()),
            ..Default::default()
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(
        call_result,
        Err(RpcInvalidTransactionError::InsufficientFunds {
            cost: U256::from(1000000000000000000000000000u128),
            balance: U256::from(99999574234737852931u128)
        }
        .into())
    );
}

#[test]
fn test_eip1559_fields_call() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SpecId::latest());

    let default_result = eth_call_eip1559(
        &evm,
        &mut working_set,
        &ledger_db,
        &signer,
        Some(100e9 as _),
        Some(2e9 as _),
    );

    assert_eq!(
        default_result.unwrap().to_string(),
        "0x00000000000000000000000000000000000000000000000000000000000001de"
    );

    let high_fee_result = eth_call_eip1559(
        &evm,
        &mut working_set,
        &ledger_db,
        &signer,
        Some(u128::MAX),
        Some(u128::MAX),
    );
    assert_eq!(
        high_fee_result,
        Err(RpcInvalidTransactionError::InsufficientFunds {
            cost: U256::from_str("34028236692093846346337460743176821145500000").unwrap(),
            balance: U256::from(99999574234737852931u128)
        }
        .into())
    );

    let low_max_fee_result = eth_call_eip1559(
        &evm,
        &mut working_set,
        &ledger_db,
        &signer,
        Some(1),
        Some(1),
    );

    assert_eq!(
        low_max_fee_result,
        Err(RpcInvalidTransactionError::FeeCapTooLow.into())
    );

    let no_max_fee_per_gas = eth_call_eip1559(
        &evm,
        &mut working_set,
        &ledger_db,
        &signer,
        None,
        Some(2e9 as _),
    );
    assert_eq!(
        no_max_fee_per_gas,
        Ok(
            Bytes::from_str("0x00000000000000000000000000000000000000000000000000000000000001de")
                .unwrap()
        )
    );

    let no_priority_fee = eth_call_eip1559(
        &evm,
        &mut working_set,
        &ledger_db,
        &signer,
        Some(100e9 as _),
        None,
    );

    assert_eq!(
        no_priority_fee.unwrap().to_string(),
        "0x00000000000000000000000000000000000000000000000000000000000001de"
    );

    let none_res = eth_call_eip1559(&evm, &mut working_set, &ledger_db, &signer, None, None);

    assert_eq!(
        none_res.unwrap().to_string(),
        "0x00000000000000000000000000000000000000000000000000000000000001de"
    );
}

fn eth_call_eip1559(
    evm: &Evm<C>,
    working_set: &mut WorkingSet<<C as Spec>::Storage>,
    ledger_db: &LedgerDB,
    signer: &TestSigner,
    max_fee_per_gas: Option<u128>,
    max_priority_fee_per_gas: Option<u128>,
) -> RpcResult<Bytes> {
    let contract = SimpleStorageContract::default();

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(signer.address().create(7))),
        gas: Some(100_000),
        gas_price: None,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        value: None,
        input: TransactionInput::new(contract.get_call_data().into()),
        nonce: Some(9u64),
        chain_id: Some(1u64),
        ..Default::default()
    };

    evm.get_call_inner(
        tx_req,
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        working_set,
        ledger_db,
        get_fork_fn_latest(),
    )
}

#[test]
fn gas_price_call_test() {
    let (evm, mut working_set, signer, ledger_db) = init_evm_single_block(SpecId::latest());

    // Define a base transaction request for reuse
    let base_tx_req = || TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(signer.address().create(0))),
        value: Some(U256::from(1000)),
        input: None.into(),
        nonce: Some(1u64),
        chain_id: Some(1u64),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        transaction_type: None,
        sidecar: None,
        // Gas, gas_price, max_fee_per_gas, and max_priority_fee_per_gas will be varied
        gas: None,
        gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        authorization_list: None,
    };

    // Test with low gas limit
    let tx_req_low_gas = base_tx_req();
    let result_low_gas = evm.get_call_inner(
        TransactionRequest {
            gas: Some(21000),
            ..tx_req_low_gas
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(
        result_low_gas,
        Err(RpcInvalidTransactionError::BasicOutOfGas(21000).into())
    );
    working_set.unset_archival_version();

    let tx_req_only_gas = base_tx_req();
    let result_only_gas = evm.get_call_inner(
        TransactionRequest {
            gas: Some(250000),
            ..tx_req_only_gas
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(result_only_gas, Ok(Bytes::new()));
    working_set.unset_archival_version();

    // Test with gas and gas_price specified - error
    let tx_req_gas_and_gas_price = base_tx_req();
    let result_gas_and_gas_price = evm.get_call_inner(
        TransactionRequest {
            gas: Some(25000),
            gas_price: Some(20e9 as _),
            ..tx_req_gas_and_gas_price
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(
        result_gas_and_gas_price,
        Err(RpcInvalidTransactionError::BasicOutOfGas(25000).into())
    );
    working_set.unset_archival_version();

    // Test with gas and gas_price specified - this time successful
    let tx_req_gas_and_gas_price = base_tx_req();
    let result_gas_and_gas_price = evm.get_call_inner(
        TransactionRequest {
            gas: Some(250000),
            gas_price: Some(20e9 as _),
            ..tx_req_gas_and_gas_price
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(result_gas_and_gas_price, Ok(Bytes::new()));
    working_set.unset_archival_version();

    // Test with max_fee_per_gas and max_priority_fee_per_gas specified
    let tx_req_fees = base_tx_req();
    let result_fees = evm.get_call_inner(
        TransactionRequest {
            max_fee_per_gas: Some(30e9 as _),
            max_priority_fee_per_gas: Some(10e9 as _),
            ..tx_req_fees
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert!(result_fees.is_ok());
    working_set.unset_archival_version();

    // Test with extremely high gas price
    // Should pass bc gas is sensible
    let tx_req_high_gas_price = base_tx_req();
    let result_high_gas_price = evm.get_call_inner(
        TransactionRequest {
            gas_price: Some(1e12 as _),
            gas: Some(250000),
            ..tx_req_high_gas_price
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert!(result_high_gas_price.is_ok());
    working_set.unset_archival_version();

    // Test with extremely high gas price
    // Will pass gas is not given
    // Which will be capped to max gas the wallet can afford
    let tx_req_high_gas_price = base_tx_req();
    let result_high_gas_price = evm.get_call_inner(
        TransactionRequest {
            gas_price: Some(1e12 as _),
            ..tx_req_high_gas_price
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert!(result_high_gas_price.is_ok());
    working_set.unset_archival_version();

    // Test with extremely high max_fee_per_gas and max_priority_fee_per_gas
    let tx_req_high_fees = base_tx_req();
    let result_high_fees = evm.get_call_inner(
        TransactionRequest {
            max_fee_per_gas: Some(1e12 as _),
            max_priority_fee_per_gas: Some(500e9 as _),
            ..tx_req_high_fees
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert!(result_high_fees.is_ok());
    working_set.unset_archival_version();
}

#[test]
fn test_call_with_state_overrides() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SpecId::latest());

    let contract = SimpleStorageContract::default();
    let contract_address = signer.address().create(7);

    let request = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(contract_address)),
        input: TransactionInput::new(contract.get_call_data().into()),
        ..Default::default()
    };
    let other_slot = B256::repeat_byte(0xAB);
    for (case, account_override, expected) in [
        ("canonical storage", None, 478),
        (
            "replacement value",
            Some(AccountOverride::default().with_state([(B256::ZERO, U256::from(15).into())])),
            15,
        ),
        (
            "nonempty replacement omits a canonical slot",
            Some(AccountOverride::default().with_state([(other_slot, U256::from(19).into())])),
            0,
        ),
        (
            "empty replacement",
            Some(AccountOverride::default().with_state([])),
            0,
        ),
        (
            "empty diff",
            Some(AccountOverride::default().with_state_diff([])),
            478,
        ),
        (
            "diff value",
            Some(AccountOverride::default().with_state_diff([(B256::ZERO, U256::from(23).into())])),
            23,
        ),
        (
            "diff omits the previous call's slot",
            Some(AccountOverride::default().with_state_diff([(other_slot, U256::from(19).into())])),
            478,
        ),
        (
            "diff explicitly sets zero",
            Some(AccountOverride::default().with_state_diff([(B256::ZERO, B256::ZERO)])),
            0,
        ),
        ("canonical storage after overrides", None, 478),
    ] {
        let overrides =
            account_override.map(|account| AddressMap::from_iter([(contract_address, account)]));
        let mut reth_db = CacheDB::new(EmptyDBTyped::<DBError>::new());
        reth_db
            .insert_account_storage(contract_address, U256::ZERO, U256::from(478))
            .unwrap();
        if let Some(overrides) = overrides.clone() {
            apply_reth_state_overrides(overrides, &mut reth_db).unwrap();
        }
        assert_eq!(
            reth_db.storage(contract_address, U256::ZERO).unwrap(),
            U256::from(expected),
            "Reth: {case}"
        );
        let result = evm
            .get_call_inner(
                request.clone(),
                None,
                overrides,
                None,
                &mut working_set,
                &ledger_db,
                get_fork_fn_latest(),
            )
            .unwrap();
        assert_eq!(result, U256::from(expected).to_be_bytes_vec(), "{case}");
    }
}

#[test]
fn test_call_with_code_override() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SpecId::latest());
    let address = Address::repeat_byte(0x42);
    let request = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(address)),
        ..Default::default()
    };
    // Return 42 as a single byte.
    let code = Bytes::from_static(&[0x60, 0x2a, 0x5f, 0x53, 0x60, 0x01, 0x5f, 0xf3]);
    let code_hash = keccak256(&code);
    let overrides = AddressMap::from_iter([(address, AccountOverride::default().with_code(code))]);
    for (overrides, expected) in [
        (None, Bytes::new()),
        (Some(overrides), Bytes::from_static(&[42])),
        (None, Bytes::new()),
    ] {
        let result = evm
            .get_call_inner(
                request.clone(),
                None,
                overrides,
                None,
                &mut working_set,
                &ledger_db,
                get_fork_fn_latest(),
            )
            .unwrap();
        assert_eq!(result, expected);
    }
    assert_eq!(
        evm.get_db(&mut working_set, SpecId::latest())
            .code_by_hash(code_hash),
        Err(DBError::UnknownCodeHash)
    );
}

#[test]
fn test_call_rejects_conflicting_storage_overrides() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SpecId::latest());
    let address = signer.address().create(7);
    let code = Bytes::from_static(&[0x60, 0x2b, 0x50, 0x00]);
    let code_hash = keccak256(&code);
    let invalid = AccountOverride::default()
        .with_state([])
        .with_state_diff([])
        .with_code(code);
    let err = evm
        .get_call_inner(
            TransactionRequest {
                to: Some(TxKind::Call(address)),
                ..Default::default()
            },
            None,
            Some(StateOverride::from_iter([(address, invalid)])),
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap_err();
    let expected = EthApiError::BothStateAndStateDiffInOverride(address);
    assert_eq!(err.code(), -32602);
    assert_eq!(err.message(), expected.to_string());
    assert_eq!(
        evm.get_db(&mut working_set, SpecId::latest())
            .code_by_hash(code_hash),
        Err(DBError::UnknownCodeHash)
    );
}

#[test]
fn test_call_override_failure_leaves_account_untouched() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SpecId::latest());
    let address = signer.address().create(7);
    let request = TransactionRequest {
        to: Some(TxKind::Call(address)),
        input: TransactionInput::new(SimpleStorageContract::default().get_call_data().into()),
        ..Default::default()
    };
    let mut call = |account: Option<AccountOverride>| {
        evm.get_call_inner(
            request.clone(),
            None,
            account.map(|account| StateOverride::from_iter([(address, account)])),
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
    };

    let malformed = AccountOverride::default().with_code(Bytes::from_static(&[0xef, 0x01]));
    for override_account in [
        malformed.clone(),
        malformed.with_state([]).with_state_diff([]),
    ] {
        let invalid_params = call(Some(override_account)).unwrap_err();
        assert_eq!(invalid_params.code(), -32602);
        assert!(invalid_params.message().starts_with("Invalid bytecode:"));
    }

    // The replacement writes slot 0 and reverts. Neither the override nor its writes survive.
    let revert = AccountOverride::default()
        .with_code(Bytes::from_static(&[
            0x60, 0x01, 0x5f, 0x55, 0x5f, 0x5f, 0xfd,
        ]))
        .with_state_diff([(B256::ZERO, U256::from(37).into())]);
    let reverted = call(Some(revert)).unwrap_err();
    assert!(reverted.message().contains("execution reverted"));
    assert_eq!(call(None).unwrap(), U256::from(478).to_be_bytes_vec());

    let empty_code = AccountOverride::default().with_code(Bytes::new());
    assert!(call(Some(empty_code)).unwrap().is_empty());
    assert_eq!(call(None).unwrap(), U256::from(478).to_be_bytes_vec());
}

#[test]
fn test_historical_call_overrides_use_selected_state() {
    let (config, signer) = get_evm_config(U256::from(1_000_000_000_000_000_000_u128), None);
    let (mut evm, working_set, storage, ledger_db) = get_evm_with_storage(&config);
    let mut root = commit(working_set, storage.clone());
    let address = signer.address().create(0);
    let spec = SpecId::latest();
    for (height, nonce, value) in [(1, 1, 11), (2, 2, 22)] {
        let mut working_set = WorkingSet::new(storage.clone());
        let block_info = HookL2BlockInfo {
            l2_height: height,
            pre_state_root: root,
            current_spec: spec,
            sequencer_pub_key: get_test_seq_pub_key(),
            l1_fee_rate: 0,
            timestamp: height,
        };
        let context = C::new(generate_address::<C>("sender"), height, spec, 0);
        let mut txs = vec![];
        if height == 1 {
            txs.push(create_contract_message(
                &signer,
                0,
                SimpleStorageContract::default(),
            ));
        }
        txs.push(set_arg_message(address, &signer, nonce, value));
        evm.begin_l2_block_hook(&block_info, &mut working_set);
        evm.call(CallMessage { txs }, &context, &mut working_set)
            .unwrap();
        evm.end_l2_block_hook(&block_info, &mut working_set);
        let mut working_set = working_set.checkpoint().to_revertable();
        evm.finalize_hook(&[height as u8; 32], &mut working_set.accessory_state());
        root = commit(working_set, storage.clone());
    }

    let mut working_set = WorkingSet::new(storage);
    let mut call = |block: BlockNumberOrTag, account: Option<AccountOverride>| {
        let result = evm
            .get_call_inner(
                TransactionRequest {
                    to: Some(TxKind::Call(address)),
                    input: TransactionInput::new(
                        SimpleStorageContract::default().get_call_data().into(),
                    ),
                    ..Default::default()
                },
                Some(block.into()),
                account.map(|account| StateOverride::from_iter([(address, account)])),
                None,
                &mut working_set,
                &ledger_db,
                get_fork_fn_latest(),
            )
            .unwrap();
        working_set.unset_archival_version();
        U256::from_be_slice(&result)
    };
    let historical = BlockNumberOrTag::Number(1);
    let latest = BlockNumberOrTag::Latest;
    let other_slot = [(B256::repeat_byte(0xFF), U256::from(99).into())];
    assert_eq!(call(historical, None), U256::from(11));
    assert_eq!(call(latest, None), U256::from(22));
    assert_eq!(
        call(
            historical,
            Some(AccountOverride::default().with_state_diff(other_slot))
        ),
        U256::from(11)
    );
    assert_eq!(
        call(
            historical,
            Some(AccountOverride::default().with_state(other_slot))
        ),
        U256::ZERO
    );
    assert_eq!(call(historical, None), U256::from(11));
    assert_eq!(call(latest, None), U256::from(22));
}

#[test]
fn test_call_with_block_overrides() {
    let (config, dev_signer) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let contract_addr = dev_signer.address().create(0);

    let (mut evm, mut working_set, _spec_id, ledger_db) = get_evm(&config);
    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    // Deploy block hashes contract
    let sender_address = generate_address::<C>("sender");
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let context = DefaultContext::new(sender_address, l2_height, SpecId::latest(), l1_fee_rate);

        let deploy_message = create_contract_message(&dev_signer, 0, BlockHashContract::default());

        evm.call(
            CallMessage {
                txs: vec![deploy_message],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());
    l2_height += 1;

    // Create empty EVM blocks
    for _i in 0..10 {
        let l1_fee_rate = 0;
        let l2_block_info = HookL2BlockInfo {
            l2_height,
            pre_state_root: [99u8; 32],
            current_spec: SpecId::latest(),
            sequencer_pub_key: get_test_seq_pub_key(),
            l1_fee_rate,
            timestamp: 0,
        };

        evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
        evm.end_l2_block_hook(&l2_block_info, &mut working_set);
        evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

        l2_height += 1;
    }

    // Construct block override with custom hashes
    let mut block_hashes = BTreeMap::new();
    block_hashes.insert(1, [1; 32].into());
    block_hashes.insert(2, [2; 32].into());

    // Call with block overrides and check that the hash for 1st block is what we want
    let call_result = evm
        .get_call_inner(
            TransactionRequest {
                from: None,
                to: Some(TxKind::Call(contract_addr)),
                input: TransactionInput::new(BlockHashContract::default().get_block_hash(1).into()),
                ..Default::default()
            },
            None,
            None,
            Some(BlockOverrides {
                number: None,
                difficulty: None,
                time: None,
                gas_limit: None,
                coinbase: None,
                random: None,
                base_fee: None,
                block_hash: Some(block_hashes.clone()),
            }),
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    let expected_hash = Bytes::from_iter([1; 32]);
    assert_eq!(call_result, expected_hash);

    // Call with block overrides and check that the hash for 2nd block is what we want
    let call_result = evm
        .get_call_inner(
            TransactionRequest {
                from: None,
                to: Some(TxKind::Call(contract_addr)),
                input: TransactionInput::new(BlockHashContract::default().get_block_hash(2).into()),
                ..Default::default()
            },
            None,
            None,
            Some(BlockOverrides {
                number: None,
                difficulty: None,
                time: None,
                gas_limit: None,
                coinbase: None,
                random: None,
                base_fee: None,
                block_hash: Some(block_hashes),
            }),
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();
    let expected_hash = Bytes::from_iter([2; 32]);
    assert_eq!(call_result, expected_hash);
}

/// A `number` override moves the `BLOCKHASH` window. Unsupplied hashes come from retained state
/// or canonical headers and resolve to zero when unavailable.
#[test]
fn test_call_block_hash_overrides_by_height() {
    // Blocks 0..=3; at the head's state the ring buffer holds the hashes of blocks 0..=2.
    let (evm, mut working_set, storage, signer, _, ledger_db) = init_evm(SpecId::latest());
    let latest = evm.last_sealed_header(&mut working_set).number;
    assert_eq!(latest, 3);
    let canonical: Vec<B256> = (0..=latest)
        .map(|n| evm.block_hash_from_number(n, &mut working_set).unwrap())
        .collect();

    // Pruning removes native block entries independently of hashes in retained EVM state.
    remove_native_header(&evm, 1, &mut working_set);
    assert_eq!(evm.block_hash_from_number(1, &mut working_set), None);

    // PUSH1 0, CALLDATALOAD, BLOCKHASH, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
    let reader = Address::repeat_byte(0xB1);
    let reader_code = Bytes::from_static(&[
        0x60, 0x00, 0x35, 0x40, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
    ]);
    let state =
        AddressMap::from_iter([(reader, AccountOverride::default().with_code(reader_code))]);
    let request = |height| TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(reader)),
        input: TransactionInput::new(U256::from(height).to_be_bytes_vec().into()),
        ..Default::default()
    };
    let mut blockhash =
        |block: BlockNumberOrTag, overrides: Option<BlockOverrides>, height: u64| {
            let output = evm
                .get_call_inner(
                    request(height),
                    Some(BlockId::Number(block)),
                    Some(state.clone()),
                    overrides,
                    &mut working_set,
                    &ledger_db,
                    get_fork_fn_latest(),
                )
                .unwrap();
            B256::from_slice(&output)
        };
    let at_height = |number: u64| BlockOverrides {
        number: Some(U256::from(number)),
        ..Default::default()
    };
    let latest_tag = BlockNumberOrTag::Latest;

    // A hash supplied for height 257 must not replace block 1's, which shares its ring-buffer slot.
    let supplied = BlockOverrides {
        block_hash: Some(BTreeMap::from([(257, B256::repeat_byte(0xAA))])),
        ..Default::default()
    };
    assert_eq!(blockhash(latest_tag, Some(supplied), 1), canonical[1]);

    let explicit_zero = BlockOverrides {
        block_hash: Some(BTreeMap::from([(1, B256::ZERO)])),
        ..Default::default()
    };
    assert_eq!(blockhash(latest_tag, Some(explicit_zero), 1), B256::ZERO);
    assert_eq!(blockhash(latest_tag, None, 1), canonical[1]);

    // The retained hash is visible with both an unchanged and a shifted block number.
    assert_eq!(
        blockhash(latest_tag, Some(at_height(latest)), 1),
        canonical[1]
    );
    assert_eq!(blockhash(latest_tag, Some(at_height(257)), 1), canonical[1]);

    // Window [2, 258): heights up to the head are canonical, later ones are zero.
    assert_eq!(blockhash(latest_tag, Some(at_height(258)), 2), canonical[2]);
    assert_eq!(
        blockhash(latest_tag, Some(at_height(258)), latest),
        canonical[3]
    );
    assert_eq!(
        blockhash(latest_tag, Some(at_height(258)), latest + 1),
        B256::ZERO
    );
    // 257 shares a slot with block 1.
    assert_eq!(blockhash(latest_tag, Some(at_height(258)), 257), B256::ZERO);

    // A supplied hash still wins inside a moved window.
    let supplied_at_height = BlockOverrides {
        block_hash: Some(BTreeMap::from([(100, B256::repeat_byte(0xBB))])),
        ..at_height(258)
    };
    assert_eq!(
        blockhash(latest_tag, Some(supplied_at_height), 100),
        B256::repeat_byte(0xBB)
    );

    let number = BLOCK_HASH_HISTORY + 2;
    let hashes = BlockOverrides {
        block_hash: Some(BTreeMap::from([
            (1, B256::repeat_byte(1)),
            (2, B256::repeat_byte(2)),
            (number - 1, B256::repeat_byte(3)),
            (number, B256::repeat_byte(4)),
            (number + 1, B256::repeat_byte(5)),
        ])),
        ..at_height(number)
    };
    for (height, expected) in [
        (1, B256::ZERO),
        (2, B256::repeat_byte(2)),
        (number - 1, B256::repeat_byte(3)),
        (number, B256::ZERO),
        (number + 1, B256::ZERO),
    ] {
        assert_eq!(
            blockhash(latest_tag, Some(hashes.clone()), height),
            expected,
            "height {height}"
        );
    }

    // On the pending block, the head is the last canonical height.
    let pending = BlockNumberOrTag::Pending;
    assert_eq!(
        blockhash(pending, Some(at_height(258)), latest),
        canonical[3]
    );
    assert_eq!(
        blockhash(pending, Some(at_height(258)), latest + 1),
        B256::ZERO
    );
    let parent_override = BlockOverrides {
        block_hash: Some(BTreeMap::from([(latest, B256::ZERO)])),
        ..Default::default()
    };
    assert_eq!(
        blockhash(pending, Some(parent_override), latest),
        B256::ZERO
    );
    assert_eq!(blockhash(pending, None, latest), canonical[3]);

    // Reth reads canonical hashes independently of the historical account and storage snapshot.
    let historical = BlockNumberOrTag::Earliest;
    assert_eq!(blockhash(historical, Some(at_height(258)), 2), canonical[2]);
    assert_eq!(blockhash(historical, Some(at_height(258)), 3), canonical[3]);
    assert_eq!(blockhash(historical, Some(at_height(258)), 4), B256::ZERO);

    for block in [pending, historical] {
        let trace = evm
            .debug_trace_call(
                request(latest),
                Some(block.into()),
                Some(GethDebugTracingCallOptions {
                    state_overrides: Some(state.clone()),
                    block_overrides: Some(at_height(258)),
                    ..Default::default()
                }),
                &mut WorkingSet::new(storage.clone()),
                &ledger_db,
                512,
            )
            .unwrap()
            .try_into_default_frame()
            .unwrap();
        assert_eq!(trace.return_value.as_ref(), canonical[3].as_slice());
    }
}

/// `eth_call` and `debug_traceCall` are bounded by the RPC gas cap (default 100M), not the block
/// gas limit, which also bounds how far one call can expand EVM memory (one `MSTORE` at a
/// multi-MiB offset). Here the request gas and a block override both ask for `u64::MAX`; the call
/// must still be rejected for lack of gas - capped to the RPC gas cap - rather than allocate
/// 32 MiB.
#[test]
fn gas_cap_bounds_memory_expansion() {
    let (evm, mut working_set, _, _signer, _, ledger_db) = init_evm(SpecId::latest());
    // The default cap is explicit and cannot be changed by other in-process tests.

    // PUSH1 1, PUSH4 0x02000000 (32 MiB), MSTORE, STOP. Expanding EVM memory to 32 MiB costs
    // ~2.4e9 gas: affordable under a u64::MAX limit but far above the 100M RPC gas cap.
    let expander = Address::from([0xAA; 20]);
    // PUSH1 1, PUSH1 0, MSTORE, STOP: a cheap store at offset 0.
    let benign = Address::from([0xBB; 20]);
    let mut overrides = AddressMap::<AccountOverride>::default();
    overrides.insert(
        expander,
        AccountOverride {
            code: Some(Bytes::from(vec![
                0x60, 0x01, 0x63, 0x02, 0x00, 0x00, 0x00, 0x52, 0x00,
            ])),
            ..Default::default()
        },
    );
    overrides.insert(
        benign,
        AccountOverride {
            code: Some(Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x52, 0x00])),
            ..Default::default()
        },
    );

    let block_gas_limit_override = |gas_limit: u64| BlockOverrides {
        gas_limit: Some(gas_limit),
        ..Default::default()
    };

    // Raise both the block gas limit and the request gas to u64::MAX. The 32 MiB memory
    // expansion must be rejected for lack of gas - capped to the RPC gas cap - instead of allocated.
    let capped = evm.get_call_inner(
        TransactionRequest {
            to: Some(TxKind::Call(expander)),
            gas: Some(u64::MAX),
            ..Default::default()
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        Some(overrides.clone()),
        Some(block_gas_limit_override(u64::MAX)),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    let err = capped.expect_err("call must be capped to the RPC gas cap");
    assert!(
        err.message().contains("gas"),
        "expected an out-of-gas error, got: {err:?}"
    );

    // The override path still works: a cheap call with a lowered block gas limit succeeds.
    let ok = evm.get_call_inner(
        TransactionRequest {
            to: Some(TxKind::Call(benign)),
            gas: Some(100_000),
            ..Default::default()
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        Some(overrides),
        Some(block_gas_limit_override(1_000_000)),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(ok.unwrap(), Bytes::from_str("0x").unwrap());
}

/// The RPC gas cap is decoupled from the block gas limit: a read-only call may consume more gas
/// than a block, up to the cap. A call needing ~76M gas succeeds under the default 100M cap even
/// though the block gas limit is 30M, and is rejected once the cap is lowered below what it needs.
#[test]
fn call_gas_cap_allows_running_above_block_gas_limit() {
    let (evm, mut working_set, _, _signer, _, ledger_db) = init_evm(SpecId::latest());

    // PUSH1 1, PUSH4 0x00600000 (6 MiB), MSTORE, STOP. Expanding EVM memory to ~6 MiB costs ~76M
    // gas: above the 30M block gas limit but below the 100M RPC gas cap.
    let heavy = Address::from([0xCC; 20]);
    let mut overrides = AddressMap::<AccountOverride>::default();
    overrides.insert(
        heavy,
        AccountOverride {
            code: Some(Bytes::from(vec![
                0x60, 0x01, 0x63, 0x00, 0x60, 0x00, 0x00, 0x52, 0x00,
            ])),
            ..Default::default()
        },
    );
    let request = || TransactionRequest {
        to: Some(TxKind::Call(heavy)),
        ..Default::default()
    };

    // Under the default 100M cap the call runs above the 30M block gas limit and succeeds.
    let ok = evm.get_call_inner(
        request(),
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        Some(overrides.clone()),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(
        ok.expect("a ~76M gas call must succeed under the 100M gas cap"),
        Bytes::from_str("0x").unwrap()
    );

    // Lower the cap below what the call needs: it is now rejected for lack of gas.
    let capped = evm.get_call_inner_with_gas_cap(
        request(),
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        Some(overrides),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
        RpcGasCap::new(30_000_000),
    );
    // No shared cap needs restoring before other in-process tests run.
    let err = capped.expect_err("call above the lowered gas cap must run out of gas");
    assert!(
        err.message().contains("gas"),
        "expected an out-of-gas error, got: {err:?}"
    );
}

/// The `GASLIMIT` opcode in a call reports the real block gas limit, not the RPC gas cap, so the
/// simulated block context matches the chain (as geth and reth do). A block override may still
/// lower that value but, per the kept `apply_block_overrides` clamp, never raise it.
#[test]
fn block_override_cannot_raise_the_block_gas_limit() {
    let (evm, mut working_set, _, _signer, _, ledger_db) = init_evm(SpecId::latest());

    // GASLIMIT, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN: returns the block gas limit the EVM
    // sees as a 32-byte word.
    let reporter = Address::from([0xDD; 20]);
    let mut overrides = AddressMap::<AccountOverride>::default();
    overrides.insert(
        reporter,
        AccountOverride {
            code: Some(Bytes::from(vec![
                0x45, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
            ])),
            ..Default::default()
        },
    );

    let gas_limit_seen = |working_set: &mut WorkingSet<<C as Spec>::Storage>,
                          block_override: Option<BlockOverrides>| {
        let out = evm
            .get_call_inner(
                TransactionRequest {
                    to: Some(TxKind::Call(reporter)),
                    ..Default::default()
                },
                Some(BlockId::Number(BlockNumberOrTag::Latest)),
                Some(overrides.clone()),
                block_override,
                working_set,
                &ledger_db,
                get_fork_fn_latest(),
            )
            .unwrap();
        U256::from_be_slice(&out)
    };

    let real = gas_limit_seen(&mut working_set, None);
    // With no override the EVM reports the real block gas limit (30M), not the 100M RPC gas cap.
    assert_eq!(real, U256::from(ETHEREUM_BLOCK_GAS_LIMIT_30M));
    assert_ne!(real, U256::from(RPC_DEFAULT_GAS_CAP));
    // A u64::MAX override must not raise the block gas limit the EVM reports above its real value.
    let raised = gas_limit_seen(
        &mut working_set,
        Some(BlockOverrides {
            gas_limit: Some(u64::MAX),
            ..Default::default()
        }),
    );
    assert_eq!(
        raised, real,
        "override must not raise the block gas limit above its real value"
    );
    // But a smaller override may still lower it.
    let lowered = gas_limit_seen(
        &mut working_set,
        Some(BlockOverrides {
            gas_limit: Some(1_000_000),
            ..Default::default()
        }),
    );
    assert_eq!(lowered, U256::from(1_000_000u64));
    assert!(
        real > U256::from(1_000_000u64),
        "the cap should exceed the lowered override"
    );
}

/// A block override affects only the `GASLIMIT` opcode, not how much gas the call may burn - that
/// ceiling is the RPC gas cap, as in geth. A ~76M gas call runs under the 100M cap even with an
/// override lowering the block gas limit to 30M; only lowering the cap itself rejects it.
#[test]
fn block_override_does_not_bound_the_call_gas() {
    let (evm, mut working_set, _, _signer, _, ledger_db) = init_evm(SpecId::latest());

    // PUSH1 1, PUSH4 0x00600000 (6 MiB), MSTORE, STOP: expanding EVM memory to ~6 MiB costs ~76M
    // gas, above the 30M override but below the 100M cap.
    let heavy = Address::from([0xCC; 20]);
    let mut overrides = AddressMap::<AccountOverride>::default();
    overrides.insert(
        heavy,
        AccountOverride {
            code: Some(Bytes::from(vec![
                0x60, 0x01, 0x63, 0x00, 0x60, 0x00, 0x00, 0x52, 0x00,
            ])),
            ..Default::default()
        },
    );
    let request = || TransactionRequest {
        to: Some(TxKind::Call(heavy)),
        ..Default::default()
    };

    // No override: the call runs under the 100M cap.
    let ok = evm.get_call_inner(
        request(),
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        Some(overrides.clone()),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(
        ok.expect("the call should run under the 100M cap"),
        Bytes::from_str("0x").unwrap()
    );

    // A block override lowering the block gas limit to 30M does NOT bound the ~76M call: it only
    // changes the `GASLIMIT` opcode, so the call still runs under the 100M cap.
    let still_ok = evm.get_call_inner(
        request(),
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        Some(overrides.clone()),
        Some(BlockOverrides {
            gas_limit: Some(30_000_000),
            ..Default::default()
        }),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(
        still_ok.expect("a block override must not bound the call's gas"),
        Bytes::from_str("0x").unwrap()
    );

    // Lowering the RPC gas cap itself to 30M, on the other hand, does reject the ~76M call.
    let capped = evm.get_call_inner_with_gas_cap(
        request(),
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        Some(overrides),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
        RpcGasCap::new(30_000_000),
    );
    let err = capped.expect_err("call above the lowered gas cap must run out of gas");
    assert!(
        err.message().contains("gas"),
        "expected an out-of-gas error, got: {err:?}"
    );
}

// TODO: add eth_call with authorization list

// TODO: add eth_estimateGas with authorization list

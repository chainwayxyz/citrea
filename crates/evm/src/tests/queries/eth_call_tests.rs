use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

use alloy_eips::eip1559::ETHEREUM_BLOCK_GAS_LIMIT_30M;
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::map::AddressMap;
use alloy_primitives::{Address, Bytes, TxKind, B256};
use alloy_rpc_types::state::AccountOverride;
use alloy_rpc_types::{BlockId, BlockOverrides, TransactionInput, TransactionRequest};
use jsonrpsee::core::RpcResult;
use reth_rpc_eth_types::RpcInvalidTransactionError;
use revm::primitives::U256;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, Spec, WorkingSet};
use sov_rollup_interface::spec::SpecId;

use crate::smart_contracts::{BlockHashContract, SimpleStorageContract};
use crate::tests::get_test_seq_pub_key;
use crate::tests::queries::{init_evm, init_evm_single_block};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{create_contract_message, get_evm, get_evm_config, get_fork_fn_latest};
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
    let (evm, mut working_set, prover_storage, signer, _, ledger_db) = init_evm(SpecId::latest());

    let contract = SimpleStorageContract::default();
    let contract_address = signer.address().create(7);

    // Get value of contract before state override
    let call_result_without_state_override = evm
        .get_call_inner(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(contract_address)),
                input: TransactionInput::new(contract.get_call_data().into()),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    assert_eq!(
        call_result_without_state_override,
        U256::from(478).to_be_bytes_vec()
    );

    // Override the state and check returned value
    let mut state: HashMap<B256, B256, alloy_primitives::map::FbBuildHasher<32>> =
        HashMap::with_hasher(alloy_primitives::map::FbBuildHasher::default());
    state.insert(U256::from(0).into(), U256::from(15).into());

    let mut state_override: HashMap<
        Address,
        AccountOverride,
        alloy_primitives::map::FbBuildHasher<20>,
    > = HashMap::with_hasher(alloy_primitives::map::FbBuildHasher::default());
    state_override.insert(
        contract_address,
        AccountOverride {
            balance: None,
            nonce: None,
            code: None,
            state: Some(state),
            state_diff: None,
            move_precompile_to: None,
        },
    );
    let call_result_with_state_override = evm
        .get_call_inner(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(contract_address)),
                input: TransactionInput::new(contract.get_call_data().into()),
                ..Default::default()
            },
            None,
            Some(state_override),
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    assert_eq!(
        call_result_with_state_override,
        U256::from(15).to_be_bytes_vec()
    );

    // Start with a fresh working set, because the previous one was for a separate RPC call.
    let mut working_set = WorkingSet::new(prover_storage);

    // Get value of contract AFTER state override, this MUST be the original value.
    let call_result_without_state_override = evm
        .get_call_inner(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(contract_address)),
                input: TransactionInput::new(contract.get_call_data().into()),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    assert_eq!(
        call_result_without_state_override,
        U256::from(478).to_be_bytes_vec()
    );

    // This deployed bytecode belongs to a smart contract that has a single function when called returns 42 and that's it.
    let deployed_byte_code_of_contract = "6080604052348015600e575f80fd5b50600436106026575f3560e01c80639c16667c14602a575b5f80fd5b60306044565b604051603b91906062565b60405180910390f35b5f602a905090565b5f819050919050565b605c81604c565b82525050565b5f60208201905060735f8301846055565b9291505056fea2646970667358221220d797c79afd038e2209602cede489acc7a3cf5706d7a37a2840c134bc6761327f64736f6c634300081a0033";

    // Function selector
    let input: Bytes = hex::decode("9c16667c").unwrap().into();

    let random_eoa_address = Address::random();

    // Override the code of that random address with the deployed bytecode of the contract
    // Then call the contract with the function selector
    let mut state_override = AddressMap::<AccountOverride>::default();
    state_override.insert(
        random_eoa_address,
        AccountOverride {
            balance: None,
            nonce: None,
            code: Some(hex::decode(deployed_byte_code_of_contract).unwrap().into()),
            state: None,
            state_diff: None,
            move_precompile_to: None,
        },
    );

    let call_result_without_state_override = evm
        .get_call_inner(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(random_eoa_address)),
                input: TransactionInput::new(input.clone()),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    // Assert that the call without state override returns empty
    assert_eq!(call_result_without_state_override, Bytes::default());

    let call_result_with_state_override = evm
        .get_call_inner(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(random_eoa_address)),
                input: TransactionInput::new(input),
                ..Default::default()
            },
            None,
            Some(state_override),
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    // Assert that the call result is 42
    assert_eq!(
        call_result_with_state_override,
        U256::from(42).to_be_bytes_vec()
    );
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

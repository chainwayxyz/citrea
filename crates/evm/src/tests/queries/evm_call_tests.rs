use std::collections::HashMap;
use std::str::FromStr;

use jsonrpsee::core::RpcResult;
use reth_primitives::{address, Address, BlockNumberOrTag, Bytes, TxKind};
use reth_rpc_eth_types::RpcInvalidTransactionError;
use reth_rpc_types::request::{TransactionInput, TransactionRequest};
use reth_rpc_types::state::AccountOverride;
use reth_rpc_types::BlockId;
use revm::primitives::U256;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::{Spec, WorkingSet};
use sov_rollup_interface::spec::SpecId;

use crate::smart_contracts::SimpleStorageContract;
use crate::tests::queries::{init_evm, init_evm_single_block};
use crate::tests::test_signer::TestSigner;
use crate::Evm;

type C = DefaultContext;

#[test]
fn call_contract_without_value() {
    let (evm, mut working_set, _, signer, _) = init_evm();

    let contract = SimpleStorageContract::default();
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();

    let call_result = evm.get_call(
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
    );

    assert_eq!(call_result.unwrap(), Bytes::from_str("0x").unwrap());

    let call_result = evm.get_call(
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
    );

    assert_eq!(
        call_result.unwrap(),
        Bytes::from_str("0x00000000000000000000000000000000000000000000000000000000000001de")
            .unwrap()
    );
}

#[test]
fn test_state_change() {
    let (mut evm, mut working_set, _, signer, l2_height) = init_evm();

    let balance_1 = evm.get_balance(signer.address(), None, &mut working_set);

    let random_address = Address::from_str("0x000000000000000000000000000000000000dead").unwrap();

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate: 1,
        timestamp: 0,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    let call_result = evm.get_call(
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
    );

    assert_eq!(call_result.unwrap(), Bytes::from_str("0x").unwrap());

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let balance_2 = evm.get_balance(signer.address(), None, &mut working_set);
    assert_eq!(balance_1, balance_2);
}

#[test]
fn call_contract_with_value_transfer() {
    let (evm, mut working_set, _, signer, _) = init_evm();

    let contract = SimpleStorageContract::default();
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();

    let call_result = evm.get_call(
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
    );

    assert!(call_result.is_err());
}

#[test]
fn call_contract_with_invalid_nonce() {
    let (evm, mut working_set, _, signer, _) = init_evm();

    let contract = SimpleStorageContract::default();
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();

    let contract_call_data = contract.set_call_data(5);

    let invalid_nonce = 100u64;

    let call_result = evm.get_call(
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
    );

    assert_eq!(call_result, Ok(Bytes::from_str("0x").unwrap()));

    let low_nonce = 2u64;

    let call_result = evm.get_call(
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
    );

    assert_eq!(call_result, Ok(Bytes::from_str("0x").unwrap()));
}

#[test]
fn call_to_nonexistent_contract() {
    let (evm, mut working_set, _, signer, _) = init_evm();

    let nonexistent_contract_address =
        Address::from_str("0x000000000000000000000000000000000000dead").unwrap();

    let call_result = evm.get_call(
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
    );

    assert_eq!(call_result.unwrap(), Bytes::from_str("0x").unwrap());
}

#[test]
fn call_with_high_gas_price() {
    let (evm, mut working_set, _, signer, _) = init_evm();

    let contract = SimpleStorageContract::default();
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();

    let high_gas_price = 1000u128 * 10_000_000_000_000_000_000_u128; // A very high gas price

    let call_result = evm.get_call(
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
    );

    assert_eq!(
        call_result,
        Err(RpcInvalidTransactionError::InsufficientFunds.into())
    );
}

#[test]
fn test_eip1559_fields_call() {
    let (evm, mut working_set, _, signer, _) = init_evm();

    let default_result = eth_call_eip1559(
        &evm,
        &mut working_set,
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
        &signer,
        Some(u128::MAX),
        Some(u128::MAX),
    );
    assert_eq!(
        high_fee_result,
        Err(RpcInvalidTransactionError::InsufficientFunds.into())
    );

    let low_max_fee_result = eth_call_eip1559(&evm, &mut working_set, &signer, Some(1), Some(1));

    assert_eq!(
        low_max_fee_result,
        Err(RpcInvalidTransactionError::FeeCapTooLow.into())
    );

    let no_max_fee_per_gas =
        eth_call_eip1559(&evm, &mut working_set, &signer, None, Some(2e9 as _));
    assert_eq!(
        no_max_fee_per_gas,
        Ok(
            Bytes::from_str("0x00000000000000000000000000000000000000000000000000000000000001de")
                .unwrap()
        )
    );

    let no_priority_fee = eth_call_eip1559(&evm, &mut working_set, &signer, Some(100e9 as _), None);

    assert_eq!(
        no_priority_fee.unwrap().to_string(),
        "0x00000000000000000000000000000000000000000000000000000000000001de"
    );

    let none_res = eth_call_eip1559(&evm, &mut working_set, &signer, None, None);

    assert_eq!(
        none_res.unwrap().to_string(),
        "0x00000000000000000000000000000000000000000000000000000000000001de"
    );
}

fn eth_call_eip1559(
    evm: &Evm<C>,
    working_set: &mut WorkingSet<<C as Spec>::Storage>,
    signer: &TestSigner,
    max_fee_per_gas: Option<u128>,
    max_priority_fee_per_gas: Option<u128>,
) -> RpcResult<reth_primitives::Bytes> {
    let contract = SimpleStorageContract::default();

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(address!(
            "eeb03d20dae810f52111b853b31c8be6f30f4cd3"
        ))),
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

    evm.get_call(
        tx_req,
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        working_set,
    )
}

#[test]
fn gas_price_call_test() {
    let (evm, mut working_set, signer) = init_evm_single_block();

    // Define a base transaction request for reuse
    let base_tx_req = || TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(address!(
            "819c5497b157177315e1204f52e588b393771719"
        ))),
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
    };

    // Test with low gas limit
    let tx_req_low_gas = base_tx_req();
    let result_low_gas = evm.get_call(
        TransactionRequest {
            gas: Some(21000),
            ..tx_req_low_gas
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(
        result_low_gas,
        Err(RpcInvalidTransactionError::BasicOutOfGas(21000).into())
    );
    working_set.unset_archival_version();

    let tx_req_only_gas = base_tx_req();
    let result_only_gas = evm.get_call(
        TransactionRequest {
            gas: Some(250000),
            ..tx_req_only_gas
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(result_only_gas, Ok(Bytes::new()));
    working_set.unset_archival_version();

    // Test with gas and gas_price specified - error
    let tx_req_gas_and_gas_price = base_tx_req();
    let result_gas_and_gas_price = evm.get_call(
        TransactionRequest {
            gas: Some(25000),
            gas_price: Some(20e9 as _),
            ..tx_req_gas_and_gas_price
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(
        result_gas_and_gas_price,
        Err(RpcInvalidTransactionError::BasicOutOfGas(25000).into())
    );
    working_set.unset_archival_version();

    // Test with gas and gas_price specified - this time successful
    let tx_req_gas_and_gas_price = base_tx_req();
    let result_gas_and_gas_price = evm.get_call(
        TransactionRequest {
            gas: Some(250000),
            gas_price: Some(20e9 as _),
            ..tx_req_gas_and_gas_price
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(result_gas_and_gas_price, Ok(Bytes::new()));
    working_set.unset_archival_version();

    // Test with max_fee_per_gas and max_priority_fee_per_gas specified
    let tx_req_fees = base_tx_req();
    let result_fees = evm.get_call(
        TransactionRequest {
            max_fee_per_gas: Some(30e9 as _),
            max_priority_fee_per_gas: Some(10e9 as _),
            ..tx_req_fees
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
    );

    assert!(result_fees.is_ok());
    working_set.unset_archival_version();

    // Test with extremely high gas price
    // Should pass bc gas is sensible
    let tx_req_high_gas_price = base_tx_req();
    let result_high_gas_price = evm.get_call(
        TransactionRequest {
            gas_price: Some(1e12 as _),
            gas: Some(250000),
            ..tx_req_high_gas_price
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
    );

    assert!(result_high_gas_price.is_ok());
    working_set.unset_archival_version();

    // Test with extremely high gas price
    // Will pass gas is not given
    // Which will be capped to max gas the wallet can afford
    let tx_req_high_gas_price = base_tx_req();
    let result_high_gas_price = evm.get_call(
        TransactionRequest {
            gas_price: Some(1e12 as _),
            ..tx_req_high_gas_price
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
    );

    assert!(result_high_gas_price.is_ok());
    working_set.unset_archival_version();

    // Test with extremely high max_fee_per_gas and max_priority_fee_per_gas
    let tx_req_high_fees = base_tx_req();
    let result_high_fees = evm.get_call(
        TransactionRequest {
            max_fee_per_gas: Some(1e12 as _),
            max_priority_fee_per_gas: Some(500e9 as _),
            ..tx_req_high_fees
        },
        Some(BlockId::Number(BlockNumberOrTag::Latest)),
        None,
        None,
        &mut working_set,
    );

    assert!(result_high_fees.is_ok());
    working_set.unset_archival_version();
}

#[test]
fn test_call_with_state_overrides() {
    let (evm, mut working_set, prover_storage, signer, _) = init_evm();

    let contract = SimpleStorageContract::default();
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();

    // Get value of contract before state override
    let call_result_without_state_override = evm
        .get_call(
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
        )
        .unwrap();

    assert_eq!(
        call_result_without_state_override,
        U256::from(478).to_be_bytes_vec()
    );

    // Override the state and check returned value
    let mut state = HashMap::new();
    state.insert(U256::from(0).into(), U256::from(15).into());

    let mut state_override = HashMap::new();
    state_override.insert(
        contract_address,
        AccountOverride {
            balance: None,
            nonce: None,
            code: None,
            state: Some(state),
            state_diff: None,
        },
    );
    let call_result_with_state_override = evm
        .get_call(
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
        .get_call(
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
        )
        .unwrap();

    assert_eq!(
        call_result_without_state_override,
        U256::from(478).to_be_bytes_vec()
    );
}

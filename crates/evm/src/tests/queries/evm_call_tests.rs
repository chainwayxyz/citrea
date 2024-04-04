use std::str::FromStr;

use hex::FromHex;
use jsonrpsee::core::RpcResult;
use reth_primitives::{Address, BlockNumberOrTag, Bytes, U64};
use reth_rpc::eth::error::RpcInvalidTransactionError;
use reth_rpc_types::request::{TransactionInput, TransactionRequest};
use revm::primitives::U256;
use sov_modules_api::WorkingSet;

use super::C;
use crate::smart_contracts::SimpleStorageContract;
use crate::tests::queries::{init_evm, init_evm_single_block};
use crate::tests::test_signer::TestSigner;
use crate::Evm;

#[test]
fn call_contract_without_value() {
    let (evm, mut working_set, signer) = init_evm();

    let contract = SimpleStorageContract::default();
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();

    let contract_call_data = Bytes::from(contract.set_call_data(5).to_vec());

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            value: None,
            input: TransactionInput::new(contract_call_data),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(call_result.unwrap(), Bytes::from_str("0x").unwrap());

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            value: None,
            input: TransactionInput::new(contract.get_call_data().to_vec().into()),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
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
    let (evm, mut working_set, signer) = init_evm();

    let balance_1 = evm.get_balance(signer.address(), None, &mut working_set);

    let random_address = Address::from_str("0x000000000000000000000000000000000000dead").unwrap();

    evm.begin_soft_confirmation_hook([5u8; 32], [42u8; 32], &[10u8; 32], 1, 0, &mut working_set);

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(random_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            value: Some(U256::from(123134235)),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(call_result.unwrap(), Bytes::from_str("0x").unwrap());

    evm.end_soft_confirmation_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let balance_2 = evm.get_balance(signer.address(), None, &mut working_set);
    assert_eq!(balance_1, balance_2);
}

#[test]
fn call_contract_with_value_transfer() {
    let (evm, mut working_set, signer) = init_evm();

    let contract = SimpleStorageContract::default();
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();

    let contract_call_data = Bytes::from(contract.set_call_data(5).to_vec());

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            value: Some(U256::from(100000000)), // reverts here.
            input: TransactionInput::new(contract_call_data),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert!(call_result.is_err());
}

#[test]
fn call_contract_with_invalid_nonce() {
    let (evm, mut working_set, signer) = init_evm();

    let contract = SimpleStorageContract::default();
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();

    let contract_call_data = Bytes::from(contract.set_call_data(5).to_vec());

    let invalid_nonce = U64::from(100);

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            nonce: Some(invalid_nonce),
            input: TransactionInput::new(contract_call_data.clone()),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(call_result, Ok(Bytes::from_str("0x").unwrap()));

    let low_nonce = U64::from(2);

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            nonce: Some(low_nonce),
            input: TransactionInput::new(contract_call_data),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(call_result, Ok(Bytes::from_str("0x").unwrap()));
}

#[test]
fn call_to_nonexistent_contract() {
    let (evm, mut working_set, signer) = init_evm();

    let nonexistent_contract_address =
        Address::from_str("0x000000000000000000000000000000000000dead").unwrap();

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(nonexistent_contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            input: TransactionInput {
                input: None,
                data: None,
            },
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(call_result.unwrap(), Bytes::from_str("0x").unwrap());
}

#[test]
fn call_with_high_gas_price() {
    let (evm, mut working_set, signer) = init_evm();

    let contract = SimpleStorageContract::default();
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();

    let contract_call_data = Bytes::from(contract.set_call_data(5).to_vec());

    let high_gas_price = U256::from(1000) * U256::from(10_000_000_000_000_000_000_i128); // A very high gas price

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(high_gas_price),
            input: TransactionInput::new(contract_call_data),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
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
    let (evm, mut working_set, signer) = init_evm();

    let default_result = eth_call_eip1559(
        &evm,
        &mut working_set,
        &signer,
        Some(U256::from(100e9 as u64)),
        Some(U256::from(2e9 as u64)),
    );

    assert_eq!(
        default_result.unwrap().to_string(),
        "0x00000000000000000000000000000000000000000000000000000000000001de"
    );

    let high_fee_result = eth_call_eip1559(
        &evm,
        &mut working_set,
        &signer,
        Some(U256::MAX),
        Some(U256::MAX),
    );
    assert_eq!(
        high_fee_result,
        Err(RpcInvalidTransactionError::TipVeryHigh.into())
    );

    let low_max_fee_result = eth_call_eip1559(
        &evm,
        &mut working_set,
        &signer,
        Some(U256::from(1)),
        Some(U256::from(1)),
    );

    assert_eq!(
        low_max_fee_result,
        Err(RpcInvalidTransactionError::FeeCapTooLow.into())
    );

    let no_max_fee_per_gas = eth_call_eip1559(
        &evm,
        &mut working_set,
        &signer,
        None,
        Some(U256::from(2e9 as u64)),
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
        &signer,
        Some(U256::from(100e9 as u64)),
        None,
    );

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
    working_set: &mut WorkingSet<C>,
    signer: &TestSigner,
    max_fee_per_gas: Option<U256>,
    max_priority_fee_per_gas: Option<U256>,
) -> RpcResult<reth_primitives::Bytes> {
    let contract = SimpleStorageContract::default();

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap()),
        gas: Some(U256::from(100_000)),
        gas_price: None,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        value: None,
        input: TransactionInput::new(contract.get_call_data().to_vec().into()),
        nonce: Some(U64::from(9)),
        chain_id: Some(1u64),
        ..Default::default()
    };

    evm.get_call(
        tx_req,
        Some(BlockNumberOrTag::Latest),
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
        to: Some(Address::from_str("0x819c5497b157177315e1204f52e588b393771719").unwrap()),
        value: Some(U256::from(1000)),
        input: None.into(),
        nonce: Some(U64::from(1u64)),
        chain_id: Some(1u64),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        transaction_type: None,
        sidecar: None,
        other: Default::default(),
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
            gas: Some(U256::from(21000)),
            ..tx_req_low_gas
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(
        result_low_gas,
        Err(RpcInvalidTransactionError::BasicOutOfGas(U256::from(21000)).into())
    );
    working_set.unset_archival_version();

    let tx_req_only_gas = base_tx_req();
    let result_only_gas = evm.get_call(
        TransactionRequest {
            gas: Some(U256::from(250000)),
            ..tx_req_only_gas
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(result_only_gas, Ok(Bytes::from_hex("0x").unwrap()));
    working_set.unset_archival_version();

    // Test with gas and gas_price specified - error
    let tx_req_gas_and_gas_price = base_tx_req();
    let result_gas_and_gas_price = evm.get_call(
        TransactionRequest {
            gas: Some(U256::from(25000)),
            gas_price: Some(U256::from(20e9 as u64)),
            ..tx_req_gas_and_gas_price
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(
        result_gas_and_gas_price,
        Err(RpcInvalidTransactionError::BasicOutOfGas(U256::from(25000)).into())
    );
    working_set.unset_archival_version();

    // Test with gas and gas_price specified - this time successful
    let tx_req_gas_and_gas_price = base_tx_req();
    let result_gas_and_gas_price = evm.get_call(
        TransactionRequest {
            gas: Some(U256::from(250000)),
            gas_price: Some(U256::from(20e9 as u64)),
            ..tx_req_gas_and_gas_price
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(result_gas_and_gas_price, Ok(Bytes::from_hex("0x").unwrap()));
    working_set.unset_archival_version();

    // Test with max_fee_per_gas and max_priority_fee_per_gas specified
    let tx_req_fees = base_tx_req();
    let result_fees = evm.get_call(
        TransactionRequest {
            max_fee_per_gas: Some(U256::from(30e9 as u64)),
            max_priority_fee_per_gas: Some(U256::from(10e9 as u64)),
            ..tx_req_fees
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert!(result_fees.is_ok());
    working_set.unset_archival_version();

    // Test with extremely high gas price
    let tx_req_high_gas_price = base_tx_req();
    let result_high_gas_price = evm.get_call(
        TransactionRequest {
            gas_price: Some(U256::from(1e12 as u64)),
            ..tx_req_high_gas_price
        },
        Some(BlockNumberOrTag::Latest),
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
            max_fee_per_gas: Some(U256::from(1e12 as u64)),
            max_priority_fee_per_gas: Some(U256::from(500e9 as u64)),
            ..tx_req_high_fees
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert!(result_high_fees.is_ok());
    working_set.unset_archival_version();
}

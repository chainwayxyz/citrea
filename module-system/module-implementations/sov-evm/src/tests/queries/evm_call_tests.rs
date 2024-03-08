use std::str::FromStr;

use alloy_rpc_types::request::{TransactionInput, TransactionRequest};
use reth_primitives::{Address, BlockNumberOrTag, Bytes, U64};
use reth_rpc::eth::error::RpcInvalidTransactionError;
use revm::primitives::U256;

use crate::tests::queries::init_evm;

#[test]
fn call_contract_without_value() {
    let (evm, mut working_set, signer) = init_evm();

    let contract_call_data = "0x313131";
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            value: None,
            input: TransactionInput::new(Bytes::from_str(&contract_call_data).unwrap()),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    // Reverts?
    assert!(call_result.is_err());
}

#[test]
fn call_contract_with_value_transfer() {
    let (evm, mut working_set, signer) = init_evm();

    let contract_call_data = "0x313131";
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            value: Some(U256::from(100000000)),
            input: TransactionInput::new(Bytes::from_str(&contract_call_data).unwrap()),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    // Reverts?
    assert!(call_result.is_err());
}

#[test]
fn call_contract_with_invalid_nonce() {
    let (evm, mut working_set, signer) = init_evm();

    let contract_call_data = "0x31";
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();
    let invalid_nonce = U64::from(100);

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            nonce: Some(invalid_nonce),
            input: TransactionInput::new(Bytes::from_str(&contract_call_data).unwrap()),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(
        call_result,
        Err(RpcInvalidTransactionError::NonceTooHigh.into())
    );

    let low_nonce = U64::from(2);

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            nonce: Some(low_nonce),
            input: TransactionInput::new(Bytes::from_str(&contract_call_data).unwrap()),
            ..Default::default()
        },
        Some(BlockNumberOrTag::Latest),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(
        call_result,
        Err(RpcInvalidTransactionError::NonceTooLow.into())
    );
}

#[test]
fn call_to_nonexistent_contract() {
    let (evm, mut working_set, signer) = init_evm();

    let contract_call_data = "0x313131";
    let nonexistent_contract_address =
        Address::from_str("0x000000000000000000000000000000000000dead").unwrap();

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(nonexistent_contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            input: TransactionInput::new(Bytes::from_str(&contract_call_data).unwrap()),
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

    let contract_call_data = "0x";
    let contract_address = Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();
    let high_gas_price = U256::from(1000) * U256::from(10_000_000_000_000_000_000 as i128); // A very high gas price

    let call_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(contract_address),
            gas: Some(U256::from(100000)),
            gas_price: Some(high_gas_price),
            input: TransactionInput::new(Bytes::from_str(&contract_call_data).unwrap()),
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

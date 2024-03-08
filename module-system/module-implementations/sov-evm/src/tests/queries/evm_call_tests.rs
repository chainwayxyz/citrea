use std::str::FromStr;

use alloy_rpc_types::request::{TransactionInput, TransactionRequest};
use jsonrpsee::core::RpcResult;
use reth_primitives::{Address, BlockNumberOrTag, Bytes, U64};
use reth_rpc::eth::error::RpcInvalidTransactionError;
use revm::primitives::U256;
use sov_modules_api::WorkingSet;

use super::C;
use crate::tests::queries::init_evm;
use crate::tests::test_signer::TestSigner;
use crate::Evm;

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
    // Reverts
    assert!(default_result.is_err());

    let high_fee_result = eth_call_eip1559(
        &evm,
        &mut working_set,
        &signer,
        Some(U256::MAX),
        Some(U256::MAX),
    );
    assert_eq!(
        high_fee_result,
        Err(RpcInvalidTransactionError::GasUintOverflow.into())
    );

    let low_max_fee_result = eth_call_eip1559(
        &evm,
        &mut working_set,
        &signer,
        Some(U256::from(1)),
        Some(U256::from(1)),
    );

    assert!(low_max_fee_result.is_err());

    let no_max_fee_per_gas = eth_call_eip1559(
        &evm,
        &mut working_set,
        &signer,
        None,
        Some(U256::from(2e9 as u64)),
    );
    assert_eq!(
        no_max_fee_per_gas,
        Err(RpcInvalidTransactionError::TipAboveFeeCap.into())
    );

    let no_priority_fee = eth_call_eip1559(
        &evm,
        &mut working_set,
        &signer,
        Some(U256::from(100e9 as u64)),
        None,
    );
    // Reverts
    assert!(no_priority_fee.is_err());

    let none_res = eth_call_eip1559(&evm, &mut working_set, &signer, None, None);
    // Reverts
    assert!(none_res.is_err());
}

fn eth_call_eip1559(
    evm: &Evm<C>,
    working_set: &mut WorkingSet<C>,
    signer: &TestSigner,
    max_fee_per_gas: Option<U256>,
    max_priority_fee_per_gas: Option<U256>,
) -> RpcResult<reth_primitives::Bytes> {
    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap()),
        gas: Some(U256::from(100_000)),
        gas_price: None,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        value: Some(U256::from(1000)),
        input: TransactionInput {
            input: None,
            data: None,
        },
        nonce: Some(U64::from(9)),
        chain_id: Some(U64::from(1u64)),
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

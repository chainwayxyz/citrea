use std::str::FromStr;

use alloy_primitives::Uint;
use alloy_rpc_types::request::{TransactionInput, TransactionRequest};
use hex::FromHex;
use jsonrpsee::core::RpcResult;
use reth_primitives::hex::ToHexExt;
use reth_primitives::{Address, BlockNumberOrTag, Bytes, KECCAK_EMPTY, U64};
use reth_rpc::eth::error::RpcInvalidTransactionError;
use revm::primitives::{SpecId, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, WorkingSet};

use super::basic_queries::{commit, get_evm_with_storage};
use crate::tests::call_tests::create_contract_transaction;
use crate::tests::queries::basic_queries::init_evm;
use crate::tests::test_signer::TestSigner;
use crate::{
    AccountData, CallMessage, EthApiError, Evm, EvmConfig, SimplePayableContract,
    SimpleStorageContract,
};

type C = DefaultContext;

pub fn init_evm_single_block() -> (Evm<C>, WorkingSet<C>, TestSigner) {
    let dev_signer: TestSigner = TestSigner::new_random();

    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: U256::from_str("100000000000000000000").unwrap(), // Setting initial balance
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
        }],
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
        ..Default::default()
    };

    let (evm, mut working_set, prover_storage) = get_evm_with_storage(&config);

    // let contract_addr: Address = Address::from_slice(
    //     hex::decode("819c5497b157177315e1204f52e588b393771719")
    //         .unwrap()
    //         .as_slice(),
    // );

    evm.begin_soft_confirmation_hook([1u8; 32], &[0u8; 32], &mut working_set);

    let simple_payable_contract_tx =
        create_contract_transaction(&dev_signer, 0, SimplePayableContract::default());

    let sender_address = generate_address::<C>("sender");
    let sequencer_address = generate_address::<C>("sequencer");
    let context = C::new(sender_address, sequencer_address, 1);

    evm.call(
        CallMessage {
            txs: vec![simple_payable_contract_tx],
        },
        &context,
        &mut working_set,
    )
    .unwrap();

    evm.end_soft_confirmation_hook(&mut working_set);
    evm.finalize_hook(&[2u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let working_set: WorkingSet<DefaultContext> = WorkingSet::new(prover_storage);

    (evm, working_set, dev_signer)
}

#[test]
fn payable_contract_value_test() {
    let (evm, mut working_set, signer) = init_evm_single_block();

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(Address::from_str("0x819c5497b157177315e1204f52e588b393771719").unwrap()), // Address of the payable contract.
        gas: Some(U256::from(100000)),
        gas_price: Some(U256::from(100000000)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        value: Some(U256::from(3100000)),
        input: TransactionInput {
            input: None,
            data: None,
        },
        nonce: Some(U64::from(1)),
        chain_id: Some(U64::from(1u64)),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Some(vec![]),
        transaction_type: None,
        sidecar: None,
        other: Default::default(),
    };

    let result = evm.eth_estimate_gas(tx_req, Some(BlockNumberOrTag::Latest), &mut working_set);
    assert_eq!(result.unwrap(), Uint::from_str("0xa9ba").unwrap());

    working_set.unset_archival_version();
}

#[test]
fn test_tx_request_fields_gas() {
    let (evm, mut working_set, signer) = init_evm_single_block();

    let fail_tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(Address::from_str("0x819c5497b157177315e1204f52e588b393771719").unwrap()),
        gas: Some(U256::from(100000)),
        gas_price: Some(U256::from(100000000)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        value: Some(U256::from(100000000)),
        input: None.into(),
        nonce: Some(U64::from(7)),
        chain_id: Some(U64::from(1u64)),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Some(vec![]),
        transaction_type: None,
        sidecar: None,
        other: Default::default(),
    };

    let fail_result = evm.eth_estimate_gas(
        fail_tx_req,
        Some(BlockNumberOrTag::Number(100)),
        &mut working_set,
    );
    assert_eq!(fail_result, Err(EthApiError::UnknownBlockNumber.into()));
    working_set.unset_archival_version();

    // let contract = SimpleStorageContract::default();
    // let call_data = contract.get_call_data().to_string();

    let tx_req_contract_call = TransactionRequest {
        from: Some(signer.address()),
        to: Some(Address::from_str("0x819c5497b157177315e1204f52e588b393771719").unwrap()),
        gas: Some(U256::from(100000000)),
        gas_price: Some(U256::from(100)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        value: None.into(),
        input: TransactionInput {
            input: None,
            data: None,
        },
        nonce: Some(U64::from(1)),
        chain_id: Some(U64::from(1u64)),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Some(vec![]),
        transaction_type: None,
        sidecar: None,
        other: Default::default(),
    };

    let result_contract_call = evm.eth_estimate_gas(
        tx_req_contract_call.clone(),
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        result_contract_call.unwrap(),
        Uint::from_str("0x6497").unwrap()
    );

    let tx_req_no_sender = TransactionRequest {
        from: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_sender = evm.eth_estimate_gas(
        tx_req_no_sender,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        result_no_sender,
        Err(RpcInvalidTransactionError::GasTooHigh.into())
    );
    working_set.unset_archival_version();

    let tx_req_no_recipient = TransactionRequest {
        to: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_recipient = evm.eth_estimate_gas(
        tx_req_no_recipient,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        result_no_recipient.unwrap(),
        Uint::from_str("0xcf09").unwrap()
    );
    working_set.unset_archival_version();

    let tx_req_no_gas = TransactionRequest {
        gas: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_gas = evm.eth_estimate_gas(
        tx_req_no_gas,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(result_no_gas.unwrap(), Uint::from_str("0x6497").unwrap());
    working_set.unset_archival_version();

    let tx_req_no_gas_price = TransactionRequest {
        gas_price: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_gas_price = evm.eth_estimate_gas(
        tx_req_no_gas_price,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        result_no_gas_price.unwrap(),
        Uint::from_str("0x6497").unwrap()
    );
    working_set.unset_archival_version();

    let tx_req_no_chain_id = TransactionRequest {
        chain_id: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_chain_id = evm.eth_estimate_gas(
        tx_req_no_chain_id,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        result_no_chain_id.unwrap(),
        Uint::from_str("0x6497").unwrap()
    );
    working_set.unset_archival_version();

    let tx_req_invalid_chain_id = TransactionRequest {
        chain_id: Some(U64::from(3u64)),
        ..tx_req_contract_call.clone()
    };

    let result_invalid_chain_id = evm.eth_estimate_gas(
        tx_req_invalid_chain_id,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        result_invalid_chain_id,
        Err(RpcInvalidTransactionError::InvalidChainId.into())
    );
    working_set.unset_archival_version();

    let tx_req_no_blob_versioned_hashes = TransactionRequest {
        blob_versioned_hashes: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_blob_versioned_hashes = evm.eth_estimate_gas(
        tx_req_no_blob_versioned_hashes,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        result_no_blob_versioned_hashes.unwrap(),
        Uint::from_str("0x6497").unwrap()
    );
    working_set.unset_archival_version();
}

#[test]
fn estimate_gas_eip1559_fields_expanded_test() {
    let (evm, mut working_set, signer) = init_evm_single_block();

    // Scenario 1: Default values for EIP-1559 fields
    let default_result = test_estimate_gas_with_eip1559_fields(
        &evm,
        &mut working_set,
        &signer,
        Some(U256::from(100e9 as u64)),
        Some(U256::from(2e9 as u64)),
    );

    assert_eq!(default_result.unwrap(), Uint::from_str("0xa9ba").unwrap());

    // Scenario 2: Boundary values
    // Very high max fee and priority fee
    let high_fee_result = test_estimate_gas_with_eip1559_fields(
        &evm,
        &mut working_set,
        &signer,
        Some(U256::MAX),
        Some(U256::MAX),
    );
    assert_eq!(
        high_fee_result,
        Err(RpcInvalidTransactionError::GasTooHigh.into())
    );

    // Very low max fee (just above 0) and priority fee
    // Why this is OK?
    let low_max_fee_result = test_estimate_gas_with_eip1559_fields(
        &evm,
        &mut working_set,
        &signer,
        Some(U256::from(1)),
        Some(U256::from(1)),
    );
    assert_eq!(
        low_max_fee_result.unwrap(),
        Uint::from_str("0xa9ba").unwrap()
    );

    let no_max_fee_per_gas = test_estimate_gas_with_eip1559_fields(
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

    let no_priority_fee = test_estimate_gas_with_eip1559_fields(
        &evm,
        &mut working_set,
        &signer,
        Some(U256::from(100e9 as u64)),
        None,
    );
    assert_eq!(no_priority_fee.unwrap(), Uint::from_str("0xa9ba").unwrap());

    let none_res =
        test_estimate_gas_with_eip1559_fields(&evm, &mut working_set, &signer, None, None);
    assert_eq!(none_res.unwrap(), Uint::from_str("0xa9ba").unwrap());
}

#[test]
fn gas_price_fee_estimation_test() {
    let (evm, mut working_set, signer) = init_evm_single_block();

    // Define a base transaction request for reuse
    let base_tx_req = || TransactionRequest {
        from: Some(signer.address()),
        to: Some(Address::from_str("0x819c5497b157177315e1204f52e588b393771719").unwrap()),
        value: Some(U256::from(1000)),
        input: None.into(),
        nonce: Some(U64::from(1u64)),
        chain_id: Some(U64::from(1u64)),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Some(vec![]),
        transaction_type: None,
        sidecar: None,
        other: Default::default(),
        // Gas, gas_price, max_fee_per_gas, and max_priority_fee_per_gas will be varied
        gas: None,
        gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };

    // Test with only gas specified
    let tx_req_only_gas = base_tx_req();
    let result_only_gas = evm.eth_estimate_gas(
        TransactionRequest {
            gas: Some(U256::from(21000)),
            ..tx_req_only_gas
        },
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        result_only_gas,
        Err(RpcInvalidTransactionError::BasicOutOfGas(U256::from(21000)).into())
    );
    working_set.unset_archival_version();

    // Test with gas and gas_price specified
    let tx_req_gas_and_gas_price = base_tx_req();
    let result_gas_and_gas_price = evm.eth_estimate_gas(
        TransactionRequest {
            gas: Some(U256::from(25000)),
            gas_price: Some(U256::from(20e9 as u64)),
            ..tx_req_gas_and_gas_price
        },
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    // Execution Reverted
    assert!(result_gas_and_gas_price.is_err());
    working_set.unset_archival_version();

    // Test with max_fee_per_gas and max_priority_fee_per_gas specified
    let tx_req_fees = base_tx_req();
    let result_fees = evm.eth_estimate_gas(
        TransactionRequest {
            max_fee_per_gas: Some(U256::from(30e9 as u64)),
            max_priority_fee_per_gas: Some(U256::from(10e9 as u64)),
            ..tx_req_fees
        },
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );

    assert_eq!(result_fees.unwrap(), Uint::from_str("0xa9ba").unwrap());
    working_set.unset_archival_version();

    // Test with extremely high gas price
    let tx_req_high_gas_price = base_tx_req();
    let result_high_gas_price = evm.eth_estimate_gas(
        TransactionRequest {
            gas_price: Some(U256::from(1e12 as u64)),
            ..tx_req_high_gas_price
        },
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        result_high_gas_price.unwrap(),
        Uint::from_str("0xa9ba").unwrap()
    );
    working_set.unset_archival_version();

    // Test with extremely high max_fee_per_gas and max_priority_fee_per_gas
    let tx_req_high_fees = base_tx_req();
    let result_high_fees = evm.eth_estimate_gas(
        TransactionRequest {
            max_fee_per_gas: Some(U256::from(1e12 as u64)),
            max_priority_fee_per_gas: Some(U256::from(500e9 as u64)),
            ..tx_req_high_fees
        },
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(result_high_fees.unwrap(), Uint::from_str("0xa9ba").unwrap());
    working_set.unset_archival_version();

    // Test with low gas limit
    let tx_req_low_gas = base_tx_req();
    let result_low_gas = evm.eth_estimate_gas(
        TransactionRequest {
            gas: Some(U256::from(21000)),
            ..tx_req_low_gas
        },
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        result_low_gas,
        Err(RpcInvalidTransactionError::BasicOutOfGas(U256::from(21000)).into())
    );
    working_set.unset_archival_version();
}

fn test_estimate_gas_with_eip1559_fields(
    evm: &Evm<C>,
    working_set: &mut WorkingSet<C>,
    signer: &TestSigner,
    max_fee_per_gas: Option<U256>,
    max_priority_fee_per_gas: Option<U256>,
) -> RpcResult<reth_primitives::U64> {
    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(Address::from_str("0x819c5497b157177315e1204f52e588b393771719").unwrap()),
        gas: Some(U256::from(100_000)),
        gas_price: None,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        value: Some(U256::from(1000)),
        input: TransactionInput {
            input: None,
            data: None,
        },
        nonce: Some(U64::from(1)),
        chain_id: Some(U64::from(1u64)),
        ..Default::default()
    };

    evm.eth_estimate_gas(tx_req, Some(BlockNumberOrTag::Latest), working_set)
}

#[test]
fn estimate_gas_with_varied_inputs_test() {
    let (evm, mut working_set, signer) = init_evm();

    let simple_call_data = 0;
    let simple_result =
        test_estimate_gas_with_input(&evm, &mut working_set, &signer, simple_call_data);

    assert_eq!(
        simple_result.unwrap(),
        Uint::from_str_radix("67ee", 16).unwrap()
    );

    let simple_call_data = 131;
    let simple_result =
        test_estimate_gas_with_input(&evm, &mut working_set, &signer, simple_call_data);

    assert_eq!(
        simple_result.unwrap(),
        Uint::from_str_radix("67fa", 16).unwrap()
    );

    // Testing with non-zero value transfer EOA
    let value_transfer_result =
        test_estimate_gas_with_value(&evm, &mut working_set, &signer, U256::from(1_000_000));

    assert_eq!(
        value_transfer_result.unwrap(),
        Uint::from_str_radix("5208", 16).unwrap()
    );
}

fn test_estimate_gas_with_input(
    evm: &Evm<C>,
    working_set: &mut WorkingSet<C>,
    signer: &TestSigner,
    input_data: u32,
) -> RpcResult<U64> {
    let input_data = SimpleStorageContract::default()
        .set_call_data(input_data)
        .encode_hex();
    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(Address::from_str("eeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap()),
        gas: Some(U256::from(100_000)),
        input: TransactionInput::new(Bytes::from_hex(input_data).unwrap()),
        ..Default::default()
    };

    evm.eth_estimate_gas(tx_req, Some(BlockNumberOrTag::Latest), working_set)
}

fn test_estimate_gas_with_value(
    evm: &Evm<C>,
    working_set: &mut WorkingSet<C>,
    signer: &TestSigner,
    value: U256,
) -> RpcResult<U64> {
    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(Address::from_str("0xabababababababababababababababababababab").unwrap()),
        value: Some(value),
        ..Default::default()
    };

    evm.eth_estimate_gas(tx_req, Some(BlockNumberOrTag::Latest), working_set)
}

use std::str::FromStr;

use alloy_eips::eip2930::AccessListWithGasUsed;
use jsonrpsee::core::RpcResult;
use reth_primitives::{
    address, b256, AccessList, AccessListItem, Address, BlockNumberOrTag, TxKind, U256,
};
use reth_rpc_eth_types::RpcInvalidTransactionError;
use reth_rpc_types::request::{TransactionInput, TransactionRequest};
use serde_json::json;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{Spec, WorkingSet};

use crate::query::MIN_TRANSACTION_GAS;
use crate::smart_contracts::{CallerContract, SimpleStorageContract};
use crate::tests::queries::{init_evm, init_evm_single_block, init_evm_with_caller_contract};
use crate::tests::test_signer::TestSigner;
use crate::{EstimatedDiffSize, Evm};

type C = DefaultContext;

#[test]
fn test_payable_contract_value() {
    let (evm, mut working_set, signer) = init_evm_single_block();

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
    };

    let result = evm.eth_estimate_gas(tx_req, Some(BlockNumberOrTag::Latest), &mut working_set);
    assert_eq!(result.unwrap(), U256::from_str("0xab13").unwrap());
}

#[test]
fn test_tx_request_fields_gas() {
    let (evm, mut working_set, signer) = init_evm_single_block();

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
    };

    let result_contract_call = evm.eth_estimate_gas(
        tx_req_contract_call.clone(),
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        result_contract_call.unwrap(),
        U256::from_str("0x6602").unwrap()
    );
    let contract_diff_size = evm.eth_estimate_diff_size(
        tx_req_contract_call.clone(),
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        contract_diff_size.unwrap(),
        serde_json::from_value::<EstimatedDiffSize>(json![{"gas":"0x6601","l1DiffSize":"0x60"}])
            .unwrap()
    );

    let tx_req_no_gas = TransactionRequest {
        gas: None,
        ..tx_req_contract_call.clone()
    };

    let contract_diff_size = evm.eth_estimate_diff_size(
        tx_req_no_gas.clone(),
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(
        contract_diff_size.unwrap(),
        serde_json::from_value::<EstimatedDiffSize>(json![{"gas":"0x6601","l1DiffSize":"0x60"}])
            .unwrap()
    );

    let tx_req_no_sender = TransactionRequest {
        from: None,
        nonce: None,
        ..tx_req_contract_call.clone()
    };

    let result_no_sender = evm.eth_estimate_gas(
        tx_req_no_sender,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );
    assert_eq!(result_no_sender.unwrap(), U256::from_str("0x6602").unwrap());
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
        U256::from_str("0xd0ad").unwrap()
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
    assert_eq!(result_no_gas.unwrap(), U256::from_str("0x6602").unwrap());
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
        U256::from_str("0x6602").unwrap()
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
        U256::from_str("0x6602").unwrap()
    );
    working_set.unset_archival_version();

    let tx_req_invalid_chain_id = TransactionRequest {
        chain_id: Some(3u64),
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

    // We don't have EIP-4844 now, so this is just to see if it's working.
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
        U256::from_str("0x6602").unwrap()
    );
    working_set.unset_archival_version();

    let no_access_list_req = TransactionRequest {
        access_list: None,
        ..tx_req_contract_call.clone()
    };

    let create_no_access_list_test = evm.create_access_list(
        no_access_list_req,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
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

    let access_list_gas_test = evm.eth_estimate_gas(
        access_list_req.clone(),
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );

    // Wrong access punishment.
    assert_eq!(
        access_list_gas_test.unwrap(),
        U256::from_str("0x6e67").unwrap()
    );

    let already_formed_list = evm.create_access_list(
        access_list_req,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
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

    let (evm, mut working_set, signer, _) = init_evm_with_caller_contract();

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
    };

    let no_access_list = evm.eth_estimate_gas(tx_req_contract_call.clone(), None, &mut working_set);
    assert_eq!(no_access_list.unwrap(), U256::from_str("0x788c").unwrap());

    let form_access_list =
        evm.create_access_list(tx_req_contract_call.clone(), None, &mut working_set);

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

    let with_access_list = evm.eth_estimate_gas(tx_req_with_access_list, None, &mut working_set);
    assert_eq!(with_access_list.unwrap(), U256::from_str("0x775e").unwrap());
}

#[test]
fn estimate_gas_with_varied_inputs_test() {
    let (evm, mut working_set, _, signer, _) = init_evm();

    let simple_call_data = 0;
    let simple_result =
        test_estimate_gas_with_input(&evm, &mut working_set, &signer, simple_call_data);

    assert_eq!(simple_result.unwrap(), U256::from_str("0x684e").unwrap());

    let simple_call_data = 131;
    let simple_result =
        test_estimate_gas_with_input(&evm, &mut working_set, &signer, simple_call_data);

    assert_eq!(simple_result.unwrap(), U256::from_str("0x68cd").unwrap());

    // Testing with non-zero value transfer EOA
    let value_transfer_result =
        test_estimate_gas_with_value(&evm, &mut working_set, &signer, U256::from(1_000_000));

    assert_eq!(
        value_transfer_result.unwrap(),
        U256::from(MIN_TRANSACTION_GAS + 1)
    );
}

#[test]
fn test_pending_env() {
    let (evm, mut working_set, signer) = init_evm_single_block();

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
    };

    let result = evm
        .eth_estimate_gas(
            tx_req.clone(),
            Some(BlockNumberOrTag::Latest),
            &mut working_set,
        )
        .unwrap();

    let result_pending = evm.eth_estimate_gas(
        tx_req.clone(),
        Some(BlockNumberOrTag::Pending),
        &mut working_set,
    );
    assert_eq!(result_pending.unwrap(), result);

    let result = evm
        .create_access_list(tx_req.clone(), None, &mut working_set)
        .unwrap();

    let result_pending = evm
        .create_access_list(
            tx_req.clone(),
            Some(BlockNumberOrTag::Pending),
            &mut working_set,
        )
        .unwrap();

    assert_eq!(result_pending, result);
}

fn test_estimate_gas_with_input(
    evm: &Evm<C>,
    working_set: &mut WorkingSet<<C as Spec>::Storage>,
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

    evm.eth_estimate_gas(tx_req, Some(BlockNumberOrTag::Latest), working_set)
}

fn test_estimate_gas_with_value(
    evm: &Evm<C>,
    working_set: &mut WorkingSet<<C as Spec>::Storage>,
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

    evm.eth_estimate_gas(tx_req, Some(BlockNumberOrTag::Latest), working_set)
}

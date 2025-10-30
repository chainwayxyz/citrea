use std::str::FromStr;

use alloy_consensus::TxReceipt as _;
use alloy_eips::eip2930::{AccessList, AccessListItem, AccessListWithGasUsed};
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{address, b256, Address, TxKind, U256};
use alloy_rpc_types::{TransactionInput, TransactionRequest};
use jsonrpsee::core::RpcResult;
use reth_rpc_eth_types::RpcInvalidTransactionError;
use serde_json::json;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, Spec, SpecId, StateVecAccessor, WorkingSet};

use crate::call::CallMessage;
use crate::query::MIN_TRANSACTION_GAS;
use crate::smart_contracts::{
    CallerContract, ERC20ImplementationContract, Execution, MinimalBatchWalletContract,
    SimpleStorageContract, SimpleTokenProxyContract,
};
use crate::tests::get_test_seq_pub_key;
use crate::tests::queries::{init_evm, init_evm_single_block, init_evm_with_caller_contract};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{commit, create_contract_message_with_bytecode, get_fork_fn_latest};
use crate::{EstimatedDiffSize, Evm};

type C = DefaultContext;

// EIP-7702 delegation code prefix - used across all EIP-7702 tests
const EIP7702_DELEGATION_PREFIX: [u8; 2] = [0xef, 0x01];

/// Deploy a contract and return its address with a new working set.
/// This helper encapsulates the common pattern of deploying contracts in tests.
///
/// If finalize_state_root is Some, calls finalize_hook with that root.
/// If None, skips the finalize_hook call.
#[allow(clippy::too_many_arguments)]
fn deploy_contract(
    evm: &mut Evm<C>,
    signer: &TestSigner,
    bytecode: Vec<u8>,
    l2_height: u64,
    prover_storage: &<C as Spec>::Storage,
    ledger_db: &LedgerDB,
    mut working_set: WorkingSet<<C as Spec>::Storage>,
    pre_state_root: [u8; 32],
    finalize_state_root: Option<[u8; 32]>,
    spec_id: SpecId,
    l1_fee_rate: u128,
    timestamp: u64,
) -> (Address, WorkingSet<<C as Spec>::Storage>) {
    let current_nonce = evm
        .get_transaction_count(signer.address(), None, &mut working_set, ledger_db)
        .unwrap();

    let contract_address = signer.address().create(current_nonce.to::<u64>());

    let deploy_tx =
        create_contract_message_with_bytecode(signer, current_nonce.to::<u64>(), bytecode, None);

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root,
        current_spec: spec_id,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    let sender_address = generate_address::<C>("sender");
    let context = C::new(sender_address, l2_height, spec_id, l1_fee_rate);

    evm.call(
        CallMessage {
            txs: vec![deploy_tx],
        },
        &context,
        &mut working_set,
    )
    .unwrap();

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);

    if let Some(finalize_root) = finalize_state_root {
        evm.finalize_hook(&finalize_root, &mut working_set.accessory_state());
    }

    let ps = prover_storage.clone();
    commit(working_set, ps.clone());

    (contract_address, WorkingSet::new(ps))
}

/// Helper function to verify approval events were emitted correctly.
///
/// Checks that:
/// 1. An Approval event was emitted
/// 2. The event has correct owner, spender, and amount
/// 3. The event is from the expected token contract
fn verify_approval_events(
    receipt: &reth_primitives::ReceiptWithBloom<reth_primitives::Receipt>,
    token_address: Address,
    owner: Address,
    spender: Address,
    amount: U256,
    context: &str,
) {
    // ERC20 Approval event signature: Approval(address,address,uint256)
    let approval_event_sig =
        alloy_primitives::b256!("8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925");

    // Find approval events matching the specific owner and spender
    let approval_events: Vec<_> = receipt
        .logs()
        .iter()
        .filter(|log| {
            if log.address != token_address
                || log.topics().is_empty()
                || log.topics()[0] != approval_event_sig
                || log.topics().len() < 3
            {
                return false;
            }
            // Check if owner and spender match
            let log_owner = Address::from_slice(&log.topics()[1].as_slice()[12..32]);
            let log_spender = Address::from_slice(&log.topics()[2].as_slice()[12..32]);
            log_owner == owner && log_spender == spender
        })
        .collect();

    assert!(
        !approval_events.is_empty(),
        "{}: No Approval event found in receipt. Expected Approval event from token: {} for owner: {}, spender: {}, amount: {}",
        context,
        token_address,
        owner,
        spender,
        amount
    );

    // Use the first matching event (there should only be one per spender in this test)
    let event = approval_events.first().unwrap();

    assert_eq!(
        event.topics().len(),
        3,
        "{}: Approval event should have 3 topics (signature, indexed owner, indexed spender)",
        context
    );

    // Check indexed parameters (owner and spender are indexed in standard ERC20)
    let event_owner = Address::from_slice(&event.topics()[1].as_slice()[12..32]);
    let event_spender = Address::from_slice(&event.topics()[2].as_slice()[12..32]);

    assert_eq!(
        event_owner, owner,
        "{}: Approval event owner mismatch. Expected: {}, Actual: {}",
        context, owner, event_owner
    );

    assert_eq!(
        event_spender, spender,
        "{}: Approval event spender mismatch. Expected: {}, Actual: {}",
        context, spender, event_spender
    );

    // Check the amount in data (not indexed)
    if event.data.data.len() >= 32 {
        let event_amount = U256::from_be_bytes::<32>(event.data.data[0..32].try_into().unwrap());
        assert_eq!(
            event_amount, amount,
            "{}: Approval event amount mismatch. Expected: {}, Actual: {}",
            context, amount, event_amount
        );
    } else {
        panic!(
            "{}: Approval event data too short. Expected at least 32 bytes, got: {}",
            context,
            event.data.data.len()
        );
    }
}

#[test]
fn test_payable_contract_value() {
    let (evm, mut working_set, signer, ledger_db) = init_evm_single_block(SpecId::Tangerine);

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
        authorization_list: None,
    };

    let result = evm.eth_estimate_gas_inner(
        tx_req,
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(result.unwrap(), U256::from_str("0xab13").unwrap());
}

#[test]
fn test_tx_request_fields_gas_fork1() {
    let (evm, mut working_set, signer, ledger_db) = init_evm_single_block(SpecId::Tangerine);

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
        authorization_list: None,
    };

    let result_contract_call = evm.eth_estimate_gas_inner(
        tx_req_contract_call.clone(),
        Some(BlockNumberOrTag::Latest),
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
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
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

    let access_list_gas_test = evm.eth_estimate_gas_inner(
        access_list_req.clone(),
        Some(BlockNumberOrTag::Latest),
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
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
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

    let (evm, mut working_set, signer, _, ledger_db) = init_evm_with_caller_contract();

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
        authorization_list: None,
    };

    let no_access_list = evm.eth_estimate_gas_inner(
        tx_req_contract_call.clone(),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(no_access_list.unwrap(), U256::from_str("0x788c").unwrap());

    let form_access_list = evm.create_access_list_inner(
        tx_req_contract_call.clone(),
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

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

    let with_access_list = evm.eth_estimate_gas_inner(
        tx_req_with_access_list,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(with_access_list.unwrap(), U256::from_str("0x775e").unwrap());
}

#[test]
fn estimate_gas_with_varied_inputs_test() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SpecId::Tangerine);

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
    let (evm, mut working_set, signer, ledger_db) = init_evm_single_block(SpecId::Tangerine);

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
        authorization_list: None,
    };

    let result = evm
        .eth_estimate_gas_inner(
            tx_req.clone(),
            Some(BlockNumberOrTag::Latest),
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();

    let result_pending = evm.eth_estimate_gas_inner(
        tx_req.clone(),
        Some(BlockNumberOrTag::Pending),
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );
    assert_eq!(result_pending.unwrap(), result);

    let result = evm
        .create_access_list_inner(
            tx_req.clone(),
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
        to: Some(TxKind::Call(address!(
            "eeb03d20dae810f52111b853b31c8be6f30f4cd3"
        ))),
        gas: Some(100_000),
        input: TransactionInput::new(input_data.into()),
        ..Default::default()
    };

    evm.eth_estimate_gas_inner(
        tx_req,
        Some(BlockNumberOrTag::Latest),
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
        working_set,
        ledger_db,
        get_fork_fn_latest(),
    )
}

#[test]
fn test_eip7702_delegation_batch_execution() {
    let spec_id = SpecId::latest();
    let (mut evm, working_set, prover_storage, signer, mut l2_height, ledger_db) =
        init_evm(spec_id);

    // Deploy token contract
    let token_impl = ERC20ImplementationContract::default();
    let token_impl_bytecode = token_impl.byte_code();
    let (token_impl_address, working_set) = deploy_contract(
        &mut evm,
        &signer,
        token_impl_bytecode,
        l2_height,
        &prover_storage,
        &ledger_db,
        working_set,
        [10u8; 32],
        Some([101u8; 32]),
        spec_id,
        1,
        24,
    );
    l2_height += 1;

    // Deploy SimpleTokenProxy pointing to token implementation contract
    let token_proxy = SimpleTokenProxyContract::default();
    let initial_supply = U256::from(1_000_000_000_000_000_000_000u128);
    let token_proxy_bytecode = token_proxy.deployment_bytecode(token_impl_address, initial_supply);
    let (token_proxy_address, working_set) = deploy_contract(
        &mut evm,
        &signer,
        token_proxy_bytecode,
        l2_height,
        &prover_storage,
        &ledger_db,
        working_set,
        [101u8; 32],
        Some([102u8; 32]),
        spec_id,
        1,
        24,
    );
    l2_height += 1;

    // Deploy MinimalBatchWallet
    let wallet = MinimalBatchWalletContract::default();
    let wallet_bytecode = wallet.byte_code();
    let (wallet_address, mut working_set) = deploy_contract(
        &mut evm,
        &signer,
        wallet_bytecode,
        l2_height,
        &prover_storage,
        &ledger_db,
        working_set,
        [102u8; 32],
        Some([103u8; 32]),
        spec_id,
        1,
        24,
    );

    let token_impl_code = evm
        .get_code(token_impl_address, None, &mut working_set, &ledger_db)
        .unwrap();

    let token_proxy_code = evm
        .get_code(token_proxy_address, None, &mut working_set, &ledger_db)
        .unwrap();
    assert!(!token_impl_code.is_empty(), "Token impl should have code");
    assert!(!token_proxy_code.is_empty(), "Token proxy should have code");

    let wallet_code = evm
        .get_code(wallet_address, None, &mut working_set, &ledger_db)
        .unwrap();
    assert!(!wallet_code.is_empty(), "Wallet should have code");

    let slot_0 = evm
        .get_storage_at(
            token_proxy_address,
            U256::ZERO,
            None,
            &mut working_set,
            &ledger_db,
        )
        .unwrap();
    let stored_impl = Address::from_slice(&slot_0[12..32]);
    assert_eq!(
        stored_impl, token_impl_address,
        "Proxy implementation mismatch!"
    );

    let spender = Address::from([0xab; 20]);
    let approve_amount = U256::from(10_000u128);
    let token_approve_call_data = token_impl.approve_call_data(spender, approve_amount);

    let spender2 = Address::from([0xcd; 20]);
    let approve_amount2 = U256::from(20_000u128);
    let token_approve_call_data2 = token_impl.approve_call_data(spender2, approve_amount2);

    let batch_executions = vec![
        Execution {
            target: token_proxy_address,
            value: U256::ZERO,
            call_data: token_approve_call_data.clone(),
        },
        Execution {
            target: token_proxy_address,
            value: U256::ZERO,
            call_data: token_approve_call_data2.clone(),
        },
    ];

    let execute_call_data = wallet.execute_batch_call_data(batch_executions.clone());

    let current_nonce = evm
        .get_transaction_count(signer.address(), None, &mut working_set, &ledger_db)
        .unwrap()
        .to::<u64>();

    let auth = signer
        .get_signed_authorization(wallet_address, current_nonce + 1)
        .expect("Should create signed authorization");

    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(signer.address())), // Self-call
        value: None,
        input: TransactionInput::new(execute_call_data.into()),
        chain_id: Some(1u64),
        gas: None,
        gas_price: Some(100_000_000),
        nonce: Some(current_nonce),
        access_list: None,
        authorization_list: Some(vec![auth]),
        ..Default::default()
    };

    // Perform gas estimation
    let gas_estimate = evm
        .eth_estimate_gas(tx_req, None, &mut working_set, &ledger_db)
        .expect("Gas estimation should succeed");

    let gas_estimate_u64 = gas_estimate.to::<u64>();

    let auth_for_exec = signer
        .get_signed_authorization(wallet_address, current_nonce + 1)
        .expect("Should create signed authorization");

    let execute_call_data_exec = wallet.execute_batch_call_data(batch_executions.clone());
    let rlp_tx = signer
        .sign_eip7702_transaction_with_gas_limit(
            signer.address(),
            execute_call_data_exec,
            current_nonce,
            vec![auth_for_exec],
            gas_estimate_u64,
        )
        .expect("Should sign transaction");

    let l1_fee_rate = 1;
    let l2_block_info_exec = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: spec_id,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 24,
    };

    evm.begin_l2_block_hook(&l2_block_info_exec, &mut working_set);
    let sender_address = generate_address::<C>("sender");
    let context = C::new(sender_address, l2_height, SpecId::Fork3, l1_fee_rate);
    let call_result = evm.call(
        CallMessage { txs: vec![rlp_tx] },
        &context,
        &mut working_set,
    );
    evm.end_l2_block_hook(&l2_block_info_exec, &mut working_set);
    evm.finalize_hook(&[103u8; 32], &mut working_set.accessory_state());

    match call_result {
        Ok(_) => {
            let receipts: Vec<_> = evm
                .receipts
                .iter(&mut working_set.accessory_state())
                .collect();

            if let Some(receipt) = receipts.last() {
                // Verify EOA has delegation code
                let eoa_code = evm
                    .get_code(signer.address(), None, &mut working_set, &ledger_db)
                    .unwrap();
                assert!(
                    eoa_code.starts_with(&EIP7702_DELEGATION_PREFIX),
                    "EOA should have EIP-7702 delegation code (0xef01...), got: 0x{}",
                    hex::encode(&eoa_code[..eoa_code.len().min(10)])
                );

                let owner = signer.address();

                // Verify delegation code is properly set
                assert!(
                    eoa_code.len() >= 23,
                    "Delegation code should be at least 23 bytes (0xef01 + 20-byte address + 1-byte designator)"
                );
                assert_eq!(
                    &eoa_code[0..2],
                    &EIP7702_DELEGATION_PREFIX,
                    "Code should start with EIP-7702 delegation prefix (0xef01)"
                );
                // EIP-7702 format: 0xef01 (2 bytes) + version (1 byte) + address (20 bytes)
                let delegated_address = Address::from_slice(&eoa_code[3..23]);
                assert_eq!(
                    delegated_address, wallet_address,
                    "Delegation should point to wallet contract, found: {}, expected: {}",
                    delegated_address, wallet_address
                );

                // Verify approval events using helper function
                verify_approval_events(
                    &receipt.receipt,
                    token_proxy_address,
                    owner,
                    spender,
                    approve_amount,
                    "First approval event",
                );
                verify_approval_events(
                    &receipt.receipt,
                    token_proxy_address,
                    owner,
                    spender2,
                    approve_amount2,
                    "Second approval event",
                );

                // Verify transaction succeeded
                assert!(
                    receipt.receipt.receipt.success,
                    "Transaction should succeed when using estimated gas. Gas used: {}, Estimated: {}",
                    receipt.gas_used,
                    gas_estimate_u64
                );

                // Verify gas usage is within limits
                assert!(
                    receipt.gas_used <= gas_estimate_u64,
                    "Actual gas used ({}) should not exceed estimate ({})",
                    receipt.gas_used,
                    gas_estimate_u64
                );
                let gas_buffer = gas_estimate_u64.saturating_sub(receipt.gas_used);
                assert!(gas_buffer > 0);

                let logs = receipt.receipt.logs();
                assert_eq!(logs.len(), 2);

                // Verify execution status
                assert!(
                    receipt.receipt.receipt.success,
                    "Transaction should succeed with estimated gas. Estimated: {}, Used: {}",
                    gas_estimate, receipt.gas_used
                );
            }
        }
        Err(err) => {
            panic!("Transaction execution failed: {err:?}");
        }
    }
}

#[test]
fn test_eip7702_persistent_delegation_gas_forwarding() {
    // Establishes delegation in one transaction, then uses that existing delegation in a second transaction.

    let (mut evm, working_set, prover_storage, signer, mut l2_height, ledger_db) =
        init_evm(SpecId::latest());

    // Deploy token implementation
    let token_impl = ERC20ImplementationContract::default();
    let token_impl_bytecode = token_impl.byte_code();
    let (token_impl_address, working_set) = deploy_contract(
        &mut evm,
        &signer,
        token_impl_bytecode,
        l2_height,
        &prover_storage,
        &ledger_db,
        working_set,
        [101u8; 32],
        Some([102u8; 32]),
        SpecId::latest(),
        1,
        11,
    );
    l2_height += 1;

    // Deploy proxy pointing to implementation
    let token_proxy = SimpleTokenProxyContract::default();
    let initial_supply = U256::from(1_000_000_000_000_000_000_000u128);
    let token_proxy_bytecode = token_proxy.deployment_bytecode(token_impl_address, initial_supply);
    let (token_proxy_address, working_set) = deploy_contract(
        &mut evm,
        &signer,
        token_proxy_bytecode,
        l2_height,
        &prover_storage,
        &ledger_db,
        working_set,
        [102u8; 32],
        Some([103u8; 32]),
        SpecId::latest(),
        1,
        12,
    );
    l2_height += 1;

    // Deploy wallet contract
    let wallet = MinimalBatchWalletContract::default();
    let wallet_bytecode = wallet.byte_code();
    let (wallet_address, working_set) = deploy_contract(
        &mut evm,
        &signer,
        wallet_bytecode,
        l2_height,
        &prover_storage,
        &ledger_db,
        working_set,
        [103u8; 32],
        Some([104u8; 32]),
        SpecId::latest(),
        1,
        13,
    );
    l2_height += 1;

    // Establish delegation
    let mut working_set = working_set;
    let nonce1 = evm
        .get_transaction_count(signer.address(), None, &mut working_set, &ledger_db)
        .unwrap()
        .to::<u64>();

    let auth1 = signer
        .get_signed_authorization(wallet_address, nonce1 + 1)
        .expect("Should create authorization");

    // Simple self-call with authorization to establish delegation
    let tx1 = signer
        .sign_eip7702_transaction(
            signer.address(),
            vec![], // Empty calldata - just establish delegation
            nonce1,
            vec![auth1],
        )
        .expect("Should sign transaction");

    let l2_block_info1 = HookL2BlockInfo {
        l2_height,
        pre_state_root: [104u8; 32],
        current_spec: SpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate: 1,
        timestamp: 14,
    };

    evm.begin_l2_block_hook(&l2_block_info1, &mut working_set);

    let sender_address = generate_address::<C>("sender");
    let context = C::new(sender_address, l2_height, SpecId::latest(), 1);

    let result1 = evm.call(CallMessage { txs: vec![tx1] }, &context, &mut working_set);

    evm.end_l2_block_hook(&l2_block_info1, &mut working_set);
    evm.finalize_hook(&[105u8; 32], &mut working_set.accessory_state());

    assert!(result1.is_ok(), "First transaction should succeed");

    let ps = prover_storage.clone();
    commit(working_set, ps.clone());
    l2_height += 1;

    let mut working_set = WorkingSet::new(prover_storage.clone());
    let eoa_code = evm
        .get_code(signer.address(), None, &mut working_set, &ledger_db)
        .unwrap();

    assert!(
        eoa_code.starts_with(&EIP7702_DELEGATION_PREFIX),
        "EOA should have EIP-7702 delegation code, got: 0x{}",
        hex::encode(&eoa_code[..eoa_code.len().min(10)])
    );

    // Build batch execution calldata with actual deployed addresses
    let spender = Address::from([0xab; 20]);
    let approve_amount = U256::from(10_000u128);
    let token_approve_call_data = token_impl.approve_call_data(spender, approve_amount);

    let spender2 = Address::from([0xcd; 20]);
    let approve_amount2 = U256::from(20_000u128);
    let token_approve_call_data2 = token_impl.approve_call_data(spender2, approve_amount2);

    let batch_executions = vec![
        Execution {
            target: token_proxy_address,
            value: U256::ZERO,
            call_data: token_approve_call_data.clone(),
        },
        Execution {
            target: token_proxy_address,
            value: U256::ZERO,
            call_data: token_approve_call_data2.clone(),
        },
    ];

    let execute_call_data = wallet.execute_batch_call_data(batch_executions.clone());

    // Use persistent delegation
    let nonce2 = evm
        .get_transaction_count(signer.address(), None, &mut working_set, &ledger_db)
        .unwrap()
        .to::<u64>();

    // Include authorization (will be ignored because EOA already has code)
    let auth2 = signer
        .get_signed_authorization(wallet_address, nonce2 + 1)
        .expect("Should create authorization");

    // Estimate gas for the transaction
    let tx_req = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(signer.address())),
        value: None,
        input: TransactionInput::new(execute_call_data.clone().into()),
        chain_id: Some(1u64),
        gas: None,
        gas_price: Some(100_000_000),
        nonce: Some(nonce2),
        access_list: None,
        authorization_list: Some(vec![auth2.clone()]),
        ..Default::default()
    };

    let gas_estimate = evm
        .eth_estimate_gas(tx_req, None, &mut working_set, &ledger_db)
        .expect("Gas estimation should succeed");

    // Execute with estimated gas
    let tx2 = signer
        .sign_eip7702_transaction_with_gas_limit(
            signer.address(),
            execute_call_data,
            nonce2,
            vec![auth2],
            gas_estimate.to::<u64>(),
        )
        .expect("Should sign transaction");

    let l2_block_info2 = HookL2BlockInfo {
        l2_height,
        pre_state_root: [105u8; 32], // previous finalize state root from block 7
        current_spec: SpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate: 1,
        timestamp: 15,
    };

    evm.begin_l2_block_hook(&l2_block_info2, &mut working_set);

    let sender_address = generate_address::<C>("sender");
    let context = C::new(sender_address, l2_height, SpecId::latest(), 1);

    let result2 = evm.call(CallMessage { txs: vec![tx2] }, &context, &mut working_set);

    evm.end_l2_block_hook(&l2_block_info2, &mut working_set);
    evm.finalize_hook(&[106u8; 32], &mut working_set.accessory_state());

    match result2 {
        Ok(_) => {
            let receipts2: Vec<_> = evm
                .receipts
                .iter(&mut working_set.accessory_state())
                .collect();

            if let Some(receipt2) = receipts2.last() {
                let success = receipt2.receipt.receipt.success;
                let gas_used = receipt2.receipt.receipt.cumulative_gas_used;

                if success {
                    // Verify delegation code persistence across transactions
                    let eoa_code_final = evm
                        .get_code(signer.address(), None, &mut working_set, &ledger_db)
                        .unwrap();
                    assert!(
                        eoa_code_final.starts_with(&EIP7702_DELEGATION_PREFIX),
                        "Delegation code should persist across transactions"
                    );
                    // EIP-7702 format: 0xef01 (2 bytes) + version (1 byte) + address (20 bytes)
                    let delegated_address = Address::from_slice(&eoa_code_final[3..23]);
                    assert_eq!(
                        delegated_address, wallet_address,
                        "Delegation should still point to wallet contract"
                    );

                    // Verify second transaction success
                    assert!(
                        receipt2.receipt.receipt.success,
                        "Second transaction with persistent delegation should succeed"
                    );

                    // Verify gas usage for persistent delegation
                    assert!(gas_used > 0, "Gas used should be greater than 0");
                    let gas_estimate_u64 = gas_estimate.to::<u64>();
                    assert!(
                        gas_used <= gas_estimate_u64,
                        "Gas used ({}) should be within estimate ({})",
                        gas_used,
                        gas_estimate_u64
                    );

                    // Verify batch execution completed correctly by checking events
                    let owner = signer.address();
                    verify_approval_events(
                        &receipt2.receipt,
                        token_proxy_address,
                        owner,
                        spender,
                        approve_amount,
                        "First approval event in persistent delegation",
                    );
                    verify_approval_events(
                        &receipt2.receipt,
                        token_proxy_address,
                        owner,
                        spender2,
                        approve_amount2,
                        "Second approval event in persistent delegation",
                    );

                    // Verify no regression from first transaction
                    assert!(
                        receipt2.receipt.receipt.success,
                        "Second transaction should maintain first transaction's success"
                    );
                } else {
                    panic!("Persistent delegation gas forwarding bug confirmed!");
                }
            }
        }
        Err(err) => {
            panic!("Transaction execution error: {err:?}");
        }
    }
}

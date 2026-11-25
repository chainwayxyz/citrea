use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{Address, Bytes, TxKind};
use alloy_rpc_types::state::{AccountOverride, StateOverride};
use alloy_rpc_types::TransactionRequest;
use sov_rollup_interface::spec::SpecId as SovSpecId;

use crate::tests::queries::init_evm;
use crate::tests::utils::{get_fork_fn_latest, remove_native_header};

#[test]
fn test_pending_block() {
    let (evm, mut working_set, _, _, l2_height, ledger_db) = init_evm(SovSpecId::latest());

    assert_eq!(l2_height, 4);

    let latest_block = evm
        .get_block_by_number(
            Some(BlockNumberOrTag::Latest),
            Some(false),
            &mut working_set,
            &ledger_db,
        )
        .unwrap()
        .unwrap();

    assert_eq!(latest_block.header.number, 3);

    let pending_block = evm
        .get_block_by_number(
            Some(BlockNumberOrTag::Pending),
            Some(true),
            &mut working_set,
            &ledger_db,
        )
        .unwrap()
        .unwrap();

    assert_eq!(pending_block.header.number, latest_block.header.number + 1);
    assert_eq!(pending_block.header.number, 4);
    assert_eq!(pending_block.transactions.len(), 0);
    assert!(pending_block.header.base_fee_per_gas.is_some());
    assert!(pending_block.header.gas_limit > 0);
    assert_eq!(pending_block.header.gas_used, 0);
    assert_eq!(pending_block.header.parent_hash, latest_block.header.hash);
}

#[test]
fn test_pending_block_with_pruned_previous_header() {
    let (evm, mut working_set, _, _, _, ledger_db) = init_evm(SovSpecId::latest());
    let head = evm.last_sealed_header(&mut working_set);
    let previous = head.number - 1;
    remove_native_header(&evm, previous, &mut working_set);
    assert_eq!(evm.block_hash_from_number(previous, &mut working_set), None);

    let pending = evm
        .get_block_by_number(
            Some(BlockNumberOrTag::Pending),
            None,
            &mut working_set,
            &ledger_db,
        )
        .unwrap()
        .unwrap();
    assert_eq!(pending.header.number, head.number + 1);
    assert_eq!(pending.header.parent_hash, head.hash());
    assert_eq!(pending.header.timestamp, head.timestamp + 2);
}

#[test]
fn test_pending_estimates_keep_parent_hash_across_retries() {
    let (evm, mut working_set, _, signer, _, ledger_db) = init_evm(SovSpecId::latest());
    let head = evm.last_sealed_header(&mut working_set).number;
    assert_eq!(evm.blockhash_get(head, &mut working_set), None);

    let address = Address::repeat_byte(0x42);
    // Check BLOCKHASH for the pending parent and revert if it is zero.
    let code = Bytes::from(vec![
        0x60,
        u8::try_from(head).unwrap(),
        0x40,
        0x15,
        0x60,
        0x08,
        0x57,
        0x00,
        0x5b,
        0x5f,
        0x5f,
        0xfd,
    ]);
    let overrides =
        StateOverride::from_iter([(address, AccountOverride::default().with_code(code))]);
    let request = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(address)),
        ..Default::default()
    };
    let pending = Some(BlockNumberOrTag::Pending);
    let gas = evm
        .eth_estimate_gas_inner(
            request.clone(),
            pending,
            Some(overrides.clone()),
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();
    let access_list = evm
        .create_access_list_inner(
            request,
            pending,
            Some(overrides),
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        )
        .unwrap();
    assert_eq!(gas, access_list.gas_used);
    assert_eq!(evm.blockhash_get(head, &mut working_set), None);
}

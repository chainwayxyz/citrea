use alloy_eips::BlockNumberOrTag;
use sov_rollup_interface::spec::SpecId as SovSpecId;

use crate::tests::queries::init_evm;

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

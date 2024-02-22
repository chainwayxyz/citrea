use sov_mock_da::MockDaSpec;
use sov_modules_api::StateMapAccessor;
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmationBatch;

use crate::tests::genesis_tests::{get_soft_confirmation_rule_enforcer, TEST_CONFIG};

#[test]
fn block_count_per_da_hash_must_be_correct() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    let mut signed_soft_confirmation_batch = SignedSoftConfirmationBatch {
        hash: [0; 32],
        da_slot_height: 0,
        da_slot_hash: [0; 32],
        pre_state_root: vec![],
        txs: vec![],
        signature: vec![],
        pub_key: vec![],
        l1_fee_rate: 1,
    };
    // call begin_slot_hook a couple times for da hash 0
    for _ in 0..3 {
        soft_confirmation_rule_enforcer
            .begin_soft_confirmation_hook(
                &mut signed_soft_confirmation_batch.clone().into(),
                &mut working_set,
            )
            .unwrap();
    }
    // the block count for da hash 0 should be 3
    assert_eq!(
        soft_confirmation_rule_enforcer
            .da_root_hash_to_number
            .get(&[0; 32], &mut working_set)
            .unwrap(),
        3
    );

    signed_soft_confirmation_batch.da_slot_hash = [1; 32];

    // call with a different da hash
    soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(
            &mut signed_soft_confirmation_batch.clone().into(),
            &mut working_set,
        )
        .unwrap();
    // the block count for da hash 1 should be 1
    assert_eq!(
        soft_confirmation_rule_enforcer
            .da_root_hash_to_number
            .get(&[1; 32], &mut working_set)
            .unwrap(),
        1
    );
}

#[test]
fn get_max_l1_fee_rate_change_percentage_must_be_correct() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    assert_eq!(
        soft_confirmation_rule_enforcer
            .get_max_l1_fee_rate_change_percentage(&mut working_set)
            .unwrap(),
        10
    );

    let mut signed_soft_confirmation_batch = SignedSoftConfirmationBatch {
        hash: [0; 32],
        da_slot_height: 0,
        da_slot_hash: [0; 32],
        pre_state_root: vec![],
        txs: vec![],
        signature: vec![],
        pub_key: vec![],
        l1_fee_rate: 1,
    };

    soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(
            &mut signed_soft_confirmation_batch.clone().into(),
            &mut working_set,
        )
        .unwrap();

    // didn't change
    assert_eq!(
        soft_confirmation_rule_enforcer
            .get_max_l1_fee_rate_change_percentage(&mut working_set)
            .unwrap(),
        10
    );
}

#[test]
fn get_last_l1_fee_rate_must_be_correct() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    assert_eq!(
        soft_confirmation_rule_enforcer
            .get_last_l1_fee_rate(&mut working_set)
            .unwrap(),
        0
    );

    let mut signed_soft_confirmation_batch = SignedSoftConfirmationBatch {
        hash: [0; 32],
        da_slot_height: 0,
        da_slot_hash: [0; 32],
        pre_state_root: vec![],
        txs: vec![],
        signature: vec![],
        pub_key: vec![],
        l1_fee_rate: 1,
    };

    soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(
            &mut signed_soft_confirmation_batch.clone().into(),
            &mut working_set,
        )
        .unwrap();

    // now set to 1
    assert_eq!(
        soft_confirmation_rule_enforcer
            .get_last_l1_fee_rate(&mut working_set)
            .unwrap(),
        1
    );
}

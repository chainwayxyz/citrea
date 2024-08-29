use sov_mock_da::MockDaSpec;
use sov_modules_api::StateMapAccessor;

use crate::tests::genesis_tests::{get_soft_confirmation_rule_enforcer, TEST_CONFIG};
use crate::tests::sc_info_helper;

#[test]
fn block_count_per_da_hash_must_be_correct() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    let mut soft_confirmation_info = sc_info_helper();

    // call begin_slot_hook a couple times for da hash 0
    for _ in 0..3 {
        soft_confirmation_rule_enforcer
            .begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set)
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

    soft_confirmation_info.da_slot_hash = [1; 32];

    // call with a different da hash
    soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set)
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

    soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&sc_info_helper(), &mut working_set)
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

    soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&sc_info_helper(), &mut working_set)
        .unwrap();

    // now set to 1
    assert_eq!(
        soft_confirmation_rule_enforcer
            .get_last_l1_fee_rate(&mut working_set)
            .unwrap(),
        1
    );
}

#[test]
fn get_last_timestamp_must_be_correct() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    assert_eq!(
        soft_confirmation_rule_enforcer
            .get_last_timestamp(&mut working_set)
            .unwrap(),
        0
    );

    let timestamp = chrono::Local::now().timestamp() as u64;
    let mut soft_confirmation_info = sc_info_helper();
    soft_confirmation_info.timestamp = timestamp;

    soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set)
        .unwrap();

    assert_ne!(
        soft_confirmation_rule_enforcer
            .get_last_timestamp(&mut working_set)
            .unwrap(),
        0,
    );
    // now set to 1
    assert_eq!(
        soft_confirmation_rule_enforcer
            .get_last_timestamp(&mut working_set)
            .unwrap(),
        timestamp,
    );
}

use sov_mock_da::MockDaSpec;
use sov_modules_api::StateValueAccessor;

use crate::tests::genesis_tests::{get_soft_confirmation_rule_enforcer, TEST_CONFIG};
use crate::tests::sc_info_helper;

#[test]
fn block_count_rule_is_enforced() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    let soft_confirmation_info = sc_info_helper();

    // call end_soft_confirmation_hook a couple times for da hash 0
    for _ in 0..3 {
        soft_confirmation_rule_enforcer
            .end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set)
            .unwrap();
    }
    // the block count for da hash 0 should be 3
    assert_eq!(
        soft_confirmation_rule_enforcer
            .data
            .get(&mut working_set)
            .unwrap()
            .counter,
        3 // the counter is 2 and not 3 because the block count rule will be ignored for the first soft confirmation
    );

    // TODO: somehow find something to test this at this level
    // soft_confirmation_info.set_da_slot_hash([2; 32]);

    // call with a different da hash
    soft_confirmation_rule_enforcer
        .end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set)
        .unwrap();

    // the block count for da hash 1 should be 1
    assert_eq!(
        soft_confirmation_rule_enforcer
            .data
            .get(&mut working_set)
            .unwrap()
            .counter,
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
    soft_confirmation_info.set_time_stamp(timestamp);

    soft_confirmation_rule_enforcer
        .end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set)
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

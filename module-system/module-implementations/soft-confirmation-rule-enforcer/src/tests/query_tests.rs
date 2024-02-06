use sov_mock_da::{MockDaSpec, MockHash};
use sov_modules_api::StateMapAccessor;

use crate::tests::genesis_tests::{get_soft_confirmation_rule_enforcer, TEST_CONFIG};

#[test]
fn block_count_per_da_hash_must_be_correct() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    // call begin_slot_hook a couple times for da hash 0
    for _ in 0..3 {
        soft_confirmation_rule_enforcer
            .begin_slot_hook(&MockHash([0; 32]), &[0; 32].into(), &mut working_set)
            .unwrap();
    }
    // the block count for da hash 0 should be 3
    assert_eq!(
        soft_confirmation_rule_enforcer
            .da_root_hash_to_number
            .get(&MockHash([0; 32]), &mut working_set)
            .unwrap(),
        3
    );

    // call with a different da hash
    soft_confirmation_rule_enforcer
        .begin_slot_hook(&MockHash([1; 32]), &[0; 32].into(), &mut working_set)
        .unwrap();
    // the block count for da hash 1 should be 1
    assert_eq!(
        soft_confirmation_rule_enforcer
            .da_root_hash_to_number
            .get(&MockHash([1; 32]), &mut working_set)
            .unwrap(),
        1
    );
}

use std::str::FromStr;

use sov_mock_da::MockDaSpec;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{Context, Module, Spec};
use sov_rollup_interface::spec::SpecId;

use super::sc_info_helper;
use crate::call::CallMessage;
use crate::tests::genesis_tests::{get_l2_block_rule_enforcer, TEST_CONFIG};

type C = DefaultContext;

#[test]
fn begin_l2_block_hook_checks_max_l2_blocks_per_l1() {
    let (mut l2_block_rule_enforcer, mut working_set) =
        get_l2_block_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    let call_message = CallMessage::ModifyMaxL2BlocksPerL1 {
        max_l2_blocks_per_l1: 10,
    };

    let sender_address = <DefaultContext as Spec>::Address::from_str(
        "sov1kqrxxkwkf7t7kfuegllwkzp6jc6r6h66pgkfe7pggtm0gayl756qku2u5p",
    )
    .unwrap();

    let context = C::new(sender_address, 1, SpecId::Fork2, 0);

    let _ = l2_block_rule_enforcer
        .call(call_message, &context, &mut working_set)
        .unwrap();

    let hook_l2_block_info = sc_info_helper();

    // call begin_slot_hook 11 times
    for i in 0..11 {
        if l2_block_rule_enforcer
            .end_l2_block_hook(&hook_l2_block_info, &mut working_set)
            .is_err()
        {
            assert_eq!(i, 10);
            break;
        }
    }
}

#[test]
fn begin_l2_block_hook_checks_timestamp() {
    let (l2_block_rule_enforcer, mut working_set) =
        get_l2_block_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    let original_timestamp = chrono::Local::now().timestamp() as u64;

    let mut hook_l2_block_info = sc_info_helper();

    hook_l2_block_info.set_time_stamp(original_timestamp);

    // call first with `original_timestamp`
    let res = l2_block_rule_enforcer.end_l2_block_hook(&hook_l2_block_info, &mut working_set);

    assert!(res.is_ok());

    // now call with a timestamp before the original one.
    // should fail

    let mut hook_l2_block_info = sc_info_helper();

    hook_l2_block_info.set_time_stamp(original_timestamp - 1000);

    let res = l2_block_rule_enforcer.end_l2_block_hook(&hook_l2_block_info, &mut working_set);

    assert!(res.is_err());

    assert_eq!(
        "Timestamp should be greater",
        format!("{}", res.unwrap_err())
    );

    // now call with a timestamp after the original one.
    // should not fail
    let mut hook_l2_block_info = sc_info_helper();

    hook_l2_block_info.set_time_stamp(original_timestamp + 1000);

    let res = l2_block_rule_enforcer.end_l2_block_hook(&hook_l2_block_info, &mut working_set);

    assert!(res.is_ok());
}

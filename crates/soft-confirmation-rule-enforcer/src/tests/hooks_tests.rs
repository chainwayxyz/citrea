use std::str::FromStr;

use sov_mock_da::MockDaSpec;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{Context, Module, Spec};
use sov_rollup_interface::spec::SpecId;

use super::sc_info_helper;
use crate::call::CallMessage;
use crate::tests::genesis_tests::{get_soft_confirmation_rule_enforcer, TEST_CONFIG};

type C = DefaultContext;

#[test]
fn begin_soft_confirmation_hook_checks_max_l2_blocks_per_l1() {
    let (mut soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    let call_message = CallMessage::ModifyMaxL2BlocksPerL1 {
        max_l2_blocks_per_l1: 10,
    };

    let sender_address = <DefaultContext as Spec>::Address::from_str(
        "sov1l6n2cku82yfqld30lanm2nfw43n2auc8clw7r5u5m6s7p8jrm4zqrr8r94",
    )
    .unwrap();

    let context = C::new(sender_address, 1, SpecId::Genesis, 0);

    let _ = soft_confirmation_rule_enforcer
        .call(call_message, &context, &mut working_set)
        .unwrap();

    let hook_soft_confirmation_info = sc_info_helper();

    // call begin_slot_hook 11 times
    for i in 0..11 {
        if soft_confirmation_rule_enforcer
            .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set)
            .is_err()
        {
            assert_eq!(i, 10);
            break;
        }
    }
}

#[test]
fn begin_soft_confirmation_hook_checks_timestamp() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    let original_timestamp = chrono::Local::now().timestamp() as u64;

    let mut hook_soft_confirmation_info = sc_info_helper();

    hook_soft_confirmation_info.timestamp = original_timestamp;

    // call first with `original_timestamp`
    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);

    assert!(res.is_ok());

    // now call with a timestamp before the original one.
    // should fail

    let mut hook_soft_confirmation_info = sc_info_helper();

    hook_soft_confirmation_info.timestamp = original_timestamp - 1000;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);

    assert!(res.is_err());

    assert_eq!(
        "Timestamp should be greater",
        format!("{}", res.unwrap_err())
    );

    // now call with a timestamp after the original one.
    // should not fail
    let mut hook_soft_confirmation_info = sc_info_helper();

    hook_soft_confirmation_info.timestamp = original_timestamp + 1000;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);

    assert!(res.is_ok());
}

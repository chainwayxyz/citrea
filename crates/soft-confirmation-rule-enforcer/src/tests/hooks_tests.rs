use std::str::FromStr;

use sov_mock_da::MockDaSpec;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, Spec};
use sov_rollup_interface::spec::SpecId;

use super::sc_info_helper;
use crate::call::CallMessage;
use crate::tests::genesis_tests::{get_soft_confirmation_rule_enforcer, TEST_CONFIG};

type C = DefaultContext;

#[test]
fn begin_soft_confirmation_hook_checks_max_l2_blocks_per_l1() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    let call_message = CallMessage::ModifyMaxL2BlocksPerL1 {
        max_l2_blocks_per_l1: 10,
    };

    let sender_address = <DefaultContext as Spec>::Address::from_str(
        "sov1l6n2cku82yfqld30lanm2nfw43n2auc8clw7r5u5m6s7p8jrm4zqrr8r94",
    )
    .unwrap();

    let sequencer_address = generate_address::<C>("sequencer");
    let context = C::new(sender_address, sequencer_address, 1, SpecId::Genesis, 0);

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
fn begin_soft_confirmation_hook_checks_l1_fee_rate() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    let mut hook_soft_confirmation_info = sc_info_helper();

    // call first with 100 fee rate to set last_l1_fee_rate
    hook_soft_confirmation_info.l1_fee_rate = 100;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);

    assert!(res.is_ok());

    // now call with 111 fee rate
    // should fail
    let mut hook_soft_confirmation_info = sc_info_helper();

    hook_soft_confirmation_info.l1_fee_rate = 111;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);

    assert!(res.is_err());
    assert_eq!(
        "Other error: L1 fee rate changed more than allowed",
        format!("{}", res.unwrap_err())
    );

    // now call with 110 fee rate
    // should not fail
    let mut hook_soft_confirmation_info = sc_info_helper();

    hook_soft_confirmation_info.l1_fee_rate = 110;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);

    assert!(res.is_ok());

    // now 122 should'nt pass but 121 should
    let mut hook_soft_confirmation_info = sc_info_helper();

    hook_soft_confirmation_info.l1_fee_rate = 122;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);

    assert!(res.is_err());

    let mut hook_soft_confirmation_info = sc_info_helper();

    hook_soft_confirmation_info.l1_fee_rate = 121;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);

    assert!(res.is_ok());

    // reset back to 100 so calculations are easier
    let mut hook_soft_confirmation_info = sc_info_helper();

    hook_soft_confirmation_info.l1_fee_rate = 109;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);
    assert!(res.is_ok());

    let mut hook_soft_confirmation_info = sc_info_helper();

    hook_soft_confirmation_info.l1_fee_rate = 100;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);
    assert!(res.is_ok());

    let mut hook_soft_confirmation_info = sc_info_helper();

    // change da root hash so it doesnt fail
    hook_soft_confirmation_info.da_slot_hash = [1; 32];
    // now 89 should'nt pass but 90 should
    hook_soft_confirmation_info.l1_fee_rate = 89;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);

    assert!(res.is_err());

    assert_eq!(
        "Other error: L1 fee rate changed more than allowed",
        format!("{}", res.unwrap_err())
    );

    let mut hook_soft_confirmation_info = sc_info_helper();

    hook_soft_confirmation_info.l1_fee_rate = 90;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);

    assert!(res.is_ok());

    // since 90 passed now e.g. 89 should pass

    let mut hook_soft_confirmation_info = sc_info_helper();

    hook_soft_confirmation_info.l1_fee_rate = 89;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&hook_soft_confirmation_info, &mut working_set);

    assert!(res.is_ok());
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
        "Other error: Timestamp should be greater than last timestamp",
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

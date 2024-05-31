use std::str::FromStr;

use sov_mock_da::MockDaSpec;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, Spec, StateValueAccessor};

use crate::call::CallMessage;
use crate::tests::genesis_tests::{get_soft_confirmation_rule_enforcer, TEST_CONFIG};

type C = DefaultContext;

#[test]
fn change_max_l2_blocks_per_l1_and_authority() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    let call_message = CallMessage::ModifyLimitingNumber {
        max_l2_blocks_per_l1: 999,
    };

    let sender_address = <DefaultContext as Spec>::Address::from_str(
        "sov1l6n2cku82yfqld30lanm2nfw43n2auc8clw7r5u5m6s7p8jrm4zqrr8r94",
    )
    .unwrap();

    let sequencer_address = generate_address::<C>("sequencer");
    let context = C::new(sender_address, sequencer_address, 1);

    let _ = soft_confirmation_rule_enforcer
        .call(call_message, &context, &mut working_set)
        .unwrap();

    assert_eq!(
        soft_confirmation_rule_enforcer
            .max_l2_blocks_per_l1
            .get(&mut working_set)
            .unwrap(),
        999
    );

    let new_authority = generate_address::<C>("braveNewWorld");
    let call_message = CallMessage::ChangeAuthority { new_authority };

    let _ = soft_confirmation_rule_enforcer
        .call(call_message, &context, &mut working_set)
        .unwrap();

    assert_eq!(
        soft_confirmation_rule_enforcer
            .authority
            .get(&mut working_set)
            .unwrap(),
        new_authority
    );

    let modify_max_l2_blocks_per_l1_message = CallMessage::ModifyLimitingNumber {
        max_l2_blocks_per_l1: 123,
    };
    // after the authority is changed we cannot call the modules function with the old context
    assert!(soft_confirmation_rule_enforcer
        .call(
            modify_max_l2_blocks_per_l1_message.clone(),
            &context,
            &mut working_set
        )
        .is_err());

    let failed_authority = generate_address::<C>("brutus");
    let change_authority_message = CallMessage::ChangeAuthority {
        new_authority: failed_authority,
    };
    assert!(soft_confirmation_rule_enforcer
        .call(change_authority_message.clone(), &context, &mut working_set)
        .is_err());
    // make sure it is still the same
    assert_eq!(
        soft_confirmation_rule_enforcer
            .max_l2_blocks_per_l1
            .get(&mut working_set)
            .unwrap(),
        999
    );
    assert_eq!(
        soft_confirmation_rule_enforcer
            .authority
            .get(&mut working_set)
            .unwrap(),
        new_authority
    );

    // create a new context with the new authority
    let context = C::new(new_authority, sequencer_address, 1);
    let _ = soft_confirmation_rule_enforcer
        .call(
            modify_max_l2_blocks_per_l1_message,
            &context,
            &mut working_set,
        )
        .unwrap();

    assert_eq!(
        soft_confirmation_rule_enforcer
            .max_l2_blocks_per_l1
            .get(&mut working_set)
            .unwrap(),
        123
    );

    let _ = soft_confirmation_rule_enforcer
        .call(change_authority_message, &context, &mut working_set)
        .unwrap();
    assert_eq!(
        soft_confirmation_rule_enforcer
            .authority
            .get(&mut working_set)
            .unwrap(),
        failed_authority
    );

    //
}

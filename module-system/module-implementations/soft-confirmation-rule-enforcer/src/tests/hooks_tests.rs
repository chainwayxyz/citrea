use std::str::FromStr;

use sov_mock_da::{MockDaSpec, MockHash};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, Spec};

use crate::call::CallMessage;
use crate::tests::genesis_tests::{get_soft_confirmation_rule_enforcer, TEST_CONFIG};

type C = DefaultContext;

#[test]
fn begin_slot_hook_checks_limiting_number() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);

    let call_message = CallMessage::ModifyLimitingNumber {
        limiting_number: 10,
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

    // call begin_slot_hook 11 times
    for i in 0..11 {
        if soft_confirmation_rule_enforcer
            .begin_slot_hook(&MockHash([0; 32]), &[0; 32].into(), &mut working_set)
            .is_err()
        {
            assert_eq!(i, 10);
            break;
        }
    }
}

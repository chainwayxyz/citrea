use std::str::FromStr;

use anyhow::anyhow;
use sov_mock_da::MockDaSpec;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, Spec, StateValueAccessor};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmationBatch;

use crate::call::CallMessage;
use crate::tests::genesis_tests::{get_soft_confirmation_rule_enforcer, TEST_CONFIG};

type C = DefaultContext;

#[test]
fn begin_soft_confirmation_hook_checks_limiting_number() {
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

    // call begin_slot_hook 11 times
    for i in 0..11 {
        if soft_confirmation_rule_enforcer
            .begin_soft_confirmation_hook(&mut signed_soft_confirmation_batch, &mut working_set)
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

    let mut signed_soft_confirmation_batch = SignedSoftConfirmationBatch {
        hash: [0; 32],
        da_slot_height: 0,
        da_slot_hash: [0; 32],
        pre_state_root: vec![],
        txs: vec![],
        signature: vec![],
        pub_key: vec![],
        l1_fee_rate: 100,
    };

    // call first with 100 fee rate to set last_l1_fee_rate
    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&mut signed_soft_confirmation_batch, &mut working_set);

    assert!(res.is_ok());

    // now call with 111 fee rate
    // should fail
    signed_soft_confirmation_batch.l1_fee_rate = 111;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&mut signed_soft_confirmation_batch, &mut working_set);

    assert!(res.is_err());
    assert_eq!(
        format!(
            "{}",
            anyhow!(
                "L1 fee rate {} changed more than allowed limit %{}",
                signed_soft_confirmation_batch.l1_fee_rate,
                soft_confirmation_rule_enforcer
                    .l1_fee_rate_change_percentage
                    .get(&mut working_set)
                    .unwrap()
            )
        ),
        format!("{}", res.unwrap_err())
    );

    // now call with 110 fee rate
    // should not fail
    signed_soft_confirmation_batch.l1_fee_rate = 110;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&mut signed_soft_confirmation_batch, &mut working_set);

    assert!(res.is_ok());

    // now 122 should'nt pass but 121 should
    signed_soft_confirmation_batch.l1_fee_rate = 122;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&mut signed_soft_confirmation_batch, &mut working_set);

    assert!(res.is_err());

    signed_soft_confirmation_batch.l1_fee_rate = 121;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&mut signed_soft_confirmation_batch, &mut working_set);

    assert!(res.is_ok());

    // reset back to 100 so calculations are easier
    signed_soft_confirmation_batch.l1_fee_rate = 109;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&mut signed_soft_confirmation_batch, &mut working_set);
    assert!(res.is_ok());
    signed_soft_confirmation_batch.l1_fee_rate = 100;
    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&mut signed_soft_confirmation_batch, &mut working_set);
    assert!(res.is_ok());

    // change da root hash so it doesnt fail
    signed_soft_confirmation_batch.da_slot_hash = [1; 32];

    // now 89 should'nt pass but 90 should
    signed_soft_confirmation_batch.l1_fee_rate = 89;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&mut signed_soft_confirmation_batch, &mut working_set);

    assert!(res.is_err());

    assert_eq!(
        format!(
            "{}",
            anyhow!(
                "L1 fee rate {} changed more than allowed limit %{}",
                signed_soft_confirmation_batch.l1_fee_rate,
                soft_confirmation_rule_enforcer
                    .l1_fee_rate_change_percentage
                    .get(&mut working_set)
                    .unwrap()
            )
        ),
        format!("{}", res.unwrap_err())
    );

    signed_soft_confirmation_batch.l1_fee_rate = 90;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&mut signed_soft_confirmation_batch, &mut working_set);

    assert!(res.is_ok());

    // since 90 past now e.g. 89 should pass

    signed_soft_confirmation_batch.l1_fee_rate = 89;

    let res = soft_confirmation_rule_enforcer
        .begin_soft_confirmation_hook(&mut signed_soft_confirmation_batch, &mut working_set);

    assert!(res.is_ok());
}

use std::str::FromStr;

use lazy_static::lazy_static;
use sov_mock_da::MockDaSpec;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{DaSpec, Module, Spec, StateValueAccessor, WorkingSet};
use sov_prover_storage_manager::new_orphan_storage;

use crate::{SoftConfirmationRuleEnforcer, SoftConfirmationRuleEnforcerConfig};

type C = DefaultContext;

lazy_static! {
    pub(crate) static ref TEST_CONFIG: SoftConfirmationRuleEnforcerConfig<C> =
        SoftConfirmationRuleEnforcerConfig {
            limiting_number: 10,
            authority: <DefaultContext as Spec>::Address::from_str(
                "sov1l6n2cku82yfqld30lanm2nfw43n2auc8clw7r5u5m6s7p8jrm4zqrr8r94"
            )
            .unwrap(),
            l1_fee_rate_change_percentage: 10,
        };
}

#[test]
fn genesis_data() {
    let (soft_confirmation_rule_enforcer, mut working_set) =
        get_soft_confirmation_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);
    let limiting_number = &TEST_CONFIG.limiting_number;
    let authority = &TEST_CONFIG.authority;
    let l1_fee_rate_change_percentage = &TEST_CONFIG.l1_fee_rate_change_percentage;

    assert_eq!(
        soft_confirmation_rule_enforcer
            .limiting_number
            .get(&mut working_set)
            .unwrap(),
        *limiting_number
    );
    assert_eq!(
        soft_confirmation_rule_enforcer
            .authority
            .get(&mut working_set)
            .unwrap(),
        *authority
    );

    assert_eq!(
        soft_confirmation_rule_enforcer
            .l1_fee_rate_change_percentage
            .get(&mut working_set)
            .unwrap(),
        *l1_fee_rate_change_percentage
    );
}

pub(crate) fn get_soft_confirmation_rule_enforcer<Da: DaSpec>(
    config: &SoftConfirmationRuleEnforcerConfig<C>,
) -> (
    SoftConfirmationRuleEnforcer<C, Da>,
    WorkingSet<DefaultContext>,
) {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut working_set = WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());
    let soft_confirmation_rule_enforcer = SoftConfirmationRuleEnforcer::<C, Da>::default();
    soft_confirmation_rule_enforcer
        .genesis(config, &mut working_set)
        .unwrap();

    (soft_confirmation_rule_enforcer, working_set)
}

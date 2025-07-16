use std::str::FromStr;
use std::sync::LazyLock;

use sov_mock_da::MockDaSpec;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{DaSpec, Module, Spec, StateValueAccessor, WorkingSet};
use sov_prover_storage_manager::new_orphan_storage;
use sov_state::ProverStorage;

use crate::{L2BlockRuleEnforcer, L2BlockRuleEnforcerConfig};

type C = DefaultContext;

pub(crate) static TEST_CONFIG: LazyLock<L2BlockRuleEnforcerConfig> =
    LazyLock::new(|| L2BlockRuleEnforcerConfig {
        max_l2_blocks_per_l1: 10,
        authority: <DefaultContext as Spec>::Address::from_str(
            "sov1kqrxxkwkf7t7kfuegllwkzp6jc6r6h66pgkfe7pggtm0gayl756qku2u5p",
        )
        .unwrap(),
    });

#[test]
fn genesis_data() {
    let (l2_block_rule_enforcer, mut working_set) =
        get_l2_block_rule_enforcer::<MockDaSpec>(&TEST_CONFIG);
    let max_l2_blocks_per_l1 = &TEST_CONFIG.max_l2_blocks_per_l1;
    let authority = &TEST_CONFIG.authority;

    assert_eq!(
        l2_block_rule_enforcer
            .data
            .get(&mut working_set)
            .unwrap()
            .max_l2_blocks_per_l1,
        *max_l2_blocks_per_l1
    );
    assert_eq!(
        l2_block_rule_enforcer
            .authority
            .get(&mut working_set)
            .unwrap(),
        *authority
    );
}

pub(crate) fn get_l2_block_rule_enforcer<Da: DaSpec>(
    config: &L2BlockRuleEnforcerConfig,
) -> (L2BlockRuleEnforcer<C, Da>, WorkingSet<ProverStorage>) {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut working_set = WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());
    let l2_block_rule_enforcer = L2BlockRuleEnforcer::<C, Da>::default();
    l2_block_rule_enforcer.genesis(config, &mut working_set);

    (l2_block_rule_enforcer, working_set)
}

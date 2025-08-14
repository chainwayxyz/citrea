use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use citrea_primitives::forks::get_forks;
use sov_db::ledger_db::SharedLedgerOps;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::StateDiff;

pub fn merge_state_diffs(old_diff: StateDiff, new_diff: StateDiff) -> StateDiff {
    let mut new_diff_map: HashMap<Arc<[u8]>, Option<Arc<[u8]>>> = HashMap::from_iter(old_diff);

    new_diff_map.extend(new_diff);
    new_diff_map.into_iter().collect()
}

pub fn check_l2_block_exists<DB: SharedLedgerOps>(ledger_db: &DB, l2_height: u64) -> bool {
    let Some(head_l2_height) = ledger_db
        .get_head_l2_block_height()
        .expect("Ledger db read must not fail")
    else {
        return false;
    };

    head_l2_height >= l2_height
}

pub fn read_env(key: &str) -> anyhow::Result<String> {
    env::var(key).map_err(|_| anyhow::anyhow!("Env {} missing or invalid UTF-8", key))
}

// If tangerine activation height is 0, return 1
// Because in tests when the first l2 block for the first sequencer commitment is needed
// Tangerine activation height should be sent
// If it is 0, it errors out because l2 block 0 is not valid
// So for only in tests, if tangerine activation height is 0, return 1
// In production, it will return whatever the activation height is
// If network starts from Fork3, use 1 as the activation height
// as we'd like to behave the same way
pub fn get_tangerine_activation_height_non_zero() -> u64 {
    let forks = get_forks();

    if forks[0].spec_id > SpecId::Tangerine {
        return 1;
    }

    let fork = forks
        .iter()
        .find(|f| f.spec_id == SpecId::Tangerine)
        .expect("Tangerine should exist");
    if fork.activation_height == 0 {
        return 1;
    }
    fork.activation_height
}

#[cfg(test)]
mod call_tests;
#[cfg(test)]
mod genesis_tests;
#[cfg(test)]
mod hooks_tests;
#[cfg(test)]
mod query_tests;

use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::SpecId;

fn sc_info_helper() -> HookL2BlockInfo {
    HookL2BlockInfo {
        l2_height: 1,
        pre_state_root: [0; 32],
        current_spec: SpecId::Fork2,
        sequencer_pub_key: vec![0; 32],
        l1_fee_rate: 1,
        timestamp: 10,
    }
}

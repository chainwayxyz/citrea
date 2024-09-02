#[cfg(test)]
mod call_tests;
#[cfg(test)]
mod genesis_tests;
#[cfg(test)]
mod hooks_tests;
#[cfg(test)]
mod query_tests;

use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::SpecId;

fn sc_info_helper() -> HookSoftConfirmationInfo {
    HookSoftConfirmationInfo {
        l2_height: 1,
        da_slot_height: 1,
        da_slot_hash: [1; 32],
        da_slot_txs_commitment: [0; 32],
        pre_state_root: vec![0; 32],
        current_spec: SpecId::Genesis,
        pub_key: vec![0; 32],
        deposit_data: vec![],
        l1_fee_rate: 1,
        timestamp: 10,
    }
}

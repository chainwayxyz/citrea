#[cfg(test)]
mod call_tests;
#[cfg(test)]
mod genesis_tests;
#[cfg(test)]
mod hooks_tests;
#[cfg(test)]
mod query_tests;

use borsh::BorshDeserialize;
use sov_keys::default_signature::K256PublicKey;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::SpecId;

fn sc_info_helper() -> HookL2BlockInfo {
    HookL2BlockInfo {
        l2_height: 1,
        pre_state_root: [0; 32],
        current_spec: SpecId::Fork2,
        sequencer_pub_key: K256PublicKey::try_from_slice(
            &hex::decode("036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7")
                .unwrap(),
        )
        .unwrap(),
        l1_fee_rate: 1,
        timestamp: 10,
    }
}

#[cfg(test)]
mod call_tests;
#[cfg(test)]
mod genesis_tests;
#[cfg(test)]
mod hooks_tests;
#[cfg(test)]
mod query_tests;

use borsh::BorshDeserialize;
use citrea_evm::{keccak256, Evm, BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS, U256};
use sov_keys::default_signature::K256PublicKey;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::{SpecId, WorkingSet};
use sov_state::ProverStorage;

fn sc_info_helper() -> HookL2BlockInfo {
    HookL2BlockInfo {
        l2_height: 1,
        pre_state_root: [0; 32],
        current_spec: SpecId::Tangerine,
        sequencer_pub_key: K256PublicKey::try_from_slice(
            &hex::decode("036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7")
                .unwrap(),
        )
        .unwrap(),
        l1_fee_rate: 1,
        timestamp: 10,
    }
}

// inserts single height and hash to evm
fn setup_evm(working_set: &mut WorkingSet<ProverStorage>) {
    let evm = Evm::<DefaultContext>::default();
    evm.storage_set(
        &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
        &U256::ZERO,
        &U256::from(1),
        working_set,
    );

    // now the corresponding height's hash

    let mut bytes = [0u8; 64];
    bytes[0..32]
        .copy_from_slice(&(U256::from(1).saturating_sub(U256::from(1))).to_be_bytes::<32>());
    bytes[32..64].copy_from_slice(&U256::from(1).to_be_bytes::<32>());

    evm.storage_set(
        &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
        &keccak256(bytes).into(),
        &U256::from_be_bytes([1u8; 32]),
        working_set,
    );
}

fn add_another_l1_hash(working_set: &mut WorkingSet<ProverStorage>) {
    let evm = Evm::<DefaultContext>::default();

    evm.storage_set(
        &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
        &U256::ZERO,
        &U256::from(2),
        working_set,
    );

    let mut bytes = [0u8; 64];
    bytes[0..32]
        .copy_from_slice(&(U256::from(2).saturating_sub(U256::from(1))).to_be_bytes::<32>());
    bytes[32..64].copy_from_slice(&U256::from(1).to_be_bytes::<32>());

    evm.storage_set(
        &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
        &keccak256(bytes).into(),
        &U256::from_be_bytes([2u8; 32]),
        working_set,
    );
}

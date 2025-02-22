#![no_main]
use citrea_primitives::forks::NIGHTLY_FORKS;
use citrea_risc0_adapter::guest::Risc0Guest;
use citrea_stf::runtime::CitreaRuntime;
use citrea_stf::verifier::StateTransitionVerifier;

use sov_mock_da::MockDaSpec;
use sov_modules_api::default_context::ZkDefaultContext;
use sov_modules_api::fork::Fork;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_rollup_interface::zk::ZkvmGuest;
use sov_state::ZkStorage;

risc0_zkvm::guest::entry!(main);

const SEQUENCER_PUBLIC_KEY: [u8; 32] = match const_hex::const_decode_to_array(
    b"204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21",
) {
    Ok(pub_key) => pub_key,
    Err(_) => panic!("Can't happen"),
};

const SEQUENCER_K256_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
    b"036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7",
) {
    Ok(pub_key) => pub_key,
    Err(_) => panic!("Can't happen"),
};

const _SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
    b"02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9",
) {
    Ok(pub_key) => pub_key,
    Err(_) => panic!("Can't happen"),
};

const FORKS: &[Fork] = &NIGHTLY_FORKS;

fn get_forks() -> &'static [Fork] {
    #[cfg(feature = "testing")]
    {
        let all_forks_flag: u32 = risc0_zkvm::guest::env::read();
        println!("All forks: {all_forks_flag}");
        if all_forks_flag == 1 {
            return &citrea_primitives::forks::ALL_FORKS;
        }
    }
    FORKS
}

pub fn main() {
    let guest = Risc0Guest::new();
    let storage = ZkStorage::new();
    let stf = StfBlueprint::new();

    let mut stf_verifier: StateTransitionVerifier<
        ZkDefaultContext,
        MockDaSpec,
        CitreaRuntime<_, _>,
    > = StateTransitionVerifier::new(stf);

    let out = stf_verifier.run_sequencer_commitments_in_da_slot(
        &guest,
        storage,
        &SEQUENCER_PUBLIC_KEY,
        &SEQUENCER_K256_PUBLIC_KEY,
        get_forks(),
    );

    guest.commit(&out);
}

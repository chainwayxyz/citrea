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

const SEQUENCER_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(
    b"036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7",
) {
    Ok(pub_key) => pub_key,
    Err(_) => panic!("Can't happen"),
};

const INITIAL_PREV_L2_BLOCK_HASH: [u8; 32] = [0; 32];

const FORKS: &[Fork] = &NIGHTLY_FORKS;

fn get_forks() -> &'static [Fork] {
    #[cfg(feature = "testing")]
    {
        if std::env::var("ALL_FORKS").is_ok() {
            println!("Enabling ALL_FORKS");
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
        Some(INITIAL_PREV_L2_BLOCK_HASH),
        get_forks(),
    );

    guest.commit(&out);
}

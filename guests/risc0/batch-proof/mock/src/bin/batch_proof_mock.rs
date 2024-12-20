#![no_main]
use citrea_primitives::forks::NIGHTLY_FORKS;
use citrea_stf::runtime::Runtime;
use citrea_stf::StfVerifier;
use sov_mock_da::MockDaVerifier;
use sov_modules_api::default_context::ZkDefaultContext;
use sov_modules_api::fork::Fork;
use sov_modules_stf_blueprint::StfBlueprint;
use citrea_risc0_adapter::guest::Risc0Guest;
use sov_state::ZkStorage;
use sov_rollup_interface::zk::ZkvmGuest;

risc0_zkvm::guest::entry!(main);

const SEQUENCER_PUBLIC_KEY: [u8; 32] = match const_hex::const_decode_to_array(b"204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21") {
    Ok(pub_key) => pub_key,
    Err(_) => panic!("Can't happen"),
};

const SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = match const_hex::const_decode_to_array(b"02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9") {
    Ok(pub_key) => pub_key,
    Err(_) => panic!("Can't happen"),
};

const FORKS: &[Fork] = &NIGHTLY_FORKS;

pub fn main() {
    let guest = Risc0Guest::new();
    let storage = ZkStorage::new();
    let stf = StfBlueprint::new();

    let mut stf_verifier: StfVerifier<_, ZkDefaultContext, Runtime<_, _>> = StfVerifier::new(
        stf,
        MockDaVerifier {}
    );

    let data = guest.read_from_host();

    let out = stf_verifier
        .run_sequencer_commitments_in_da_slot(data, storage, &SEQUENCER_PUBLIC_KEY, &SEQUENCER_DA_PUBLIC_KEY, FORKS)
        .expect("Prover must be honest");

    guest.commit(&out);
}

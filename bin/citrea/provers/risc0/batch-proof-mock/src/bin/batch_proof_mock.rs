#![no_main]
use citrea_stf::runtime::Runtime;
use citrea_stf::StfVerifier;
use sov_mock_da::MockDaVerifier;
use sov_modules_api::default_context::ZkDefaultContext;
use sov_modules_stf_blueprint::StfBlueprint;
use citrea_risc0_adapter::guest::Risc0Guest;
use sov_state::ZkStorage;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let guest = Risc0Guest::new();
    let storage = ZkStorage::new();

    let stf: StfBlueprint<ZkDefaultContext, _, Runtime<_, _>> = StfBlueprint::new();

    let mut stf_verifier = StfVerifier::new(stf, MockDaVerifier {});

    stf_verifier
        .run_sequencer_commitments_in_da_slot(guest, storage)
        .expect("Prover must be honest");
}

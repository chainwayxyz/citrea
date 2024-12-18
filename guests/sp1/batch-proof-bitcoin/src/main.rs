#![no_main]
sp1_zkvm::entrypoint!(main);

use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use citrea_sp1::guest::SP1Guest;
use citrea_stf::runtime::Runtime;
use citrea_stf::StfVerifier;
use sov_modules_api::default_context::ZkDefaultContext;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::zk::ZkvmGuest;
use sov_state::ZkStorage;

pub fn main() {
    let guest = SP1Guest::new();
    let storage = ZkStorage::new();
    let stf = StfBlueprint::new();

    let mut stf_verifier: StfVerifier<_, ZkDefaultContext, Runtime<_, _>> = StfVerifier::new(
        stf,
        BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
            to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
        }),
    );

    let data = guest.read_from_host();

    let out = stf_verifier
        .run_sequencer_commitments_in_da_slot(data, storage)
        .expect("Prover must be honest");

    guest.commit(&out);
}

#![no_main]
use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_primitives::{REVEAL_BATCH_PROOF_PREFIX, REVEAL_LIGHT_CLIENT_PREFIX};
use citrea_stf::runtime::Runtime;
use citrea_stf::StfVerifier;
use sov_modules_api::default_context::ZkDefaultContext;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::da::DaVerifier;
use sov_state::ZkStorage;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let guest = Risc0Guest::new();
    let storage = ZkStorage::new();

    let stf: StfBlueprint<ZkDefaultContext, _, _, Runtime<_, _>> = StfBlueprint::new();

    let mut stf_verifier = StfVerifier::new(
        stf,
        BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: REVEAL_BATCH_PROOF_PREFIX.to_vec(),
            reveal_light_client_prefix: REVEAL_LIGHT_CLIENT_PREFIX.to_vec(),
        }),
    );

    stf_verifier
        .run_sequencer_commitments_in_da_slot(guest, storage)
        .expect("Prover must be honest");
}

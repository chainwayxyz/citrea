#![no_main]
use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use citrea_risc0_adapter::guest::Risc0Guest;
use citrea_stf::runtime::Runtime;
use citrea_stf::StfVerifier;
use sov_modules_api::default_context::ZkDefaultContext;
use sov_modules_api::fork::{parse_fork_list_utf8, Fork};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::zk::ZkvmGuest;
use sov_state::ZkStorage;

risc0_zkvm::guest::entry!(main);

const SEQUENCER_PUBLIC_KEY: [u8; 32] = {
    let hex_pub_key = env!("SEQUENCER_PUBLIC_KEY");

    match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("SEQUENCER_PUBLIC_KEY must be valid 32-byte hex string"),
    }
};

const SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = {
    let hex_pub_key = env!("SEQUENCER_DA_PUBLIC_KEY");

    match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
        // TODO: maybe verify the first byte?
        Ok(pub_key) => pub_key,
        Err(_) => panic!("SEQUENCER_DA_PUBLIC_KEY must be valid 33-byte hex string"),
    }
};

// Temporary variable to allow FORKS static reference to be valid
const TEMP_FORKS: ([Fork; 50], usize) = {
    let forks_str = env!("FORKS");

    match parse_fork_list_utf8(forks_str) {
        Some((forks, count)) => {
            if count == 0 {
                panic!("FORKS can not be empty");
            }
            (forks, count)
        }
        None => panic!("FORKS must be valid comma separated list"),
    }
};

const FORKS: &[Fork] = {
    let (temp_forks, count) = &TEMP_FORKS;
    temp_forks.split_at(*count).0
};

pub fn main() {
    let guest = Risc0Guest::new();
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

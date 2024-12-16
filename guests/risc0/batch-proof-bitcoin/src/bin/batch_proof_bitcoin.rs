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

const SEQUENCER_PUBLIC_KEY: [u8; 32] = match option_env!("SEQUENCER_PUBLIC_KEY") {
    Some(hex_pub_key) => {
        match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
            Ok(pub_key) => pub_key,
            Err(_) => panic!("SEQUENCER_PUBLIC_KEY must be valid 32-byte hex string"),
        }
    }
    // TODO: what to do here?
    None => [0; 32],
};

const SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = match option_env!("SEQUENCER_DA_PUBLIC_KEY") {
    Some(hex_pub_key) => {
        match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
            // TODO: maybe verify the first byte?
            Ok(pub_key) => pub_key,
            Err(_) => panic!("SEQUENCER_DA_PUBLIC_KEY must be valid 33-byte hex string"),
        }
    }
    // TODO: what to do here?
    None => [0; 33],
};

// Temporary variable to allow FORKS static reference to be valid
const TEMP_FORKS: Option<([Fork; 100], usize)> = match option_env!("FORKS") {
    Some(forks_str) => match parse_fork_list_utf8(forks_str) {
        Some((forks, count)) => {
            if count == 0 {
                panic!("FORKS can not be empty");
            }
            Some((forks, count))
        }
        None => panic!("FORKS must be valid comma separated list"),
    },
    // TODO: what to do here?
    None => None,
};

const FORKS: &[Fork] = match &TEMP_FORKS {
    Some((forks, count)) => {
        forks.split_at(*count).0
    }
    // TODO: what to do here?
    None => &[],
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

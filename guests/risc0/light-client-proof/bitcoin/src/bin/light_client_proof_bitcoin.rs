#![no_main]
use bitcoin_da::spec::{BitcoinSpec, RollupParams};
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_light_client_prover::circuit::initial_values::bitcoinda;
use citrea_light_client_prover::circuit::LightClientProofCircuit;
use citrea_primitives::REVEAL_TX_PREFIX;
use citrea_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;
use sov_state::ZkStorage;

risc0_zkvm::guest::entry!(main);

const NETWORK: Network = match option_env!("CITREA_NETWORK") {
    Some(network) => match Network::const_from_str(network) {
        Some(network) => network,
        None => panic!("Invalid CITREA_NETWORK value"),
    },
    None => Network::Nightly,
};

const L2_GENESIS_ROOT: [u8; 32] = {
    match NETWORK {
        Network::Mainnet => bitcoinda::MAINNET_GENESIS_ROOT,
        Network::Testnet => bitcoinda::TESTNET_GENESIS_ROOT,
        Network::Devnet => bitcoinda::DEVNET_GENESIS_ROOT,
        Network::Nightly => bitcoinda::NIGHTLY_GENESIS_ROOT,
        Network::TestNetworkWithForks => bitcoinda::TEST_NETWORK_WITH_FORKS_GENESIS_ROOT,
    }
};

const INITIAL_BATCH_PROOF_METHOD_IDS: &[(u64, [u32; 8])] = {
    match NETWORK {
        Network::Mainnet => bitcoinda::MAINNET_INITIAL_BATCH_PROOF_METHOD_IDS,
        Network::Testnet => bitcoinda::TESTNET_INITIAL_BATCH_PROOF_METHOD_IDS,
        Network::Devnet => bitcoinda::DEVNET_INITIAL_BATCH_PROOF_METHOD_IDS,
        Network::Nightly => bitcoinda::NIGHTLY_INITIAL_BATCH_PROOF_METHOD_IDS,
        Network::TestNetworkWithForks => {
            bitcoinda::TEST_NETWORK_WITH_FORKS_INITIAL_BATCH_PROOF_METHOD_IDS
        }
    }
};

const SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = {
    match NETWORK {
        Network::Mainnet => bitcoinda::MAINNET_SEQUENCER_DA_PUBLIC_KEY,
        Network::Testnet => bitcoinda::TESTNET_SEQUENCER_DA_PUBLIC_KEY,
        Network::Devnet => bitcoinda::DEVNET_SEQUENCER_DA_PUBLIC_KEY,
        Network::Nightly => bitcoinda::NIGHTLY_SEQUENCER_DA_PUBLIC_KEY,
        Network::TestNetworkWithForks => bitcoinda::TEST_NETWORK_WITH_FORKS_SEQUENCER_DA_PUBLIC_KEY,
    }
};

const BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = {
    match NETWORK {
        Network::Mainnet => bitcoinda::MAINNET_BATCH_PROVER_DA_PUBLIC_KEY,
        Network::Testnet => bitcoinda::TESTNET_BATCH_PROVER_DA_PUBLIC_KEY,
        Network::Devnet => bitcoinda::DEVNET_BATCH_PROVER_DA_PUBLIC_KEY,
        Network::Nightly => bitcoinda::NIGHTLY_BATCH_PROVER_DA_PUBLIC_KEY,
        Network::TestNetworkWithForks => {
            bitcoinda::TEST_NETWORK_WITH_FORKS_BATCH_PROVER_DA_PUBLIC_KEY
        }
    }
};

pub const METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY: [u8; 33] = {
    match NETWORK {
        Network::Mainnet => bitcoinda::MAINNET_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY,
        Network::Testnet => bitcoinda::TESTNET_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY,
        Network::Devnet => bitcoinda::DEVNET_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY,
        Network::Nightly => bitcoinda::NIGHTLY_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY,
        Network::TestNetworkWithForks => {
            bitcoinda::TEST_NETWORK_WITH_FORKS_METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY
        }
    }
};

pub fn main() {
    let storage = ZkStorage::new();

    let guest = Risc0Guest::new();

    let da_verifier = BitcoinVerifier::new(RollupParams {
        reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
    });

    let input = guest.read_from_host();

    let lcp = LightClientProofCircuit::<ZkStorage, BitcoinSpec, Risc0Guest>::new();

    let output = lcp
        .run_circuit(
            da_verifier,
            input,
            storage,
            NETWORK,
            L2_GENESIS_ROOT,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &BATCH_PROVER_DA_PUBLIC_KEY,
            &SEQUENCER_DA_PUBLIC_KEY,
            &METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY,
        )
        .unwrap();

    guest.commit(&output);
}

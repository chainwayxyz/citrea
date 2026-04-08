#![no_main]
use alloy_primitives::Address;
use bitcoin_da::spec::{BitcoinSpec, RollupParams};
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_light_client_prover::circuit::initial_values::bitcoinda;
use citrea_light_client_prover::circuit::initial_values::non_empty_slice::NonEmptySlice;
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

const INITIAL_BATCH_PROOF_METHOD_IDS: NonEmptySlice<(u64, [u32; 8])> = {
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

const INITIAL_SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = {
    match NETWORK {
        Network::Mainnet => bitcoinda::INITIAL_MAINNET_SEQUENCER_DA_PUBLIC_KEY,
        Network::Testnet => bitcoinda::INITIAL_TESTNET_SEQUENCER_DA_PUBLIC_KEY,
        Network::Devnet => bitcoinda::INITIAL_DEVNET_SEQUENCER_DA_PUBLIC_KEY,
        Network::Nightly => bitcoinda::INITIAL_NIGHTLY_SEQUENCER_DA_PUBLIC_KEY,
        Network::TestNetworkWithForks => {
            bitcoinda::INITIAL_TEST_NETWORK_WITH_FORKS_SEQUENCER_DA_PUBLIC_KEY
        }
    }
};

const INITIAL_BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = {
    match NETWORK {
        Network::Mainnet => bitcoinda::INITIAL_MAINNET_BATCH_PROVER_DA_PUBLIC_KEY,
        Network::Testnet => bitcoinda::INITIAL_TESTNET_BATCH_PROVER_DA_PUBLIC_KEY,
        Network::Devnet => bitcoinda::INITIAL_DEVNET_BATCH_PROVER_DA_PUBLIC_KEY,
        Network::Nightly => bitcoinda::INITIAL_NIGHTLY_BATCH_PROVER_DA_PUBLIC_KEY,
        Network::TestNetworkWithForks => {
            bitcoinda::INITIAL_TEST_NETWORK_WITH_FORKS_BATCH_PROVER_DA_PUBLIC_KEY
        }
    }
};

pub const INITIAL_SECURITY_COUNCIL_DA_ADDRESSES: NonEmptySlice<Address> = {
    match NETWORK {
        Network::Mainnet => {
            bitcoinda::MAINNET_SECURITY_COUNCIL_INITIAL_DA_ADDRESSES
        }
        Network::Testnet => {
            bitcoinda::TESTNET_SECURITY_COUNCIL_INITIAL_DA_ADDRESSES
        }
        Network::Devnet => {
            bitcoinda::DEVNET_SECURITY_COUNCIL_INITIAL_DA_ADDRESSES
        }
        Network::Nightly => {
            bitcoinda::NIGHTLY_SECURITY_COUNCIL_INITIAL_DA_ADDRESSES
        }
        Network::TestNetworkWithForks => {
            bitcoinda::TEST_NETWORK_WITH_FORKS_SECURITY_COUNCIL_INITIAL_DA_ADDRESSES
        }
    }
};

pub const INITIAL_SECURITY_COUNCIL_THRESHOLD: usize =
    bitcoinda::INITIAL_SECURITY_COUNCIL_THRESHOLD;

pub const SECURITY_COUNCIL_DOMAIN_NAME: &str = {
    match NETWORK {
        Network::Mainnet => bitcoinda::MAINNET_EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME,
        Network::Testnet => bitcoinda::TESTNET_EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME,
        Network::Devnet => bitcoinda::DEVNET_EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME,
        Network::Nightly => bitcoinda::NIGHTLY_EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME,
        Network::TestNetworkWithForks => {
            bitcoinda::TEST_NETWORK_WITH_FORKS_EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME
        }
    }
};

const ALLOWED_PREVIOUS_LCP_METHOD_IDS: &[[u32; 8]] = {
    match NETWORK {
        Network::Mainnet => bitcoinda::MAINNET_ALLOWED_PREVIOUS_LCP_METHOD_IDS,
        Network::Testnet => bitcoinda::TESTNET_ALLOWED_PREVIOUS_LCP_METHOD_IDS,
        Network::Devnet => bitcoinda::DEVNET_ALLOWED_PREVIOUS_LCP_METHOD_IDS,
        Network::Nightly => bitcoinda::NIGHTLY_ALLOWED_PREVIOUS_LCP_METHOD_IDS,
        Network::TestNetworkWithForks => {
            bitcoinda::TEST_NETWORK_WITH_FORKS_ALLOWED_PREVIOUS_LCP_METHOD_IDS
        }
    }
};

pub fn main() {
    let storage = ZkStorage::new();

    let guest = Risc0Guest::new();

    let da_verifier = BitcoinVerifier::new(RollupParams {
        reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
        network: NETWORK,
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
            &INITIAL_BATCH_PROVER_DA_PUBLIC_KEY,
            &INITIAL_SEQUENCER_DA_PUBLIC_KEY,
            INITIAL_SECURITY_COUNCIL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            SECURITY_COUNCIL_DOMAIN_NAME.to_string(),
            ALLOWED_PREVIOUS_LCP_METHOD_IDS,
        )
        .unwrap();

    guest.commit(&output);
}

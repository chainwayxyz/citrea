use std::sync::OnceLock;

use sov_rollup_interface::fork::{fork_pos_from_block_number, verify_forks, Fork};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::Network;

#[cfg(not(feature = "testing"))]
static FORKS: OnceLock<&'static [Fork]> = OnceLock::new();

#[cfg(feature = "testing")]
pub static FORKS: OnceLock<&'static [Fork]> = OnceLock::new();

/// Set forks globally based on the network. Must be called once at the start of the application.
pub fn use_network_forks(network: Network) {
    let forks: &[Fork] = match network {
        Network::Mainnet => &MAINNET_FORKS,
        Network::Testnet => &TESTNET_FORKS,
        Network::Devnet => &DEVNET_FORKS,
        Network::Nightly => &NIGHTLY_FORKS,
        Network::TestNetworkWithForks => &ALL_FORKS,
    };

    #[cfg(not(feature = "testing"))]
    FORKS.set(forks).expect("Forks must be set exactly once");

    #[cfg(feature = "testing")]
    let _ = FORKS.set(forks);
}

/// Get forks. Forks need to be set before calling this method if not in testing environment.
/// In testing environment default forks are used.
pub fn get_forks() -> &'static [Fork] {
    match FORKS.get() {
        Some(forks) => forks,
        None => {
            #[cfg(not(feature = "testing"))]
            panic!("Forks must be set before accessing");

            #[cfg(feature = "testing")]
            {
                use_network_forks(Network::Nightly);
                FORKS.get().expect("Just set it")
            }
        }
    }
}

/// Get fork from the given block number. Forks must be set before calling this method if not in test environment.
/// In test environment default forks are used.
pub fn fork_from_block_number(block_number: u64) -> Fork {
    let forks = get_forks();
    let pos = fork_pos_from_block_number(forks, block_number);
    forks[pos]
}

pub const MAINNET_FORKS: [Fork; 1] = [Fork::new(SpecId::Fork2, 0)];

pub const TESTNET_FORKS: [Fork; 3] = [
    Fork::new(SpecId::Genesis, 0),
    Fork::new(SpecId::Kumquat, 5546000), // will be reached Jan 24 2025 ~7 PM
    Fork::new(SpecId::Fork2, u64::MAX),
];

pub const DEVNET_FORKS: [Fork; 3] = [
    Fork::new(SpecId::Genesis, 0),
    Fork::new(SpecId::Kumquat, 1921835),
    Fork::new(SpecId::Fork2, u64::MAX),
];

pub const NIGHTLY_FORKS: [Fork; 1] = [Fork::new(SpecId::Fork2, 0)];

pub const ALL_FORKS: [Fork; 3] = [
    Fork::new(SpecId::Genesis, 0),
    // TODO: since we didn't freeze kumquat elfs yet, tests depending on Kumquat fork
    // are actually going to be using the current elf.
    // So this doesn't mean anything, it will act like Fork2
    Fork::new(SpecId::Kumquat, 100),
    Fork::new(SpecId::Fork2, 200),
];

const _CHECK_FORKS: () = {
    if !verify_forks(&MAINNET_FORKS)
        || !verify_forks(&TESTNET_FORKS)
        || !verify_forks(&DEVNET_FORKS)
        || !verify_forks(&NIGHTLY_FORKS)
    {
        panic!("FORKS order is invalid")
    }
};

// If fork2 activation height is 0, return 1
// Because in tests when the first l2 block for the first sequencer commitment is needed
// Fork2 activation height should be sent
// If it is 0, it errors out because l2 block 0 is not valid
// So for only in tests, if fork2 activation height is 0, return 1
// In production, it will return whatever the activation height is
pub fn get_fork2_activation_height_non_zero() -> u64 {
    let forks = get_forks();
    let fork = forks
        .iter()
        .find(|f| f.spec_id == SpecId::Fork2)
        .expect("Fork2 should exist");
    if fork.activation_height == 0 {
        return 1;
    }
    fork.activation_height
}

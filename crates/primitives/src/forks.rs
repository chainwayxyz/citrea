use std::sync::OnceLock;

use sov_rollup_interface::fork::{fork_pos_from_block_number, Fork};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::Network;

static FORKS: OnceLock<&'static [Fork]> = OnceLock::new();

/// Set forks globally based on the network. Must be called once at the start of the application.
pub fn use_network_forks(network: Network) {
    let forks: &[Fork] = match network {
        Network::Mainnet => &MAINNET_FORKS,
        Network::Testnet => &TESTNET_FORKS,
        Network::Devnet => &DEVNET_FORKS,
        Network::Nightly => &NIGHTLY_FORKS,
    };
    FORKS.set(forks).expect("Forks must be set exactly once");
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
                FORKS
                    .set(&TESTING_FORKS)
                    .expect("Already checked that it is not set");
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

const MAINNET_FORKS: [Fork; 1] = [Fork::new(SpecId::Fork1, 0)];

const TESTNET_FORKS: [Fork; 2] = [
    Fork::new(SpecId::Genesis, 0),
    Fork::new(SpecId::Fork1, 999_999_999),
];

const DEVNET_FORKS: [Fork; 2] = [
    Fork::new(SpecId::Genesis, 0),
    Fork::new(SpecId::Fork1, 999_999_999),
];

const NIGHTLY_FORKS: [Fork; 1] = [Fork::new(SpecId::Fork1, 0)];

#[cfg(feature = "testing")]
const TESTING_FORKS: [Fork; 3] = [
    Fork {
        spec_id: SpecId::Genesis,
        activation_height: 0,
    },
    Fork {
        spec_id: SpecId::Fork1,
        activation_height: 1000,
    },
    Fork {
        spec_id: SpecId::Fork2,
        activation_height: 2000,
    },
];

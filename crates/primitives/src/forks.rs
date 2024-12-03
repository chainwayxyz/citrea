use sov_rollup_interface::fork::Fork;
use sov_rollup_interface::spec::SpecId;

/// This defines the list of forks which will be activated
/// at specific heights.
#[cfg(not(feature = "testing"))]
pub const FORKS: &[Fork] = &[
    Fork {
        spec_id: SpecId::Genesis,
        activation_height: 0,
    },
    Fork {
        spec_id: SpecId::Fork1,
        activation_height: 99999999999, // TODO: change this to the correct height once decided
    },
    // Examples of how we can define further forks
    // Fork { spec_id: SpecId::Fork2, activation_height: 1000 },
];

#[cfg(feature = "testing")]
pub const FORKS: &[Fork] = &[
    Fork {
        spec_id: SpecId::Genesis,
        activation_height: 0,
    },
    Fork {
        spec_id: SpecId::Fork1,
        activation_height: 10000,
    },
    Fork {
        spec_id: SpecId::Fork2,
        activation_height: 20000,
    },
];

const _CHECK_FORKS_ARE_SORTED: () = {
    const fn check_forks_are_sorted() {
        let mut height = FORKS[0].activation_height;
        let mut i = 1;
        while i < FORKS.len() {
            let fork = FORKS[i];
            let fork_height = fork.activation_height;
            assert!(fork_height > height, "FORKS are not sorted!");
            height = fork_height;
            i += 1;
        }
    }
    check_forks_are_sorted()
};

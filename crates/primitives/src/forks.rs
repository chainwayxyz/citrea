use sov_rollup_interface::fork::Fork;
use sov_rollup_interface::spec::SpecId;

/// This defines the list of forks which will be activated
/// at specific heights.
pub const FORKS: [Fork; 2] = [
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

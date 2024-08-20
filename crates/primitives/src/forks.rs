use sov_rollup_interface::fork::Fork;
use sov_rollup_interface::spec::SpecId;

/// This defines the list of forks which will be activated
/// at specific heights.
pub const FORKS: [Fork; 1] = [
    Fork {
        spec_id: SpecId::Genesis,
        activation_height: 0,
    },
    // Examples of how we can define further forks
    // Fork { spec_id: SpecId::Fork1, activation_height: 100 },
    // Fork { spec_id: SpecId::Fork2, activation_height: 1000 },
];

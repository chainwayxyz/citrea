use sov_rollup_interface::spec::SpecId;

/// This defines the list of forks which will be activated
/// at specific heights.
pub const FORKS: [(SpecId, u64); 1] = [
    (SpecId::Genesis, 0),
    // Examples of how we can define further forks
    // (SpecId::Fork1, 100),
    // (SpecId::Fork2, 200)
];

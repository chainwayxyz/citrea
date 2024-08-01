use lazy_static::lazy_static;
use sov_rollup_interface::spec::SpecId;

/// This defines the list of forks which will be activated
/// at specific heights.
lazy_static! {
    static ref FORKS: Vec<(SpecId, u64)> = vec![
        (SpecId::Genesis, 0),
        (SpecId::Fork1, 100),
        (SpecId::Fork2, 200)
    ];
}

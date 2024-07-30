use citrea_primitives::fork::SpecId;
use lazy_static::lazy_static;

lazy_static! {
    static ref FORKS: Vec<(SpecId, u64)> = vec![
        (SpecId::Genesis, 0),
        (SpecId::Fork1, 100),
        (SpecId::Fork2, 200)
    ];
}

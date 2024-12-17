use std::sync::OnceLock;

use sov_rollup_interface::fork::{Fork, Forks};

static FORKS: OnceLock<Forks> = OnceLock::new();

/// Set the forks. Must be called once.
pub fn set_forks(forks: Forks) {
    FORKS.set(forks).expect("Forks must be set exactly once");
}

/// Get forks. Forks need to be set before calling this method if not in testing environment.
/// In testing environment default forks are used.
pub fn get_forks() -> &'static Forks {
    match FORKS.get() {
        Some(forks) => forks,
        None => {
            #[cfg(not(feature = "testing"))]
            panic!("Forks must be set before accessing");

            #[cfg(feature = "testing")]
            {
                use sov_rollup_interface::spec::SpecId;

                set_forks(
                    Forks::from_slice(&[
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
                    ])
                    .expect("Forks are ordered"),
                );
                FORKS.get().expect("Just set it")
            }
        }
    }
}

/// Get fork from the given block number. Forks must be set before calling this method if not in test environment.
/// In test environment default forks are used.
pub fn fork_from_block_number(block_number: u64) -> Fork {
    get_forks().fork_from_block_number(block_number)
}

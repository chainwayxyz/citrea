#![allow(missing_docs)]

mod manager;
mod migration;
#[cfg(test)]
mod tests;

pub use manager::*;
pub use migration::*;

use crate::spec::SpecId;

/// Fork is a wrapper struct that contains spec id and it's activation height
#[derive(Debug, Clone, Copy)]
pub struct Fork {
    /// Spec id for this fork
    pub spec_id: SpecId,
    /// Height to activate this spec
    pub activation_height: u64,
}

impl PartialEq for Fork {
    fn eq(&self, other: &Self) -> bool {
        self.spec_id == other.spec_id && self.activation_height == other.activation_height
    }
}

impl Default for Fork {
    fn default() -> Self {
        Self {
            spec_id: SpecId::Genesis,
            activation_height: 0,
        }
    }
}

impl Fork {
    /// Creates new Fork instance
    pub const fn new(spec_id: SpecId, activation_height: u64) -> Self {
        Self {
            spec_id,
            activation_height,
        }
    }
}

/// Verifies the order of forks.
pub const fn verify_forks(forks: &[Fork]) -> bool {
    let mut i = 0;
    while i < forks.len() {
        let fork = forks[i];
        if i == 0 {
            // Ensure that the first fork starts from height 0
            if fork.activation_height != 0 {
                return false;
            }
        } else {
            // Validate spec_id increase by 1, and activation height is strictly greater than the previous fork
            if (fork.spec_id as u8).wrapping_sub(forks[i - 1].spec_id as u8) != 1
                || fork.activation_height <= forks[i - 1].activation_height
            {
                return false;
            }
        }

        i += 1;
    }

    true
}

/// Simple search for the fork to which a specific block number belongs.
/// This assumes that the list of forks is sorted by block number in ascending fashion.
pub fn fork_pos_from_block_number(forks: &[Fork], block_number: u64) -> usize {
    let pos = forks.binary_search_by(|fork| fork.activation_height.cmp(&block_number));

    match pos {
        Ok(idx) => idx,
        Err(idx) => idx.saturating_sub(1),
    }
}

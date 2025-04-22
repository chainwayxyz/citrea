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
            spec_id: SpecId::Tangerine,
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

/// ForkCodec is the serialization trait for types that require forking when changed.
/// Optimal usecase would be the type to be versioned enum, and do untagged enum ser/de.
///
/// Example:
///
/// ```
/// use sov_rollup_interface::fork::ForkCodec;
/// use sov_rollup_interface::spec::SpecId;
///
/// #[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
/// struct InputV1 {}
///
/// #[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
/// struct InputV2 {}
///
/// enum Input {
///     V1(InputV1),
///     V2(InputV2),
/// }
///
/// impl Input {
///     pub fn new_v1(v1: InputV1) -> Self {
///         Self::V1(v1)
///     }
///
///     pub fn new_v2(v2: InputV2) -> Self {
///         Self::V2(v2)
///     }
/// }
///
/// impl ForkCodec for Input {
///     fn encode(&self) -> anyhow::Result<Vec<u8>> {
///         match self {
///             Self::V1(v1) => Ok(borsh::to_vec(v1)?),
///             Self::V2(v2) => Ok(borsh::to_vec(v2)?),
///         }
///     }
///
///     fn decode(bytes: impl AsRef<[u8]>, spec: SpecId) -> anyhow::Result<Self> {
///         let slice = bytes.as_ref();
///         match spec {
///             SpecId::Genesis => Ok(Self::new_v1(borsh::from_slice(slice)?)),
///             SpecId::Kumquat => Ok(Self::new_v2(borsh::from_slice(slice)?)),
///         }
///     }
/// }
/// ```
pub trait ForkCodec: Sized {
    fn encode(&self) -> anyhow::Result<Vec<u8>>;
    fn decode(bytes: impl AsRef<[u8]>, spec: SpecId) -> anyhow::Result<Self>;
}

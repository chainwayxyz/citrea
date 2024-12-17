#![allow(missing_docs)]

mod manager;
mod migration;
#[cfg(test)]
mod tests;

pub use manager::*;
pub use migration::*;

use crate::spec::SpecId;

pub struct Forks {
    forks: [Fork; 50],
    count: usize,
}

impl Forks {
    /// Parse fork list from utf8 string. Format should be `{spec_id as u8}:{activation_height},{spec_id2 as u8}:{activation_height2}`.
    /// Since this is a constant fn, it returns a stack allocated array with 50 const size, and a second return value as the count
    /// of valid forks within this array
    ///
    /// Example:
    /// ```
    /// use sov_rollup_interface::fork::{Fork, Forks};
    /// const FORKS: Option<Forks> = Forks::from_utf8("0:1000,1:5000,2:100000");
    ///
    /// fn main() {
    ///     let forks: &[Fork] = match &FORKS {
    ///         Some(forks) => forks.inner(),
    ///         None => &[],
    ///     };
    /// }
    /// ```
    pub const fn from_utf8(forks_str: &str) -> Option<Self> {
        if forks_str.is_empty() {
            return None;
        }

        let mut forks = [Fork::new(SpecId::Genesis, 0); 50];
        let mut count = 0;

        let mut bytes = forks_str.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b',' {
                i += 1;
                continue;
            }

            let (fork_utf8, remaining_bytes) = bytes.split_at(i);

            let Some(fork) = Fork::from_colon_separated_utf8(fork_utf8) else {
                return None;
            };

            // Ignore comma
            let Some((_, remaining_bytes)) = remaining_bytes.split_first() else {
                return None;
            };
            bytes = remaining_bytes;

            forks[count] = fork;
            count += 1;

            i = 0;
        }

        // Add the last one
        let Some(fork) = Fork::from_colon_separated_utf8(bytes) else {
            return None;
        };
        forks[count] = fork;
        count += 1;

        if !verify_forks(&forks, count) {
            return None;
        }

        Some(Self { forks, count })
    }

    pub const fn inner(&self) -> &[Fork] {
        self.forks.split_at(self.count).0
    }
}

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

impl Fork {
    /// Creates new Fork instance
    pub const fn new(spec_id: SpecId, activation_height: u64) -> Self {
        Self {
            spec_id,
            activation_height,
        }
    }

    /// Parses `Fork` from colon separated bytes.
    /// Required format is `{spec_id as u8}:{activation_height}`.
    ///
    /// Example:
    /// ```
    /// use sov_rollup_interface::fork::Fork;
    /// const FORK: Option<Fork> = Fork::from_colon_separated_utf8(b"0:1000");
    /// ```
    pub const fn from_colon_separated_utf8(bytes: &[u8]) -> Option<Fork> {
        pub const fn is_digit(v: u8) -> bool {
            v >= b'0' && v <= b'9'
        }

        // Find the index of colon
        let mut i = 0;
        let colon_idx = loop {
            if i == bytes.len() {
                return None;
            }
            if bytes[i] == b':' {
                break i;
            }
            i += 1;
        };

        let (spec_id_bytes, height_bytes) = bytes.split_at(colon_idx);
        // Ignore colon
        let Some((_, height_bytes)) = height_bytes.split_first() else {
            return None;
        };

        if spec_id_bytes.is_empty() || height_bytes.is_empty() {
            return None;
        }

        // If multiple digits, first digit should not be 0
        if (spec_id_bytes.len() > 1 && spec_id_bytes[0] == b'0')
            || (height_bytes.len() > 1 && height_bytes[0] == b'0')
        {
            return None;
        }

        // Largest u8 is 3 digits, largest u64 is 20 digits
        if spec_id_bytes.len() > 3 || height_bytes.len() > 20 {
            return None;
        }

        // Parse spec_id
        let mut i = 0;
        let mut spec_id: u8 = 0;
        while i < spec_id_bytes.len() {
            if !is_digit(spec_id_bytes[i]) {
                return None;
            }

            let digit = spec_id_bytes[i] - b'0';
            let exp = spec_id_bytes.len() - i - 1;

            let Some(multiplier) = 10u8.checked_pow(exp as u32) else {
                return None;
            };
            let Some(to_add) = digit.checked_mul(multiplier) else {
                return None;
            };

            if let Some(new_spec_id) = spec_id.checked_add(to_add) {
                spec_id = new_spec_id;
            } else {
                return None;
            }

            i += 1;
        }

        let Some(spec_id) = SpecId::from_u8(spec_id) else {
            return None;
        };

        // Parse activation_height
        let mut i = 0;
        let mut height: u64 = 0;
        while i < height_bytes.len() {
            if !is_digit(height_bytes[i]) {
                return None;
            }

            let digit = (height_bytes[i] - b'0') as u64;
            let exp = height_bytes.len() - i - 1;

            let Some(multiplier) = 10u64.checked_pow(exp as u32) else {
                return None;
            };

            let Some(to_add) = digit.checked_mul(multiplier) else {
                return None;
            };

            if let Some(new_height) = height.checked_add(to_add) {
                height = new_height;
            } else {
                return None;
            }

            i += 1;
        }

        Some(Fork {
            spec_id,
            activation_height: height,
        })
    }
}

/// Verifies the order of forks. `size` is needed here due to being in const environment,
/// size of the fork might not be known beforehand.
pub const fn verify_forks(forks: &[Fork], size: usize) -> bool {
    let mut i = 0;
    while i < size {
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

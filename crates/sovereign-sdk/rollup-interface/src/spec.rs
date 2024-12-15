#![allow(clippy::module_inception)]
use core::hash::Hash;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
pub use spec::*;

#[cfg(not(feature = "testing"))]
mod spec {
    use super::*;
    /// Fork specification
    #[derive(
        Debug,
        Clone,
        Copy,
        Eq,
        PartialEq,
        PartialOrd,
        Default,
        BorshDeserialize,
        BorshSerialize,
        Serialize,
        Deserialize,
        Hash,
    )]
    #[borsh(use_discriminant = true)]
    pub enum SpecId {
        /// Genesis spec
        #[default]
        Genesis = 0,
        /// First fork activates:
        /// 1. the light client proof
        /// 2. EVM cancun upgrade (with no kzg precompile)
        /// 3. Don't use borsh when signing SoftConfirmation's
        Fork1 = 1,
    }

    impl SpecId {
        /// Const fn to convert u8 to corresponding SpecId. Valid values are
        /// 0 and 1. Panics otherwise.
        pub const fn from_u8(n: u8) -> Option<SpecId> {
            match n {
                0 => Some(SpecId::Genesis),
                1 => Some(SpecId::Fork1),
                _ => None,
            }
        }
    }
}

#[cfg(feature = "testing")]
mod spec {
    use super::*;
    /// Fork specification
    #[derive(
        Debug,
        Clone,
        Copy,
        Eq,
        PartialEq,
        PartialOrd,
        Default,
        BorshDeserialize,
        BorshSerialize,
        Serialize,
        Deserialize,
        Hash,
    )]
    #[borsh(use_discriminant = true)]
    pub enum SpecId {
        /// Genesis spec
        #[default]
        Genesis = 0,
        /// First fork
        Fork1 = 1,
        /// Second fork
        Fork2 = 2,
        /// Third fork
        Fork3 = 3,
    }

    impl SpecId {
        /// Const fn to convert u8 to corresponding SpecId. Valid values are
        /// 0, 1, 2 and 3.
        pub const fn from_u8(n: u8) -> Option<SpecId> {
            match n {
                0 => Some(SpecId::Genesis),
                1 => Some(SpecId::Fork1),
                2 => Some(SpecId::Fork2),
                3 => Some(SpecId::Fork3),
                _ => None,
            }
        }
    }
}

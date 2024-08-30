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
        Default,
        BorshDeserialize,
        BorshSerialize,
        Serialize,
        Deserialize,
        Hash,
    )]
    #[borsh(use_discriminant = true)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub enum SpecId {
        /// Genesis spec
        #[default]
        Genesis = 0,
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
        Default,
        BorshDeserialize,
        BorshSerialize,
        Serialize,
        Deserialize,
        Hash,
    )]
    #[borsh(use_discriminant = true)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub enum SpecId {
        /// Genesis spec
        #[default]
        Genesis = 0,
        /// First fork
        Fork1 = 1,
        /// Second fork
        Fork2 = 2,
    }
}

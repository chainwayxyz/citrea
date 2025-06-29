#![allow(clippy::module_inception)]
use core::hash::Hash;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Currently available Citrea fork specs.
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
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum SpecId {
    /// Genesis spec
    #[default]
    Genesis = 0,
    /// First fork activates:
    /// 1. the light client proof
    /// 2. EVM cancun upgrade (with no kzg precompile)
    /// 3. Don't use borsh when signing L2Block's
    /// 4. Better usage of DA layer by committing only the hash
    ///    of the smart contracts to state
    Kumquat = 1,
    /// Tangerine spec
    Tangerine = 2,
    /// Third fork activates:
    /// 1. Fixes for vulnerabilities that need forking on existing networks
    /// 2. Sov-tx signature serialization
    /// 3. Sov-tx serialization to generate signature
    Fork3 = 3,
    /// Fork4 spec
    #[cfg(feature = "testing")]
    Fork4 = 4,
}

impl SpecId {
    /// Get the latest active (official) SpecId.
    pub const fn latest() -> Self {
        Self::Fork3
    }
}

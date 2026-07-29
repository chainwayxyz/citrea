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
    /// 4. L2 merkle tree separators
    /// 5. LCP Method ID update is now done with 3/5 multisig of security council
    /// 6. Minimum base fee is now set to 0.001 gwei
    Tangelo = 3,
    /// Fourth fork fixes an edge case issue with selfdestruct opcode
    TangeloSelfdestructFix = 4,
    /// Fifth fork moves EVM signature verification to pre-computed pubkey
    /// witnesses in the batch-proof input.
    V3 = 5,
    #[cfg(feature = "testing")]
    /// Sixth fork for testing purposes only
    Fork6 = 6,
}

impl SpecId {
    /// Get the latest active (official) SpecId.
    pub const fn latest() -> Self {
        Self::V3
    }

    /// Returns whether batch proofs for this spec carry pre-computed ecrecover
    /// pubkey witnesses.
    pub fn uses_ecrecover_pubkey_witnesses(self) -> bool {
        self >= Self::V3
    }
}

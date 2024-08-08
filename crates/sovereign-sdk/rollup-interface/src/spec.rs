use anyhow::anyhow;
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
    )]
    #[borsh(use_discriminant = true)]
    pub enum SpecId {
        /// Genesis spec
        #[default]
        Genesis = 0,
    }

    impl TryFrom<u32> for SpecId {
        type Error = anyhow::Error;

        fn try_from(value: u32) -> Result<Self, Self::Error> {
            Ok(match value {
                0 => SpecId::Genesis,
                _ => return Err(anyhow!("No spec with this ID")),
            })
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
        PartialEq,
        Default,
        BorshDeserialize,
        BorshSerialize,
        Serialize,
        Deserialize,
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
    }

    impl TryFrom<u32> for SpecId {
        type Error = anyhow::Error;

        fn try_from(value: u32) -> Result<Self, Self::Error> {
            Ok(match value {
                0 => SpecId::Genesis,
                1 => SpecId::Fork1,
                2 => SpecId::Fork2,
                _ => return Err(anyhow!("No spec with this ID")),
            })
        }
    }
}

pub type L2BlockHash = [u8; 32];
use serde::{Deserialize, Serialize};

pub type SoftConfirmationHash = [u8; 32];
pub type BlockNumber = u64;
pub type L2Range = (BlockNumber, BlockNumber);

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Digest([u32; 8]);

impl Digest {
    pub fn new(value: [u32; 8]) -> Self {
        Self(value)
    }
}

impl From<[u32; 8]> for Digest {
    fn from(value: [u32; 8]) -> Self {
        Self::new(value)
    }
}

impl From<Digest> for [u32; 8] {
    fn from(value: Digest) -> Self {
        value.0
    }
}

#[cfg(feature = "r0")]
impl From<Digest> for risc0_zkvm::sha::Digest {
    fn from(value: Digest) -> Self {
        Self::new(value.0)
    }
}

#[cfg(feature = "r0")]
impl From<&Digest> for risc0_zkvm::sha::Digest {
    fn from(value: &Digest) -> Self {
        Self::new(value.0)
    }
}

#[cfg(feature = "r0")]
impl From<risc0_zkvm::sha::Digest> for Digest {
    fn from(value: risc0_zkvm::sha::Digest) -> Self {
        Self::new(value.into())
    }
}

use serde::{Deserialize, Serialize};
use sp1_sdk::{CpuProver, HashableKey, Prover, SP1VerifyingKey};

pub mod guest;
#[cfg(feature = "native")]
pub mod host;

#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyingKey(SP1VerifyingKey);

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = self.0.bytes32();
        write!(f, "VerifyingKey {{ SP1VerifyingKey {{ vk: {} }} }}", key)
    }
}

#[cfg(feature = "native")]
impl VerifyingKey {
    pub fn from_elf(elf: &[u8]) -> Self {
        let (_, vk) = CpuProver::new().setup(elf);
        Self(vk)
    }
}

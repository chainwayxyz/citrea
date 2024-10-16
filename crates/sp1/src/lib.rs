use serde::{Deserialize, Serialize};
use sp1_sdk::{HashableKey, SP1VerifyingKey};

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

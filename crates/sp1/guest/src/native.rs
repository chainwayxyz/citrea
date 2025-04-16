use anyhow::anyhow;
use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::zk::Zkvm;
use sp1_sdk::{HashableKey, SP1VerifyingKey};
use sp1_zkvm::lib::verify::verify_sp1_proof;

use super::SP1Guest;

impl Zkvm for SP1Guest {
    type CodeCommitment = VerifyingKey;

    type Error = anyhow::Error;

    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<(), Self::Error> {
        let vk_digest = code_commitment.clone().into();
        let serialized_proof = serialized_proof[0..32].try_into()?;
        verify_sp1_proof(&vk_digest, &serialized_proof);

        Ok(())
    }
    fn extract_raw_output(_serialized_proof: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unimplemented!()
    }

    fn deserialize_output<T: BorshDeserialize>(journal: &[u8]) -> Result<T, Self::Error> {
        T::try_from_slice(journal).map_err(|err| anyhow!("{err}"))
    }

    fn verify_and_deserialize_output<T: BorshDeserialize>(
        _serialized_proof: &[u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<T, Self::Error> {
        unimplemented!()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyingKey(pub SP1VerifyingKey);

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = self.0.bytes32();
        write!(f, "VerifyingKey {{ SP1VerifyingKey {{ vk: {} }} }}", key)
    }
}

impl From<[u32; 8]> for VerifyingKey {
    fn from(_value: [u32; 8]) -> Self {
        unimplemented!()
    }
}

impl From<VerifyingKey> for [u32; 8] {
    fn from(value: VerifyingKey) -> Self {
        value.0.hash_u32()
    }
}

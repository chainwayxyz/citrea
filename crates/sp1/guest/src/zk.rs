use anyhow::anyhow;
use borsh::BorshDeserialize;
use sov_rollup_interface::zk::Zkvm;
use sp1_zkvm::lib::verify::verify_sp1_proof;

use super::SP1Guest;

impl Zkvm for SP1Guest {
    type CodeCommitment = [u32; 8];

    type Error = anyhow::Error;

    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<(), Self::Error> {
        let serialized_proof = serialized_proof[0..32].try_into()?;
        verify_sp1_proof(code_commitment, &serialized_proof);

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

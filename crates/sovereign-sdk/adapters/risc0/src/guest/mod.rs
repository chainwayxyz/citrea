//! This module implements the `ZkvmGuest` trait for the RISC0 VM.
//! However the implementation is different
//!  for host(native) and guest(zkvm) part.
//! The host implementation is used for tests only and brings no real value.

use borsh::BorshDeserialize;
use risc0_zkvm::guest::env;
use risc0_zkvm::Receipt;
use sov_rollup_interface::zk::Zkvm;

use crate::Risc0MethodId;

// Here goes the host/guest implementation:

#[cfg(not(target_os = "zkvm"))]
mod native;
#[cfg(target_os = "zkvm")]
mod zkvm;

#[cfg(not(target_os = "zkvm"))]
pub use native::Risc0Guest;
#[cfg(target_os = "zkvm")]
pub use zkvm::Risc0Guest;

// Here goes the common implementation:

// This is a dummy impl because T: ZkvmGuest where T: Zkvm.
impl Zkvm for Risc0Guest {
    type CodeCommitment = Risc0MethodId;

    type Error = anyhow::Error;

    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<Vec<u8>, Self::Error> {
        let receipt: Receipt = bincode::deserialize(serialized_proof)?;
        env::verify(code_commitment.0, receipt.journal.bytes.as_slice())
            .expect("Guest side verification error should be Infallible");
        Ok(receipt.journal.bytes)
    }

    fn verify_and_extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let receipt: Receipt = bincode::deserialize(serialized_proof)?;
        env::verify(code_commitment.0, receipt.journal.bytes.as_slice())
            .expect("Guest side verification error should be Infallible");

        Ok(BorshDeserialize::deserialize(
            &mut receipt.journal.bytes.as_slice(),
        )?)
    }
}

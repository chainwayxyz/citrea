//! This module implements the `ZkvmGuest` trait for the RISC0 VM.
//! However the implementation is different
//!  for host(native) and guest(zkvm) part.
//! The host implementation is used for tests only and brings no real value.

use serde::de::DeserializeOwned;
use serde::Serialize;
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

    fn verify<'a>(
        _serialized_proof: &'a [u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<&'a [u8], Self::Error> {
        // Implement this method once risc0 supports recursion: issue #633
        todo!("Implement once risc0 supports recursion: https://github.com/Sovereign-Labs/sovereign-sdk/issues/633")
    }

    fn verify_and_extract_output<
        Da: sov_rollup_interface::da::DaSpec,
        Root: Serialize + DeserializeOwned,
    >(
        _serialized_proof: &[u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        todo!()
    }
}

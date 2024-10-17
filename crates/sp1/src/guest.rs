//! This module implements the `ZkvmGuest` trait for the SP1 VM.
use borsh::{BorshDeserialize, BorshSerialize};
use sov_rollup_interface::zk::{Zkvm, ZkvmGuest};
use sp1_zkvm::io;

/// A guest for the SP1 VM. Implements the `ZkvmGuest` trait
///  in terms of Risc0's env::read and env::commit functions.
#[derive(Default)]
pub struct SP1Guest {}

impl SP1Guest {
    /// Constructs a new Risc0 Guest
    pub fn new() -> Self {
        Self::default()
    }
}

impl Zkvm for SP1Guest {
    #[cfg(feature = "native")]
    type CodeCommitment = crate::host::VerifyingKey;
    #[cfg(not(feature = "native"))]
    type CodeCommitment = ();

    type Error = anyhow::Error;

    fn verify(
        _serialized_proof: &[u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<Vec<u8>, Self::Error> {
        unimplemented!()
    }

    fn verify_and_extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        _serialized_proof: &[u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        unimplemented!()
    }
}

impl ZkvmGuest for SP1Guest {
    fn read_from_host<T: BorshDeserialize>(&self) -> T {
        let buf = io::read_vec();
        T::try_from_slice(&buf).expect("Failed to deserialize input from host")
    }

    fn commit<T: BorshSerialize>(&self, item: &T) {
        let buf = borsh::to_vec(item).expect("Serialization to vec is infallible");
        io::commit_slice(&buf);
    }
}

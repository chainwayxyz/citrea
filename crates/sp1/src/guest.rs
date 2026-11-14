//! Guest I/O and proof verification for SP1.
use std::io::Cursor;
use std::sync::Mutex;

use borsh::{BorshDeserialize, BorshSerialize};
use sov_rollup_interface::zk::{Zkvm, ZkvmGuest};

use crate::{ProgramVKeyHash, SP1Proof};

#[derive(Default)]
pub struct SP1Guest {
    input: Mutex<Option<Cursor<Vec<u8>>>>,
}
impl SP1Guest {
    pub fn new() -> Self {
        Self::default()
    }

    fn verify_batch(
        proof: &SP1Proof,
        program: &ProgramVKeyHash,
        allow_mock: bool,
    ) -> anyhow::Result<()> {
        // DA batch proofs must stay recoverably verifiable Groth16 proofs. Native
        // recursion obligations must never be introduced by an untrusted DA blob.
        anyhow::ensure!(
            !matches!(proof, SP1Proof::Compressed { .. }),
            "Batch proof must be Groth16"
        );
        proof.verify(program, allow_mock)
    }
}
impl ZkvmGuest for SP1Guest {
    fn read_from_host<T: BorshDeserialize>(&self) -> T {
        // Citrea incrementally decodes Borsh values from one buffer. Upstream read_vec()
        // consumes a whole SP1 input buffer per call; the cursor is our adapter behavior.
        // https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/zkvm/lib/src/io.rs#L41-L52
        let mut input = self.input.lock().unwrap();
        let reader = input.get_or_insert_with(|| Cursor::new(sp1_zkvm::io::read_vec()));
        T::deserialize_reader(reader).expect("Invalid guest input")
    }
    fn commit<T: BorshSerialize>(&self, item: &T) {
        sp1_zkvm::io::commit_slice(&borsh::to_vec(item).expect("Output serialization failed"));
    }
}
impl Zkvm for SP1Guest {
    type CodeCommitment = ProgramVKeyHash;
    type Error = anyhow::Error;
    fn verify(proof: &[u8], program: &ProgramVKeyHash, allow_mock: bool) -> anyhow::Result<()> {
        let proof = SP1Proof::try_from_slice(proof)?;
        Self::verify_batch(&proof, program, allow_mock)
    }
    fn extract_raw_output(proof: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(SP1Proof::try_from_slice(proof)?.public_values().to_vec())
    }
    fn deserialize_output<T: BorshDeserialize>(journal: &[u8]) -> anyhow::Result<T> {
        Ok(T::try_from_slice(journal)?)
    }
    fn verify_and_deserialize_output<T: BorshDeserialize>(
        proof: &[u8],
        program: &ProgramVKeyHash,
        allow_mock: bool,
    ) -> anyhow::Result<T> {
        let proof = SP1Proof::try_from_slice(proof)?;
        Self::verify_batch(&proof, program, allow_mock)?;
        Ok(T::try_from_slice(proof.public_values())?)
    }
    fn verify_lcp_and_deserialize_output<T: BorshDeserialize>(
        proof: &[u8],
        program: &ProgramVKeyHash,
        allow_mock: bool,
    ) -> anyhow::Result<T> {
        let proof = SP1Proof::try_from_slice(proof)?;
        proof.verify_lcp(program, allow_mock)?;
        Ok(T::try_from_slice(proof.public_values())?)
    }
}

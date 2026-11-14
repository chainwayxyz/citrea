//! Compressed SP1 LCP transport and guest recursive verification.
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
#[cfg(not(feature = "native"))]
use sha2::{Digest, Sha256};

use super::sp1::KOALABEAR_P;

/// The same wire representation is used by Citrea and both Clementines.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CompressedProof {
    /// SP1's eight canonical KoalaBear key-hash words, not bytes32 reinterpreted as words.
    pub native_vkey: [u32; 8],
    /// Bincode-encoded SP1Proof::Compressed. Only the host reads this.
    pub proof: Vec<u8>,
    /// Bincode-encoded SP1VerifyingKey. Only the host reads this.
    pub vkey: Vec<u8>,
}

impl CompressedProof {
    /// Strip the large prover-only payload before serializing the guest input.
    pub fn guest_hint(&self) -> Self {
        Self {
            native_vkey: self.native_vkey,
            proof: vec![],
            vkey: vec![],
        }
    }

    /// Register a native recursion obligation binding `journal` to `expected_program`.
    ///
    /// The proof comes from the prover's proof stream. SP1's recursion circuit only accepts a
    /// complete compressed proof with exit code 0 whose committed-value digest is `sha256(journal)`.
    /// Citrea never verifies an LCP on the host; builds with `native` return an error.
    /// The digest matches [SP1PublicValues::hash()] and is passed to [verify_sp1_proof()].
    /// Complete-proof boundary checks come from the upstream [assert_complete] circuit.
    ///
    /// [SP1PublicValues::hash()]: https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/primitives/src/io.rs#L56-L59
    /// [verify_sp1_proof()]: https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/zkvm/lib/src/verify.rs#L3-L20
    /// [assert_complete]: https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/recursion/circuit/src/machine/complete.rs#L10-L148
    pub fn verify(&self, expected_program: &[u32; 8], journal: &[u8]) -> Result<(), String> {
        if self.native_vkey.iter().any(|&word| word >= KOALABEAR_P) {
            return Err("Noncanonical SP1 native key digest".into());
        }
        if self.native_vkey != *expected_program {
            return Err("Compressed SP1 program mismatch".into());
        }
        if !self.proof.is_empty() || !self.vkey.is_empty() {
            return Err("Compressed proof payload must use the native proof stream".into());
        }
        #[cfg(not(feature = "native"))]
        {
            let digest: [u8; 32] = Sha256::digest(journal).into();
            sp1_zkvm::lib::verify::verify_sp1_proof(&self.native_vkey, &digest);
            Ok(())
        }
        #[cfg(feature = "native")]
        {
            let _ = journal;
            Err("Compressed SP1 proofs can only be verified in a guest".into())
        }
    }
}

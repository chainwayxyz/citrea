//! SP1 proof transport shared by the node and its guests.
use borsh::{BorshDeserialize, BorshSerialize};

/// KoalaBear field modulus; native SP1 key-digest words must be smaller than this.
/// Matches the pinned [KoalaBear modulus] used by SP1 6.10.0.
///
/// [KoalaBear modulus]: https://github.com/Plonky3/Plonky3/blob/5309d4d0975d260f414ea98cf47456299971927a/koala-bear/src/koala_bear.rs#L19
pub const KOALABEAR_P: u32 = 0x7f00_0001;

/// SP1's native verification-key digest, returned by [HashableKey::hash_u32()].
/// The same eight words identify a program in rollup interfaces and native recursion.
///
/// [HashableKey::hash_u32()]: https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/hypercube/src/verifier/hashable_key.rs#L46-L56
pub type ProgramVKeyHash = [u32; 8];

/// Pack a native key digest into the BN254 bytes32 used by SP1's Groth16 verifier.
///
/// Matches SP1 6.10.0's [HashableKey::bytes32_raw()]: the big-endian bytes of
/// [koalabears_to_bn254] applied to the native digest. This implements the same base-2^31
/// packing without pulling `sp1-hypercube` into the guests. `tests/program_ids.rs` checks
/// a CLI output fixture; `crates/sp1/tests/native_keys.rs` checks all pinned ELFs against the SDK.
///
/// [HashableKey::bytes32_raw()]: https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/hypercube/src/verifier/hashable_key.rs#L65-L75
/// [koalabears_to_bn254]: https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/hypercube/src/verifier/hashable_key.rs#L20-L32
pub fn groth16_program_id(words: &ProgramVKeyHash) -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    for &word in words {
        if word >= KOALABEAR_P {
            return Err("Noncanonical SP1 native key digest".into());
        }
        let mut carry = u64::from(word);
        for byte in bytes.iter_mut().rev() {
            let value = (u64::from(*byte) << 31) + carry;
            *byte = value as u8;
            carry = value >> 8;
        }
        debug_assert_eq!(carry, 0);
    }
    Ok(bytes)
}

/// Citrea's versioned Borsh envelope, with explicit mock and compressed variants.
/// The tags belong to Citrea's transport; they do not mirror the SDK's proof serialization.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum SP1Proof {
    /// A Groth16 proof in the SDK's [SP1ProofWithPublicValues::bytes()] format, including
    /// the four-byte verification-key selector.
    ///
    /// [SP1ProofWithPublicValues::bytes()]: https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/sdk/src/proof.rs#L135-L195
    Groth16 {
        /// SP1 proof bytes, including the key selector.
        proof: Vec<u8>,
        /// Borsh encoded public output.
        public_values: Vec<u8>,
    } = 0,
    /// Execution-only output, accepted exclusively when the caller allows development mode.
    Mock {
        /// Program commitment for execution-only output.
        program: ProgramVKeyHash,
        /// Borsh encoded public output.
        public_values: Vec<u8>,
    } = 1,
    /// Compressed LCP. Tag 3 matches Clementine's receipt transport.
    Compressed {
        /// Native recursion witness and program key.
        proof: super::compressed::CompressedProof,
        /// Borsh encoded public output.
        public_values: Vec<u8>,
    } = 3,
}
impl SP1Proof {
    /// Public output bytes, without verification.
    pub fn public_values(&self) -> &[u8] {
        match self {
            Self::Groth16 { public_values, .. }
            | Self::Mock { public_values, .. }
            | Self::Compressed { public_values, .. } => public_values,
        }
    }
    /// Verify the proof against the caller's expected program commitment.
    pub fn verify(&self, program: &ProgramVKeyHash, allow_mock: bool) -> anyhow::Result<()> {
        match self {
            Self::Compressed {
                proof,
                public_values,
            } => proof
                .verify(program, public_values)
                .map_err(anyhow::Error::msg),
            Self::Groth16 {
                proof,
                public_values,
            } => sp1_verifier::Groth16Verifier::verify(
                proof,
                public_values,
                &format!(
                    "0x{}",
                    hex::encode(groth16_program_id(program).map_err(anyhow::Error::msg)?)
                ),
                &sp1_verifier::GROTH16_VK_BYTES,
            )
            .map_err(|error| anyhow::anyhow!("SP1 proof verification failed: {error:?}")),
            Self::Mock {
                program: claimed, ..
            } if allow_mock
                && claimed == program
                && program.iter().all(|&word| word < KOALABEAR_P) =>
            {
                Ok(())
            }
            Self::Mock { .. } => {
                anyhow::bail!("Mock proof rejected or program commitment mismatch")
            }
        }
    }

    /// LCP recursion does not accept Groth16 proofs.
    pub fn verify_lcp(&self, program: &ProgramVKeyHash, allow_mock: bool) -> anyhow::Result<()> {
        anyhow::ensure!(
            matches!(self, Self::Compressed { .. } | Self::Mock { .. }),
            "LCP requires a compressed SP1 proof"
        );
        self.verify(program, allow_mock)
    }

    /// Ordinary guest input contains the claim, while the host carries the proof.
    pub fn guest_hint(&self) -> Self {
        match self {
            Self::Compressed {
                proof,
                public_values,
            } => Self::Compressed {
                proof: proof.guest_hint(),
                public_values: public_values.clone(),
            },
            _ => self.clone(),
        }
    }
}

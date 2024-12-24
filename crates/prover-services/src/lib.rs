mod parallel;
pub use parallel::*;

#[derive(Debug, Clone, Copy)]
pub enum ProofGenMode {
    /// Skips proving.
    Skip,
    /// The executor runs the rollup verification logic in the zkVM, but does not actually
    /// produce a zk proof
    Execute,
    /// The prover runs the rollup verification logic in the zkVM and produces a zk proof
    ProveWithSampling,
    /// The prover runs the rollup verification logic in the zkVM and produces a zk/fake proof
    ProveWithSamplingWithFakeProofs(
        /// Average number of _REAL_ commitments to prove
        /// If proof_sampling_number is 0, then we always produce real proofs
        /// Otherwise we prove with a probability of 1/proof_sampling_number,
        ///  but produce fake proofs with a probability of (1-1/proof_sampling_number).
        ///
        /// proof_sampling_number:
        usize,
    ),
}

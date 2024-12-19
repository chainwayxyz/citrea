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
    Prove,
}

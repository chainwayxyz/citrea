mod parallel;
use async_trait::async_trait;
pub use parallel::ParallelProverService;
use serde::Serialize;
use sov_rollup_interface::services::da::DaService;
use thiserror::Error;

use crate::StateTransitionData;

pub(crate) type Hash = [u8; 32];

/// The possible configurations of the prover.
pub enum RollupProverConfig {
    /// Skip proving.
    Skip,
    /// Run the rollup verification logic inside the current process
    Simulate,
    /// Run the rollup verifier in a zkVM executor
    Execute,
    /// Run the rollup verifier and create a SNARK of execution
    Prove,
}

/// Indicates the status of the DA proof submission.
pub enum ProofSubmissionStatus {
    /// Proof was submitted to the DA.
    Success,
    /// Proof generation is still in progress.
    ProvingInProgress,
    /// Proof submission failed
    Err(anyhow::Error),
}

/// An error that occurred during ZKP proving.
#[derive(Error, Debug)]
pub enum ProverServiceError {
    /// Prover is too busy.
    #[error("Prover is too busy")]
    ProverBusy,
    /// Some internal prover error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// This service is responsible for ZKP proof generation.
/// The proof is generated in two stages:
/// 1. Witness is submitted via `submit_witness` to a prover service.
/// 2. The proof generation is triggered by the `prove` method.
#[async_trait]
pub trait ProverService {
    /// Root hash of state merkle tree.
    type StateRoot: Serialize + Clone + AsRef<[u8]>;
    /// Data that is produced during batch execution.
    type Witness: Serialize;
    /// Data Availability service.
    type DaService: DaService;

    /// Submit witness for proving.
    async fn submit_witness(
        &self,
        state_transition_data: StateTransitionData<
            Self::StateRoot,
            Self::Witness,
            <Self::DaService as DaService>::Spec,
        >,
    );

    /// Creates ZKP prove for a block corresponding to `block_header_hash`.
    async fn prove(&self, block_header_hash: Hash) -> Result<(), ProverServiceError>;

    /// Sends the ZK proof to the DA create by the `prove`.
    async fn send_proof_to_da(&self, block_header_hash: Hash) -> ProofSubmissionStatus;
}

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::Proof;
use thiserror::Error;

/// The possible configurations of the prover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProverGuestRunConfig {
    /// Skip proving.
    Skip,
    /// Run the rollup verification logic inside the current process.
    Simulate,
    /// Run the rollup verifier in a zkVM executor.
    Execute,
    /// Run the rollup verifier and create a SNARK of execution.
    Prove,
}

impl<'de> Deserialize<'de> for ProverGuestRunConfig {
    fn deserialize<D>(deserializer: D) -> Result<ProverGuestRunConfig, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <std::string::String as Deserialize>::deserialize(deserializer)?;
        match s.as_str() {
            "skip" => Ok(ProverGuestRunConfig::Skip),
            "simulate" => Ok(ProverGuestRunConfig::Simulate),
            "execute" => Ok(ProverGuestRunConfig::Execute),
            "prove" => Ok(ProverGuestRunConfig::Prove),
            _ => Err(serde::de::Error::custom("invalid prover guest run config")),
        }
    }
}

/// Represents the status of a witness submission.
#[derive(Debug, Eq, PartialEq)]
pub enum WitnessSubmissionStatus {
    /// The witness has been submitted to the prover.
    SubmittedForProving,
    /// The witness is already present in the prover.
    WitnessExist,
}

/// Represents the status of a DA proof submission.
#[derive(Debug, Eq, PartialEq)]
pub enum ProofSubmissionStatus {
    /// Indicates successful submission of the proof to the DA.
    Success(Proof),
    /// Indicates that proof generation is currently in progress.
    ProofGenerationInProgress,
}

/// Represents the current status of proof generation.
#[derive(Debug, Eq, PartialEq)]
pub enum ProofProcessingStatus {
    /// Indicates that proof generation is currently in progress.
    ProvingInProgress,
    /// Indicates that the prover is busy and will not initiate a new proving process.
    Busy,
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

pub(crate) type Input = Vec<u8>;
pub(crate) type Assumptions = Vec<Vec<u8>>;
pub(crate) type ProofData = (Input, Assumptions);

/// This service is responsible for ZK proof generation.
/// The proof generation process involves the following stages:
///     1. Submitting an input and assumptions using `add_proof_data` method.
///     2. Generate proof and submit it to DA Service with the `prove_and_submit` method.
#[async_trait]
pub trait ProverService {
    /// Data Availability service.
    type DaService: DaService;

    /// Add proof data, namely input and assumptions to ProverService.
    async fn add_proof_data(&self, proof_data: ProofData);

    /// Prove added input and assumptions.
    async fn prove(&self, elf: Vec<u8>) -> anyhow::Result<Vec<Proof>>;

    /// Submit proofs to DA.
    async fn submit_proofs(
        &self,
        proofs: Vec<Proof>,
    ) -> anyhow::Result<Vec<(<Self::DaService as DaService>::TransactionId, Proof)>>;

    /// Recover the ongoing sessions and submit them to DA.
    async fn recover_and_submit_proving_sessions(
        &self,
    ) -> anyhow::Result<Vec<(<Self::DaService as DaService>::TransactionId, Proof)>>;
}

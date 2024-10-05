use std::sync::Arc;

use async_trait::async_trait;
use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use sov_modules_api::Zkvm;
use sov_rollup_interface::da::DaSpec;
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

/// This service is responsible for ZK proof generation.
/// The proof generation process involves the following stages:
///     1. Submitting a witness using the `submit_witness` method to a prover service.
///     2. Initiating proof generation with the `prove` method.
/// Once the proof is ready, it can be sent to the DA with `send_proof_to_da` method.
/// Currently, the cancellation of proving jobs for submitted witnesses is not supported,
/// but this functionality will be added in the future (#1185).
#[async_trait]
pub trait ProverService<Vm: Zkvm> {
    /// Data Availability service.
    type DaService: DaService;

    /// Submit a witness for proving.
    async fn submit_witness(
        &self,
        input: Vec<u8>,
        da_slot_hash: <<Self::DaService as DaService>::Spec as DaSpec>::SlotHash,
    ) -> WitnessSubmissionStatus;

    /// Creates ZKP prove for a block corresponding to `block_header_hash`.
    async fn prove(
        &self,
        block_header_hash: <<Self::DaService as DaService>::Spec as DaSpec>::SlotHash,
    ) -> Result<ProofProcessingStatus, ProverServiceError>;

    /// Wait for proving to be complete and extract the output
    /// from the prover service.
    async fn wait_for_proving_and_extract_output<T: BorshDeserialize>(
        &self,
        block_header_hash: <<Self::DaService as DaService>::Spec as DaSpec>::SlotHash,
    ) -> Result<T, anyhow::Error>;

    /// Sends the ZK proof to the DA.
    async fn wait_for_proving_and_send_to_da(
        &self,
        block_header_hash: <<Self::DaService as DaService>::Spec as DaSpec>::SlotHash,
        da_service: &Arc<Self::DaService>,
    ) -> Result<(<Self::DaService as DaService>::TransactionId, Proof), anyhow::Error>;

    /// Recovers pending proving sessions and sends proofs to the DA.
    async fn recover_proving_sessions_and_send_to_da(
        &self,
        da_service: &Arc<Self::DaService>,
    ) -> Result<Vec<(<Self::DaService as DaService>::TransactionId, Proof)>, anyhow::Error>;
}

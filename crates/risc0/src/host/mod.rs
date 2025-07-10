//! This module implements the [`ZkvmHost`] trait for the RISC0 VM.

mod bonsai;
mod boundless;
mod config;
mod local;
mod pricing_service;

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, mem};

use bonsai::BonsaiProver;
use borsh::BorshDeserialize;
use boundless::BoundlessProver;
use local::LocalProver;
use risc0_zkvm::sha::Digest;
use risc0_zkvm::AssumptionReceipt;
use sov_db::ledger_db::LedgerDB;
use sov_rollup_interface::zk::{Proof, ProofWithJob, ReceiptType, Zkvm, ZkvmHost};
use sov_rollup_interface::Network;
use tokio::sync::oneshot;
use tracing::{debug, info};
use uuid::Uuid;

use crate::guest::Risc0Guest;
use crate::receipt_from_proof;

/// [`Risc0Host`] stores a binary to execute in the Risc0 VM and prove in the Risc0 Bonsai API.
#[derive(Clone)]
pub struct Risc0Host {
    env: Vec<u8>,
    assumptions: Vec<AssumptionReceipt>,
    prover: Prover,
}

impl Risc0Host {
    /// Create a new Risc0Host to prove the given binary.
    pub async fn new(ledger_db: LedgerDB, network: Network) -> Self {
        let prover = match std::env::var("RISC0_PROVER") {
            Ok(prover) => match prover.as_str() {
                "boundless" => Prover::Boundless(BoundlessProver::new(ledger_db).await),
                "bonsai" => Prover::Bonsai(BonsaiProver::new(ledger_db)),
                "ipc" => Prover::Local(LocalProver::new(network)),
                _ => panic!("Invalid prover specified: {}", prover),
            },
            Err(_) => {
                debug!("No prover specified.");
                Prover::Local(LocalProver::new(network))
            }
        };

        Self {
            env: Default::default(),
            assumptions: vec![],
            prover,
        }
    }
}

#[async_trait::async_trait]
impl ZkvmHost for Risc0Host {
    type Guest = Risc0Guest;

    fn add_hint(&mut self, item: Vec<u8>) {
        info!("Added hint to guest with size {}", item.len());
        // write buf
        self.env.extend_from_slice(&item);
    }

    /// Guest simulation (execute mode) is run inside the Risc0 VM locally
    fn simulate_with_hints(&mut self) -> Self::Guest {
        unimplemented!("we don't use it yet")
    }

    fn add_assumption(&mut self, receipt_buf: Vec<u8>) {
        let receipt = receipt_from_proof(&receipt_buf).expect("Receipt should be valid");
        self.assumptions.push(receipt.into());
    }

    async fn run(
        &mut self,
        job_id: Uuid,
        elf: Vec<u8>,
        receipt_type: ReceiptType,
        with_prove: bool,
    ) -> anyhow::Result<oneshot::Receiver<ProofWithJob>> {
        let input = mem::take(&mut self.env);
        let assumptions = mem::take(&mut self.assumptions);

        if let Ok(backup_dir) = env::var("TX_BACKUP_DIR") {
            let input_path = Path::new(&backup_dir).join(format!(
                "{}-proof-input.bin",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::write(input_path, &input).expect("Proof input write cannot fail");
        }

        match &self.prover {
            Prover::Local(local) => {
                local.prove(job_id, elf, input, assumptions, receipt_type, with_prove)
            }
            Prover::Bonsai(bonsai) => {
                assert!(
                    with_prove,
                    "Bonsai prover must always be run with prove set to true"
                );
                bonsai.prove(job_id, elf, input, assumptions, receipt_type)
            }
            Prover::Boundless(boundless) => {
                assert!(
                    with_prove,
                    "Boundless prover must always be run with prove set to true"
                );
                boundless
                    .prove(job_id, elf, input, assumptions, receipt_type)
                    .await
            }
        }
    }

    fn extract_output<T: BorshDeserialize>(proof: &Proof) -> Result<T, Self::Error> {
        let receipt = receipt_from_proof(proof)?;
        let journal = receipt.journal;

        Ok(T::try_from_slice(&journal.bytes)?)
    }

    fn start_session_recovery(
        &self,
    ) -> Result<Vec<oneshot::Receiver<ProofWithJob>>, anyhow::Error> {
        self.prover.start_prover_session_recovery()
    }
}

impl Zkvm for Risc0Host {
    type CodeCommitment = Digest;

    type Error = anyhow::Error;

    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<(), Self::Error> {
        let receipt = receipt_from_proof(serialized_proof)?;

        Ok(receipt.verify(*code_commitment)?)
    }

    fn extract_raw_output(serialized_proof: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let receipt = receipt_from_proof(serialized_proof)?;
        Ok(receipt.journal.bytes)
    }

    fn deserialize_output<T: BorshDeserialize>(journal: &[u8]) -> Result<T, Self::Error> {
        Ok(T::try_from_slice(journal)?)
    }

    fn verify_and_deserialize_output<T: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<T, Self::Error> {
        let receipt = receipt_from_proof(serialized_proof)?;

        #[allow(clippy::clone_on_copy)]
        receipt.verify(code_commitment.clone())?;

        Ok(T::deserialize(&mut receipt.journal.as_ref())?)
    }
}

/// Supported `Prover` types
#[derive(Clone)]
pub enum Prover {
    /// Local prover
    Local(LocalProver),
    /// Bonsai prover
    Bonsai(BonsaiProver),
    /// Boundless prover network
    Boundless(BoundlessProver),
}

impl Prover {
    /// Start recovery for prover if it supports it
    pub fn start_prover_session_recovery(
        &self,
    ) -> anyhow::Result<Vec<oneshot::Receiver<ProofWithJob>>> {
        match self {
            Prover::Local(_) => {
                info!("Skipping proving recovery...");
                Ok(vec![])
            }
            Prover::Boundless(prover) => prover.start_recovery(),
            Prover::Bonsai(prover) => prover.start_recovery(),
        }
    }
}

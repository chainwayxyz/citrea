use std::env;

use borsh::BorshDeserialize;
use citrea_sp1_guest::SP1Guest;
use local::LocalProver;
use network::SuccinctProver;
use sov_db::ledger_db::LedgerDB;
use sov_rollup_interface::zk::{Digest, Proof, ProofWithJob, ReceiptType, Zkvm, ZkvmHost};
use sov_rollup_interface::Network;
use sp1_sdk::{include_elf, SP1ProofWithPublicValues};
use tokio::sync::oneshot;
use tracing::{debug, info};

pub use citrea_sp1_guest::VerifyingKey;

mod local;

mod network;

pub const ELF: &[u8] = include_elf!("sp1-batch-prover-bitcoin");

#[derive(Clone)]
pub struct SP1Host {
    prover: Prover,
    inputs: Vec<Vec<u8>>,
}

impl SP1Host {
    /// Creates an [`SP1Host`] instance.
    pub fn new(elf: Vec<u8>, ledger_db: LedgerDB, network: Network) -> Self {
        let prover = match std::env::var("SP1_PROVER") {
            Ok(prover) => match prover.as_str() {
                "network" => Prover::Network(SuccinctProver::new(elf, ledger_db)),
                _ => Prover::Local(LocalProver::new(elf, network)),
            },
            Err(_) => {
                debug!("No prover specified.");
                Prover::Local(LocalProver::new(elf, network))
            }
        };

        Self {
            prover,
            inputs: vec![],
        }
    }
}

impl ZkvmHost for SP1Host {
    type Guest = SP1Guest;

    fn add_hint(&mut self, buf: Vec<u8>) {
        info!("Adding hint to guest with size {}", buf.len());

        self.inputs.push(buf);
    }

    fn simulate_with_hints(&mut self) -> Self::Guest {
        unimplemented!("Simulate is not implemented for SP1")
    }

    fn run(
        &mut self,
        job_id: uuid::Uuid,
        _elf: Vec<u8>,
        receipt_type: ReceiptType,
        _with_prove: bool,
    ) -> anyhow::Result<oneshot::Receiver<ProofWithJob>> {
        match &self.prover {
            Prover::Local(local) => local.prove(job_id, self.inputs.clone(), receipt_type),
            Prover::Network(network) => network.prove(job_id, self.inputs.clone(), receipt_type),
        }
    }

    fn extract_output<T: BorshDeserialize>(proof: &Proof) -> Result<T, Self::Error> {
        let proof = bincode::deserialize::<SP1ProofWithPublicValues>(proof)?;

        Ok(T::try_from_slice(proof.public_values.as_slice())?)
    }

    fn start_session_recovery(
        &self,
    ) -> Result<Vec<oneshot::Receiver<ProofWithJob>>, anyhow::Error> {
        Ok(vec![])
    }

    fn add_assumption(&mut self, _receipt_buf: Vec<u8>) {
        unimplemented!("add_assumption")
    }
}

impl Zkvm for SP1Host {
    type CodeCommitment = Digest;
    type Error = anyhow::Error;

    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<(), Self::Error> {
        // TODO: Verify the proof
        Ok(())
    }

    fn extract_raw_output(_serialized_proof: &[u8]) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }

    fn deserialize_output<T: BorshDeserialize>(_journal: &[u8]) -> Result<T, Self::Error> {
        todo!()
    }

    fn verify_and_deserialize_output<T: BorshDeserialize>(
        serialized_proof: &[u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<T, Self::Error> {
        let proof: SP1ProofWithPublicValues = bincode::deserialize(serialized_proof)?;

        // TODO: Verify the proof

        Ok(T::try_from_slice(proof.public_values.as_slice())?)
    }
}

/// Supported `Prover` types
#[derive(Clone)]
pub enum Prover {
    Network(SuccinctProver),
    Local(LocalProver),
}

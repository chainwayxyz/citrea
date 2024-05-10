//! This module implements the [`ZkvmHost`] trait for the RISC0 VM.

use std::time::Duration;

use ::bonsai_sdk::alpha::Client;
use bonsai_sdk::alpha as bonsai_sdk;
use risc0_zkvm::{
    compute_image_id, serde::to_vec, ExecutorEnvBuilder, ExecutorImpl, InnerReceipt, Journal,
    Receipt, Session,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};

use crate::guest::Risc0Guest;
use crate::Risc0MethodId;

/// A [`Risc0BonsaiHost`] stores a binary to execute in the Risc0 VM, and accumulates hints to be
/// provided to its execution.
#[derive(Clone)]
pub struct Risc0BonsaiHost<'a> {
    env: Vec<u32>,
    elf: &'a [u8],
    client: Client,
}

#[cfg(feature = "bench")]
fn add_benchmarking_callbacks(mut env: ExecutorEnvBuilder<'_>) -> ExecutorEnvBuilder<'_> {
    use sov_zk_cycle_utils::{cycle_count_callback, get_syscall_name, get_syscall_name_cycles};

    use crate::metrics::metrics_callback;

    let metrics_syscall_name = get_syscall_name();
    env.io_callback(metrics_syscall_name, metrics_callback);

    let cycles_syscall_name = get_syscall_name_cycles();
    env.io_callback(cycles_syscall_name, cycle_count_callback);

    env
}

impl<'a> Risc0BonsaiHost<'a> {
    /// Create a new Risc0Host to prove the given binary.
    pub fn new(elf: &'a [u8]) -> Self {
        // handle error
        let client = bonsai_sdk::Client::from_env(risc0_zkvm::VERSION).unwrap();

        Self {
            env: Default::default(),
            elf,
            client,
        }
    }
}

impl<'a> ZkvmHost for Risc0BonsaiHost<'a> {
    type Guest = Risc0Guest;

    fn add_hint<T: serde::Serialize>(&mut self, item: T) {
        // We use the in-memory size of `item` as an indication of how much
        // space to reserve. This is in no way guaranteed to be exact, but
        // usually the in-memory size and serialized data size are quite close.
        //
        // Note: this is just an optimization to avoid frequent reallocations,
        // it's not actually required.

        // Compute the image_id, then upload the ELF with the image_id as its key.
        // handle error
        let image_id = hex::encode(compute_image_id(&self.elf).unwrap());
        // handle error
        self.client
            .upload_img(&image_id, self.elf.to_vec())
            .unwrap();

        // Prepare input data and upload it.
        let input_data = to_vec(&item).unwrap();
        let input_data = bytemuck::cast_slice(&input_data).to_vec();
        // handle error
        let input_id = self.client.upload_input(input_data).unwrap();

        // Add a list of assumptions
        let assumptions: Vec<String> = vec![];

        // Start a session running the prover
        let session = self
            .client
            //hanfle error
            .create_session(image_id, input_id, assumptions)
            .unwrap();
        loop {
            // handle error
            let res = session.status(&self.client).unwrap();
            if res.status == "RUNNING" {
                eprintln!(
                    "Current status: {} - state: {} - continue polling...",
                    res.status,
                    res.state.unwrap_or_default()
                );
                std::thread::sleep(Duration::from_secs(15));
                continue;
            }
            if res.status == "SUCCEEDED" {
                // Download the receipt, containing the output
                let receipt_url = res
                    .receipt_url
                    .expect("API error, missing receipt on completed session");
                // handle error
                let receipt_buf = self.client.download(&receipt_url).unwrap();
                // handle error
                let receipt: Receipt = bincode::deserialize(&receipt_buf).unwrap();
                receipt
                    .verify(&risc0::MOCK_DA_ELF)
                    .expect("Receipt verification failed");
            } else {
                panic!(
                    "Workflow exited: {} - | err: {}",
                    res.status,
                    res.error_msg.unwrap_or_default()
                );
            }

            break;
        }
    }

    fn simulate_with_hints(&mut self) -> Self::Guest {
        unreachable!("Bonsai does not support simulation");
        Risc0Guest::with_hints(std::mem::take(&mut self.env))
    }

    fn run(&mut self, with_proof: bool) -> Result<Proof, anyhow::Error> {
        if with_proof {
            unimplemented!()
            // let receipt = self.run()?;
            // let data = bincode::serialize(&receipt)?;
            // Ok(Proof::Full(data))
        } else {
            let session = self.run_without_proving()?;
            let data = bincode::serialize(&session.journal)?;
            Ok(Proof::PublicInput(data))
        }
    }

    fn extract_output<Da: sov_rollup_interface::da::DaSpec, Root: Serialize + DeserializeOwned>(
        proof: &Proof,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        match proof {
            Proof::PublicInput(journal) => {
                let journal: Journal = bincode::deserialize(journal)?;
                Ok(journal.decode()?)
            }
            Proof::Full(data) => {
                let receipt: Receipt = bincode::deserialize(data)?;
                Ok(receipt.journal.decode()?)
            }
        }
    }
}

impl<'host> Zkvm for Risc0BonsaiHost<'host> {
    type CodeCommitment = Risc0MethodId;

    type Error = anyhow::Error;

    fn verify<'a>(
        serialized_proof: &'a [u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<&'a [u8], Self::Error> {
        verify_from_slice(serialized_proof, code_commitment)
    }

    fn verify_and_extract_output<
        Da: sov_rollup_interface::da::DaSpec,
        Root: Serialize + DeserializeOwned,
    >(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let output = Self::verify(serialized_proof, code_commitment)?;
        Ok(risc0_zkvm::serde::from_slice(output)?)
    }
}

/// A verifier for Risc0 proofs.
pub struct Risc0Verifier;

impl Zkvm for Risc0Verifier {
    type CodeCommitment = Risc0MethodId;

    type Error = anyhow::Error;

    fn verify<'a>(
        serialized_proof: &'a [u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<&'a [u8], Self::Error> {
        verify_from_slice(serialized_proof, code_commitment)
    }

    fn verify_and_extract_output<
        Da: sov_rollup_interface::da::DaSpec,
        Root: Serialize + DeserializeOwned,
    >(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let output = Self::verify(serialized_proof, code_commitment)?;
        Ok(risc0_zkvm::serde::from_slice(output)?)
    }
}

fn verify_from_slice<'a>(
    serialized_proof: &'a [u8],
    code_commitment: &Risc0MethodId,
) -> Result<&'a [u8], anyhow::Error> {
    let Risc0Proof::<'a> {
        receipt, journal, ..
    } = bincode::deserialize(serialized_proof)?;

    // after upgrade to risc0, verify is now in type Receipt
    // unless we change trait return types we have to clone here.
    let receipt: Receipt = Receipt::new(receipt, journal.to_vec());

    receipt.verify(code_commitment.0)?;

    Ok(journal)
}

/// A convenience type which contains the same data a Risc0 [`Receipt`] but borrows the journal
/// data. This allows us to avoid one unnecessary copy during proof verification.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Risc0Proof<'a> {
    /// The cryptographic data certifying the execution of the program.
    pub receipt: InnerReceipt,
    /// The public outputs produced by the program execution.
    pub journal: &'a [u8],
}

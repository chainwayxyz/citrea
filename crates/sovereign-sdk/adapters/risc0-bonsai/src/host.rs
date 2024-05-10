//! This module implements the [`ZkvmHost`] trait for the RISC0 VM.

use std::time::Duration;

use ::bonsai_sdk::alpha::Client;
use anyhow::anyhow;
use bonsai_sdk::alpha as bonsai_sdk;
use risc0_zkvm::serde::to_vec;
use risc0_zkvm::{
    compute_image_id, ExecutorEnvBuilder, ExecutorImpl, InnerReceipt, Journal, Receipt,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};

use crate::Risc0MethodId;

/// A [`Risc0BonsaiHost`] stores a binary to execute in the Risc0 VM and prove in the Risc0 Bonsai API.
#[derive(Clone)]
pub struct Risc0BonsaiHost<'a> {
    elf: &'a [u8],
    env: Vec<u32>,
    image_id: String,
    client: Client,
    last_input_id: Option<String>,
}

#[cfg(not(feature = "bench"))]
#[inline(always)]
fn add_benchmarking_callbacks(env: ExecutorEnvBuilder<'_>) -> ExecutorEnvBuilder<'_> {
    env
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

        // Compute the image_id, then upload the ELF with the image_id as its key.
        // handle error
        let image_id = hex::encode(compute_image_id(elf).unwrap());
        // handle error
        client.upload_img(&image_id, elf.to_vec()).unwrap();

        Self {
            elf,
            env: Default::default(),
            image_id,
            client,
            last_input_id: None,
        }
    }
}

impl<'a> ZkvmHost for Risc0BonsaiHost<'a> {
    type Guest = Risc0Guest;

    fn add_hint<T: serde::Serialize>(&mut self, item: T) {
        // For running in "execute" mode.

        // We use the in-memory size of `item` as an indication of how much
        // space to reserve. This is in no way guaranteed to be exact, but
        // usually the in-memory size and serialized data size are quite close.
        //
        // Note: this is just an optimization to avoid frequent reallocations,
        // it's not actually required.
        self.env
            .reserve(std::mem::size_of::<T>() / std::mem::size_of::<u32>());

        let mut serializer = risc0_zkvm::serde::Serializer::new(&mut self.env);
        item.serialize(&mut serializer)
            .expect("Risc0 hint serialization is infallible");

        // For running in "prove" mode.

        // Prepare input data and upload it.
        let input_data = to_vec(&item).unwrap();
        let input_data = bytemuck::cast_slice(&input_data).to_vec();
        // handle error
        let input_id = self.client.upload_input(input_data).unwrap();

        self.last_input_id = Some(input_id);
    }

    /// Guest simulation (execute mode) is run inside the Risc0 VM locally
    fn simulate_with_hints(&mut self) -> Self::Guest {
        Risc0Guest::with_hints(std::mem::take(&mut self.env))
    }

    /// Only with_proof = true is supported.
    /// Proofs are created on the Bonsai API.
    fn run(&mut self, with_proof: bool) -> Result<Proof, anyhow::Error> {
        if !with_proof {
            let env = add_benchmarking_callbacks(ExecutorEnvBuilder::default())
                .write_slice(&self.env)
                .build()
                .unwrap();
            let mut executor = ExecutorImpl::from_elf(env, self.elf)?;

            let session = executor.run()?;
            let data = bincode::serialize(&session.journal)?;

            Ok(Proof::PublicInput(data))
        } else {
            let input_id = self.last_input_id.take();

            let input_id = match input_id {
                Some(input_id) => input_id,
                None => return Err(anyhow::anyhow!("No input data provided")),
            };

            // Start a session running the prover
            let session = self
                .client
                //hanfle error
                .create_session(self.image_id.clone(), input_id, vec![])
                .map_err(|e| anyhow!("Bonsai API return error: {}", e))?;
            loop {
                // handle error
                let res = session.status(&self.client).unwrap();
                if res.status == "RUNNING" {
                    println!(
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

                    let receipt_buf = self.client.download(&receipt_url)?;

                    // let receipt: Receipt = bincode::deserialize(&receipt_buf).unwrap();

                    return Ok(Proof::Full(receipt_buf));
                } else {
                    return Err(anyhow!(
                        "Workflow exited: {} with error message: {}",
                        res.status,
                        res.error_msg.unwrap_or_default()
                    ));
                }
            }
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

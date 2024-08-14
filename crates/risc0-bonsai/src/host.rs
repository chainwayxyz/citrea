//! This module implements the [`ZkvmHost`] trait for the RISC0 VM.
use std::time::Duration;

use anyhow::anyhow;
use backoff::exponential::ExponentialBackoffBuilder;
use backoff::{retry as retry_backoff, SystemClock};
use bonsai_sdk::blocking::Client;
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{
    compute_image_id, ExecutorEnvBuilder, ExecutorImpl, Groth16Receipt, InnerReceipt, Journal,
    Receipt,
};
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};
use tracing::{error, info, warn};

macro_rules! retry_backoff_bonsai {
    ($bonsai_call:expr) => {
        retry_backoff(
            ExponentialBackoffBuilder::<SystemClock>::new()
                .with_initial_interval(Duration::from_secs(5))
                .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
                .build(),
            || {
                let response = $bonsai_call;
                match response {
                    Ok(r) => Ok(r),
                    Err(e) => {
                        use ::bonsai_sdk::SdkErr::*;
                        match e {
                            InternalServerErr(s) => {
                                let err = format!("Got HHTP 500 from Bonsai: {}", s);
                                warn!(err);
                                Err(backoff::Error::transient(err))
                            }
                            HttpErr(e) => {
                                let err = format!("Reconnecting to Bonsai: {}", e);
                                error!(err);
                                Err(backoff::Error::transient(err))
                            }
                            HttpHeaderErr(e) => {
                                let err = format!("Reconnecting to Bonsai: {}", e);
                                error!(err);
                                Err(backoff::Error::transient(err))
                            }
                            e => {
                                let err = format!("Got unrecoverable error from Bonsai: {}", e);
                                error!(err);
                                Err(backoff::Error::permanent(err))
                            }
                        }
                    }
                }
            },
        )
    };
}

/// A [`Risc0BonsaiHost`] stores a binary to execute in the Risc0 VM and prove in the Risc0 Bonsai API.
#[derive(Clone)]
pub struct Risc0BonsaiHost<'a> {
    elf: &'a [u8],
    env: Vec<u8>,
    image_id: Digest,
    client: Option<Client>,
    last_input_id: Option<String>,
}

impl<'a> Risc0BonsaiHost<'a> {
    /// Create a new Risc0Host to prove the given binary.
    pub fn new(elf: &'a [u8], api_url: String, api_key: String) -> Self {
        // Compute the image_id, then upload the ELF with the image_id as its key.
        // handle error
        let image_id = compute_image_id(elf).unwrap();

        tracing::trace!("Calculated image id: {:?}", image_id.as_words());

        // handle error
        let client = if !api_url.is_empty() && !api_key.is_empty() {
            tracing::debug!("Uploading image with id: {}", image_id);

            let client = Client::from_parts(api_url, api_key, risc0_zkvm::VERSION)
                .expect("Failed to create Bonsai client; qed");

            client
                .upload_img(hex::encode(image_id).as_str(), elf.to_vec())
                .expect("Failed to upload image; qed");

            Some(client)
        } else {
            None
        };

        Self {
            elf,
            env: Default::default(),
            image_id,
            client,
            last_input_id: None,
        }
    }

    fn upload_to_bonsai(&mut self, buf: Vec<u8>) {
        // handle error
        let input_id = retry_backoff_bonsai!(self
            .client
            .as_ref()
            .expect("Bonsai client is not initialized")
            .upload_input(buf.clone()))
        .expect("Failed to upload input; qed");
        tracing::info!("Uploaded input with id: {}", input_id);
        self.last_input_id = Some(input_id);
    }
}

impl<'a> ZkvmHost for Risc0BonsaiHost<'a> {
    type Guest = Risc0Guest;

    fn add_hint<T: BorshSerialize>(&mut self, item: T) {
        // For running in "execute" mode.

        let buf = borsh::to_vec(&item).expect("Risc0 hint serialization is infallible");
        info!("Added hint to guest with size {}", buf.len());

        // write buf
        self.env.extend_from_slice(&buf);

        if self.client.is_some() {
            self.upload_to_bonsai(buf);
        }
    }

    /// Guest simulation (execute mode) is run inside the Risc0 VM locally
    fn simulate_with_hints(&mut self) -> Self::Guest {
        Risc0Guest::with_hints(std::mem::take(&mut self.env))
    }

    /// Only with_proof = true is supported.
    /// Proofs are created on the Bonsai API.
    fn run(&mut self, with_proof: bool) -> Result<Proof, anyhow::Error> {
        if !with_proof {
            let env =
                sov_risc0_adapter::host::add_benchmarking_callbacks(ExecutorEnvBuilder::default())
                    .write_slice(&self.env)
                    .build()
                    .unwrap();
            let mut executor = ExecutorImpl::from_elf(env, self.elf)?;

            let session = executor.run()?;
            // don't delete useful while benchmarking
            // println!(
            //     "user cycles: {}\ntotal cycles: {}\nsegments: {}",
            //     session.user_cycles,
            //     session.total_cycles,
            //     session.segments.len()
            // );
            let data = bincode::serialize(&session.journal.expect("Journal shouldn't be empty"))?;

            Ok(Proof::PublicInput(data))
        } else {
            let client = self.client.as_ref().ok_or_else(|| {
                anyhow!("Bonsai client is not initialized running in full node mode or missing API URL or API key")
            })?;

            let input_id = self.last_input_id.take();

            let input_id = match input_id {
                Some(input_id) => input_id,
                None => return Err(anyhow::anyhow!("No input data provided")),
            };

            // Start a session running the prover
            // execute only is set to false because we run bonsai only when proving
            let session = retry_backoff_bonsai!(client.create_session(
                hex::encode(self.image_id),
                input_id.clone(),
                vec![],
                false
            ))
            .expect("Failed to create session; qed");
            tracing::info!("Session created: {}", session.uuid);
            let receipt = loop {
                // handle error
                let res = retry_backoff_bonsai!(session.status(client))
                    .expect("Failed to fetch status; qed");

                if res.status == "RUNNING" {
                    tracing::info!(
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

                    tracing::info!("Receipt URL: {}", receipt_url);
                    if let Some(stats) = res.stats {
                        tracing::info!(
                            "User cycles: {} - Total cycles: {} - Segments: {}",
                            stats.cycles,
                            stats.total_cycles,
                            stats.segments,
                        );
                    }

                    let receipt_buf = retry_backoff_bonsai!(client.download(receipt_url.as_str()))
                        .expect("Failed to download receipt; qed");

                    let receipt: Receipt = bincode::deserialize(&receipt_buf).unwrap();

                    break receipt;
                } else {
                    return Err(anyhow!(
                        "Workflow exited: {} with error message: {}",
                        res.status,
                        res.error_msg.unwrap_or_default()
                    ));
                }
            };

            tracing::info!("Creating the SNARK");

            let snark_session = retry_backoff_bonsai!(client.create_snark(session.uuid.clone()))
                .expect("Failed to create snark session; qed");

            tracing::info!("SNARK session created: {}", snark_session.uuid);

            loop {
                let res = retry_backoff_bonsai!(snark_session.status(client))
                    .expect("Failed to fetch status; qed");
                match res.status.as_str() {
                    "RUNNING" => {
                        tracing::info!("Current status: {} - continue polling...", res.status,);
                        std::thread::sleep(Duration::from_secs(15));
                        continue;
                    }
                    "SUCCEEDED" => {
                        let snark_receipt = match res.output {
                            Some(output) => output,
                            None => {
                                return Err(anyhow!(
                                    "SNARK session succeeded but no output was provided"
                                ))
                            }
                        };
                        tracing::info!("Snark proof!: {snark_receipt:?}");

                        // now we convert the snark_receipt to a full receipt

                        use risc0_zkvm::sha::Digestible;
                        let inner = InnerReceipt::Groth16(Groth16Receipt::new(
                            snark_receipt.snark.to_vec(),
                            receipt.claim().expect("stark_2_snark error, receipt claim"),
                            risc0_zkvm::Groth16ReceiptVerifierParameters::default().digest(),
                        ));

                        let full_snark_receipt = Receipt::new(inner, snark_receipt.journal);

                        tracing::info!("Full snark proof!: {full_snark_receipt:?}");

                        let full_snark_receipt = bincode::serialize(&full_snark_receipt)?;

                        return Ok(Proof::Full(full_snark_receipt));
                    }
                    _ => {
                        return Err(anyhow!(
                            "Workflow exited: {} with error message: {}",
                            res.status,
                            res.error_msg.unwrap_or_default()
                        ));
                    }
                }
            }
        }
    }

    fn extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        proof: &Proof,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let journal = match proof {
            Proof::PublicInput(journal) => {
                let journal: Journal = bincode::deserialize(journal)?;
                journal
            }
            Proof::Full(data) => {
                let receipt: Receipt = bincode::deserialize(data)?;
                receipt.journal
            }
        };
        Ok(BorshDeserialize::try_from_slice(&journal.bytes)?)
    }
}

impl<'host> Zkvm for Risc0BonsaiHost<'host> {
    type CodeCommitment = Digest;

    type Error = anyhow::Error;

    fn verify<'a>(
        _serialized_proof: &'a [u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<&'a [u8], Self::Error> {
        unimplemented!();
    }

    fn verify_and_extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let receipt: Receipt = bincode::deserialize(serialized_proof)?;

        #[allow(clippy::clone_on_copy)]
        receipt.verify(code_commitment.clone())?;

        Ok(BorshDeserialize::deserialize(
            &mut receipt.journal.bytes.as_slice(),
        )?)
    }
}

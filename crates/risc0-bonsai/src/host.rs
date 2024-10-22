//! This module implements the [`ZkvmHost`] trait for the RISC0 VM.
use core::str;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use backoff::exponential::ExponentialBackoffBuilder;
use backoff::{retry as retry_backoff, SystemClock};
use bonsai_sdk::blocking::Client;
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{
    compute_image_id, ExecutorEnvBuilder, ExecutorImpl, ExternalProver, Journal, Prover, ProverOpts, Receipt
};
use sov_db::ledger_db::{LedgerDB, ProvingServiceLedgerOps};
use sov_risc0_adapter::guest::Risc0Guest;
use sov_risc0_adapter::host::add_benchmarking_callbacks;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};
use tracing::{error, info, warn};

type StarkSessionId = String;
type SnarkSessionId = String;

/// Bonsai sessions to be recovered in case of a crash.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum BonsaiSession {
    /// Stark session id if the prover crashed during stark proof generation.
    StarkSession(StarkSessionId),
    /// Both Stark and Snark session id if the prover crashed during stark to snarkconversion.
    SnarkSession(StarkSessionId, SnarkSessionId),
}

/// Recovered bonsai session.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RecoveredBonsaiSession {
    /// Used for sending proofs in order
    pub id: u8,
    /// Recovered session
    pub session: BonsaiSession,
}

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
    ledger_db: LedgerDB,
}

impl<'a> Risc0BonsaiHost<'a> {
    /// Create a new Risc0Host to prove the given binary.
    pub fn new(elf: &'a [u8], api_url: String, api_key: String, ledger_db: LedgerDB) -> Self {
        // Compute the image_id, then upload the ELF with the image_id as its key.
        // handle error
        let image_id = compute_image_id(elf).unwrap();

        tracing::trace!("Calculated image id: {:?}", image_id.as_words());

        // handle error
        let client = if !api_url.is_empty() && !api_key.is_empty() {
            tracing::debug!("Uploading image with id: {}", image_id);
            let elf = elf.to_vec();
            thread::spawn(move || {
                let client = Client::from_parts(api_url, api_key, risc0_zkvm::VERSION)
                    .expect("Failed to create Bonsai client; qed");

                client
                    .upload_img(hex::encode(image_id).as_str(), elf)
                    .expect("Failed to upload image; qed");

                tracing::debug!("Image uploaded");

                Some(client)
            })
            .join()
            .unwrap()
        } else {
            None
        };

        Self {
            elf,
            env: Default::default(),
            image_id,
            client,
            ledger_db,
        }
    }

    fn upload_to_bonsai(&self, client: &Client, buf: Vec<u8>) -> String {
        let client = client.clone();
        let input_id =
            thread::spawn(move || retry_backoff_bonsai!(client.upload_input(buf.clone())))
                .join()
                .unwrap()
                .expect("Failed to upload input; qed");
        tracing::info!("Uploaded input with id: {}", input_id);
        input_id
    }

    fn receipt_loop(&self, session: &str, client: &Client) -> Result<Vec<u8>, anyhow::Error> {
        let session = bonsai_sdk::blocking::SessionId::new(session.to_owned());
        loop {
            // handle error
            let session = session.clone();
            let client_clone = client.clone();
            let res = thread::spawn(move || {
                retry_backoff_bonsai!(session.status(&client_clone))
                    .expect("Failed to fetch status; qed")
            })
            .join()
            .unwrap();

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
                let client_clone = client.clone();
                let receipt_buf = thread::spawn(move || {
                    retry_backoff_bonsai!(client_clone.download(receipt_url.as_str()))
                })
                .join()
                .unwrap()
                .expect("Failed to download receipt; qed");
                break Ok(receipt_buf);
            } else {
                return Err(anyhow!(
                    "Workflow exited: {} with error message: {}",
                    res.status,
                    res.error_msg.unwrap_or_default()
                ));
            }
        }
    }

    fn wait_for_receipt(&self, session: &str) -> Result<Vec<u8>, anyhow::Error> {
        let session = bonsai_sdk::blocking::SessionId::new(session.to_string());
        let client = self.client.as_ref().unwrap();
        self.receipt_loop(&session.uuid, client)
    }

    fn wait_for_stark_to_snark_conversion(
        &self,
        snark_session: Option<&str>,
        stark_session: &str,
    ) -> Result<Proof, anyhow::Error> {
        // If snark session exists use it else create one from stark
        let snark_session = match snark_session {
            Some(snark_session) => bonsai_sdk::blocking::SnarkId::new(snark_session.to_string()),
            None => {
                let client = self.client.clone().unwrap();
                let session = bonsai_sdk::blocking::SessionId::new(stark_session.to_string());
                thread::spawn(move || {
                    retry_backoff_bonsai!(client.create_snark(session.uuid.clone()))
                        .expect("Failed to create snark session; qed")
                })
                .join()
                .unwrap()
            }
        };

        let recovered_serialized_snark_session = borsh::to_vec(&RecoveredBonsaiSession {
            id: 0,
            session: BonsaiSession::SnarkSession(
                stark_session.to_string(),
                snark_session.uuid.clone(),
            ),
        })?;
        self.ledger_db
            .add_pending_proving_session(recovered_serialized_snark_session.clone())?;

        let client = self.client.as_ref().unwrap();
        loop {
            let snark_session = snark_session.clone();
            let client_clone = client.clone();
            let res = thread::spawn(move || {
                retry_backoff_bonsai!(snark_session.status(&client_clone))
                    .expect("Failed to fetch status; qed")
            })
            .join()
            .unwrap();
            match res.status.as_str() {
                "RUNNING" => {
                    tracing::info!("Current status: {} - continue polling...", res.status,);
                    std::thread::sleep(Duration::from_secs(15));
                    continue;
                }
                "SUCCEEDED" => {
                    let snark_receipt_url = match res.output {
                        Some(output) => output,
                        None => {
                            return Err(anyhow!(
                                "SNARK session succeeded but no output was provided"
                            ))
                        }
                    };

                    let client_clone = client.clone();
                    let snark_receipt_buf = thread::spawn(move || {
                        retry_backoff_bonsai!(client_clone.download(snark_receipt_url.as_str()))
                    })
                    .join()
                    .unwrap()
                    .expect("Failed to download receipt; qed");

                    let snark_receipt: Receipt = bincode::deserialize(&snark_receipt_buf.clone())?;

                    tracing::info!("Snark proof!: {snark_receipt:?}");

                    // now we convert the snark_receipt to a full receipt

                    return Ok(Proof::Full(snark_receipt_buf));
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

impl<'a> ZkvmHost for Risc0BonsaiHost<'a> {
    type Guest = Risc0Guest;

    fn add_hint<T: BorshSerialize>(&mut self, item: T) {
        // For running in "execute" mode.

        let buf = borsh::to_vec(&item).expect("Risc0 hint serialization is infallible");
        info!("Added hint to guest with size {}", buf.len());

        // write buf
        self.env.extend_from_slice(&buf);
    }

    /// Guest simulation (execute mode) is run inside the Risc0 VM locally
    fn simulate_with_hints(&mut self) -> Self::Guest {
        Risc0Guest::with_hints(std::mem::take(&mut self.env))
    }

    /// Only with_proof = true is supported.
    /// Proofs are created on the Bonsai API.
    fn run(&mut self, with_proof: bool) -> Result<Proof, anyhow::Error> {
        let proof = match (self.client.as_ref(), with_proof) {
            // Local execution. If mode is Execute, we always do local execution.
            (_, false) => {
                let env = add_benchmarking_callbacks(ExecutorEnvBuilder::default())
                    .write_slice(&self.env)
                    .build()
                    .unwrap();
                let mut executor = ExecutorImpl::from_elf(env, self.elf)?;

                let session = executor.run()?;
                let data =
                    bincode::serialize(&session.journal.expect("Journal shouldn't be empty"))?;

                Ok(Proof::PublicInput(data))
            }
            // Local proving
            (None, true) => {
                let env = add_benchmarking_callbacks(ExecutorEnvBuilder::default())
                    .write_slice(&self.env)
                    .build()
                    .unwrap();

                // let prover = LocalProver::new("citrea");
                let prover = ExternalProver::new("citrea", get_r0vm_path());

                let start = std::time::Instant::now();
                let proving_session =
                    prover.prove_with_opts(env, self.elf, &ProverOpts::groth16())?;
                let end = std::time::Instant::now();

                tracing::info!("Local proving completed");

                proving_session.receipt.verify(self.image_id)?;

                tracing::info!("Verified the receipt");

                tracing::error!(
                    "Proving stats:\tuser cycles: {}\ttotal cycles: {}\ttotal time: {}",
                    proving_session.stats.user_cycles,
                    proving_session.stats.total_cycles,
                    (end - start).as_secs_f64()
                );

                let serialized_receipt = bincode::serialize(&proving_session.receipt)?;

                Ok(Proof::Full(serialized_receipt))
            }
            // Bonsai proving
            (Some(client), true) => {
                // Upload input to Bonsai
                let input_id = self.upload_to_bonsai(client, self.env.clone());

                let image_id = hex::encode(self.image_id);
                let client_clone = client.clone();
                // Start a Bonsai session
                let session = thread::spawn(move || {
                    retry_backoff_bonsai!(client_clone.create_session(
                        image_id.clone(),
                        input_id.clone(),
                        vec![],
                        false
                    ))
                    .expect("Failed to fetch status; qed")
                })
                .join()
                .unwrap();
                let stark_session = RecoveredBonsaiSession {
                    id: 0,
                    session: BonsaiSession::StarkSession(session.uuid.clone()),
                };
                let serialized_stark_session = borsh::to_vec(&stark_session)
                    .expect("Bonsai host should be able to serialize bonsai sessions");
                self.ledger_db
                    .add_pending_proving_session(serialized_stark_session.clone())?;

                tracing::info!("Session created: {}", session.uuid);

                let _receipt = self.wait_for_receipt(&session.uuid)?;

                tracing::info!("Creating the SNARK");

                let client_clone = client.clone();
                let uuid = session.uuid.clone();
                let snark_session = thread::spawn(move || {
                    retry_backoff_bonsai!(client_clone.create_snark(uuid.clone()))
                        .expect("Failed to fetch status; qed")
                })
                .join()
                .unwrap();

                // Remove the stark session as it is finished
                self.ledger_db
                    .remove_pending_proving_session(serialized_stark_session)?;

                tracing::info!("SNARK session created: {}", snark_session.uuid);

                // Snark session is saved in the function
                self.wait_for_stark_to_snark_conversion(Some(&snark_session.uuid), &session.uuid)
            }
        }?;

        // Cleanup env
        self.env.clear();

        Ok(proof)
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

    fn recover_proving_sessions(&self) -> Result<Vec<Proof>, anyhow::Error> {
        if self.client.is_none() {
            tracing::debug!("Skipping bonsai session recovery");
            return Ok(vec![]);
        }

        let sessions = self.ledger_db.get_pending_proving_sessions()?;
        tracing::info!("Recovering {} bonsai sessions", sessions.len());
        let mut proofs = Vec::new();
        for session in sessions {
            let bonsai_session: RecoveredBonsaiSession = BorshDeserialize::try_from_slice(&session)
                .expect("Bonsai host should be able to recover bonsai sessions");

            tracing::info!("Recovering bonsai session: {:?}", bonsai_session);
            match bonsai_session.session {
                BonsaiSession::StarkSession(stark_session) => {
                    let _receipt = self.wait_for_receipt(&stark_session)?;
                    let proof = self.wait_for_stark_to_snark_conversion(None, &stark_session)?;
                    proofs.push(proof);
                }
                BonsaiSession::SnarkSession(stark_session, snark_session) => {
                    let _receipt = self.wait_for_receipt(&stark_session)?;
                    let proof = self
                        .wait_for_stark_to_snark_conversion(Some(&snark_session), &stark_session)?;
                    proofs.push(proof)
                }
            }
        }
        Ok(proofs)
    }
}

impl<'host> Zkvm for Risc0BonsaiHost<'host> {
    type CodeCommitment = Digest;

    type Error = anyhow::Error;

    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<Vec<u8>, Self::Error> {
        let receipt: Receipt = bincode::deserialize(serialized_proof)?;

        #[allow(clippy::clone_on_copy)]
        receipt.verify(code_commitment.clone())?;

        Ok(receipt.journal.bytes)
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

fn get_r0vm_path() -> PathBuf {
    let output = Command::new("which")
        .arg("r0vm")
        .output()
        .expect("Failed to execute `which r0vm` command");
    assert!(output.status.success(), "r0vm binary must be available in PATH");

    let path = str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");
    path.into()
}

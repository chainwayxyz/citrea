//! This module implements the [`ZkvmHost`] trait for the RISC0 VM.

use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use bonsai_sdk::alpha as bonsai_sdk;
use bonsai_sdk::responses::SnarkReceipt;
use risc0_zkvm::serde::to_vec;
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{
    compute_image_id, CompactReceipt, ExecutorEnvBuilder, ExecutorImpl, InnerReceipt, Journal,
    Receipt,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};

use crate::Risc0MethodId;

/// Requests to bonsai client. Each variant represents its own method.
enum BonsaiRequest {
    UploadImg {
        image_id: String,
        buf: Vec<u8>,
        notify: Sender<Result<bool, bonsai_sdk::SdkErr>>,
    },
    UploadInput {
        buf: Vec<u8>,
        notify: Sender<Result<String, bonsai_sdk::SdkErr>>,
    },
    Download {
        url: String,
        notify: Sender<Result<Vec<u8>, bonsai_sdk::SdkErr>>,
    },
    CreateSession {
        img_id: String,
        input_id: String,
        assumptions: Vec<String>,
        notify: Sender<Result<bonsai_sdk::SessionId, bonsai_sdk::SdkErr>>,
    },
    CreateSnark {
        session: bonsai_sdk::SessionId,
        notify: Sender<Result<bonsai_sdk::SnarkId, bonsai_sdk::SdkErr>>,
    },
    Status {
        session: bonsai_sdk::SessionId,
        notify: Sender<Result<bonsai_sdk::responses::SessionStatusRes, bonsai_sdk::SdkErr>>,
    },
    SnarkStatus {
        session: bonsai_sdk::SnarkId,
        notify: Sender<Result<bonsai_sdk::responses::SnarkStatusRes, bonsai_sdk::SdkErr>>,
    },
}

/// A wrapper around Bonsai SDK to handle tokio runtime inside another tokio runtime.
/// See https://stackoverflow.com/a/62536772.
#[derive(Clone)]
struct BonsaiClient {
    queue: std::sync::mpsc::Sender<BonsaiRequest>,
    _join_handle: Arc<std::thread::JoinHandle<()>>,
}

impl BonsaiClient {
    fn from_parts(api_url: String, api_key: String, risc0_version: &str) -> Self {
        let risc0_version = risc0_version.to_string();
        let (queue, rx) = std::sync::mpsc::channel();
        let join_handle = std::thread::spawn(move || {
            let client = bonsai_sdk::Client::from_parts(api_url, api_key, &risc0_version).unwrap();
            loop {
                let request = rx.recv().expect("bonsai client sender is dead");
                match request {
                    BonsaiRequest::UploadImg {
                        image_id,
                        buf,
                        notify,
                    } => {
                        let res = client.upload_img(&image_id, buf);
                        let _ = notify.send(res);
                    }
                    BonsaiRequest::UploadInput { buf, notify } => {
                        let res = client.upload_input(buf);
                        let _ = notify.send(res);
                    }
                    BonsaiRequest::Download { url, notify } => {
                        let res = client.download(&url);
                        let _ = notify.send(res);
                    }
                    BonsaiRequest::CreateSession {
                        img_id,
                        input_id,
                        assumptions,
                        notify,
                    } => {
                        let res = client.create_session(img_id, input_id, assumptions);
                        let _ = notify.send(res);
                    }
                    BonsaiRequest::Status { session, notify } => {
                        let res = session.status(&client);
                        let _ = notify.send(res);
                    }
                    BonsaiRequest::CreateSnark { session, notify } => {
                        let res = client.create_snark(session.uuid);
                        let _ = notify.send(res);
                    }
                    BonsaiRequest::SnarkStatus { session, notify } => {
                        let res = session.status(&client);
                        let _ = notify.send(res);
                    }
                }
            }
        });
        let _join_handle = Arc::new(join_handle);
        Self {
            queue,
            _join_handle,
        }
    }

    fn upload_img(&self, image_id: String, buf: Vec<u8>) -> Result<bool, bonsai_sdk::SdkErr> {
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BonsaiRequest::UploadImg {
                image_id,
                buf,
                notify,
            })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    fn upload_input(&self, buf: Vec<u8>) -> Result<String, bonsai_sdk::SdkErr> {
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BonsaiRequest::UploadInput { buf, notify })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    fn download(&self, url: String) -> Result<Vec<u8>, bonsai_sdk::SdkErr> {
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BonsaiRequest::Download { url, notify })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    fn create_session(
        &self,
        img_id: String,
        input_id: String,
        assumptions: Vec<String>,
    ) -> Result<bonsai_sdk::SessionId, bonsai_sdk::SdkErr> {
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BonsaiRequest::CreateSession {
                img_id,
                input_id,
                assumptions,
                notify,
            })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    fn status(
        &self,
        session: &bonsai_sdk::SessionId,
    ) -> Result<bonsai_sdk::responses::SessionStatusRes, bonsai_sdk::SdkErr> {
        let session = session.clone();
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BonsaiRequest::Status { session, notify })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    fn create_snark(
        &self,
        session: &bonsai_sdk::SessionId,
    ) -> Result<bonsai_sdk::SnarkId, bonsai_sdk::SdkErr> {
        let session = session.clone();
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BonsaiRequest::CreateSnark { session, notify })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    fn snark_status(
        &self,
        snark_session: &bonsai_sdk::SnarkId,
    ) -> Result<bonsai_sdk::responses::SnarkStatusRes, bonsai_sdk::SdkErr> {
        let snark_session = snark_session.clone();
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BonsaiRequest::SnarkStatus {
                session: snark_session,
                notify,
            })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }
}

/// A [`Risc0BonsaiHost`] stores a binary to execute in the Risc0 VM and prove in the Risc0 Bonsai API.
#[derive(Clone)]
pub struct Risc0BonsaiHost<'a> {
    elf: &'a [u8],
    env: Vec<u32>,
    image_id: Digest,
    client: Option<BonsaiClient>,
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
    pub fn new(elf: &'a [u8], api_url: String, api_key: String) -> Self {
        // Compute the image_id, then upload the ELF with the image_id as its key.
        // handle error
        let image_id = compute_image_id(elf).unwrap();

        // handle error
        let client = if !api_url.is_empty() && !api_key.is_empty() {
            let client = BonsaiClient::from_parts(api_url, api_key, risc0_zkvm::VERSION);

            tracing::info!("Uploading image with id: {}", image_id);
            // handle error

            client
                .upload_img(hex::encode(image_id), elf.to_vec())
                .unwrap();

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

    fn add_hint_bonsai<T: serde::Serialize>(&mut self, item: T) {
        // For running in "prove" mode.

        // Prepare input data and upload it.
        let client = self.client.as_ref().unwrap();

        let input_data = to_vec(&item).unwrap();
        let input_data = bytemuck::cast_slice(&input_data).to_vec();
        // handle error
        let input_id = client.upload_input(input_data).unwrap();
        tracing::info!("Uploaded input with id: {}", input_id);
        self.last_input_id = Some(input_id);
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

        if self.client.is_some() {
            self.add_hint_bonsai(item)
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
            let env = add_benchmarking_callbacks(ExecutorEnvBuilder::default())
                .write_slice(&self.env)
                .build()
                .unwrap();
            let mut executor = ExecutorImpl::from_elf(env, self.elf)?;

            let session = executor.run()?;
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
            let session = client
                //hanfle error
                .create_session(hex::encode(self.image_id.clone()), input_id, vec![])
                .map_err(|e| anyhow!("Bonsai API return error: {}", e))?;
            tracing::info!("Session created: {}", session.uuid);
            let receipt = loop {
                // handle error
                let res = client.status(&session).unwrap();
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
                    let receipt_buf = client.download(receipt_url)?;

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

            let snark_session = client
                .create_snark(&session)
                .map_err(|e| anyhow!("Bonsai API return error: {}", e))?;

            tracing::info!("SNARK session created: {}", snark_session.uuid);

            loop {
                let res = client.snark_status(&snark_session)?;
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

                        let full_snark_receipt = Receipt {
                            inner: InnerReceipt::Compact(CompactReceipt {
                                seal: snark_receipt.snark.to_vec(),
                                claim: receipt
                                    .get_claim()
                                    .expect("stark_2_snark error, receipt claim"),
                            }),
                            journal: risc0_zkvm::Journal {
                                bytes: snark_receipt.journal,
                            },
                        };

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
    type CodeCommitment = Digest;

    type Error = anyhow::Error;

    fn verify<'a>(
        serialized_proof: &'a [u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<&'a [u8], Self::Error> {
        unimplemented!();
    }

    fn verify_and_extract_output<
        Da: sov_rollup_interface::da::DaSpec,
        Root: Serialize + DeserializeOwned,
    >(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let receipt: Receipt = bincode::deserialize(serialized_proof)?;

        receipt.verify(code_commitment.clone())?;

        Ok(receipt.journal.decode()?)
    }

    fn get_code_commitment(&self) -> Self::CodeCommitment {
        self.image_id.clone()
    }
}

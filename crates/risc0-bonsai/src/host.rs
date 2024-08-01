//! This module implements the [`ZkvmHost`] trait for the RISC0 VM.

use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use bonsai_sdk::alpha as bonsai_sdk;
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{
    compute_image_id, ExecutorEnvBuilder, ExecutorImpl, Groth16Receipt, InnerReceipt, Journal,
    Receipt,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};
use tracing::{debug, error, instrument, trace, warn};

/// Requests to bonsai client. Each variant represents its own method.
#[derive(Clone)]
enum BonsaiRequest {
    UploadImg {
        image_id: String,
        buf: Vec<u8>,
        notify: Sender<bool>,
    },
    UploadInput {
        buf: Vec<u8>,
        notify: Sender<String>,
    },
    Download {
        url: String,
        notify: Sender<Vec<u8>>,
    },
    CreateSession {
        img_id: String,
        input_id: String,
        assumptions: Vec<String>,
        notify: Sender<bonsai_sdk::SessionId>,
    },
    CreateSnark {
        session: bonsai_sdk::SessionId,
        notify: Sender<bonsai_sdk::SnarkId>,
    },
    Status {
        session: bonsai_sdk::SessionId,
        notify: Sender<bonsai_sdk::responses::SessionStatusRes>,
    },
    SnarkStatus {
        session: bonsai_sdk::SnarkId,
        notify: Sender<bonsai_sdk::responses::SnarkStatusRes>,
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
        macro_rules! unwrap_bonsai_response {
            ($response:expr, $client_loop:lifetime, $queue_loop:lifetime) => (
                match $response {
                    Ok(r) => r,
                    Err(e) => {
                        use ::bonsai_sdk::alpha::SdkErr::*;
                        match e {
                            InternalServerErr(s) => {
                                warn!(%s, "Got HHTP 500 from Bonsai");
                                std::thread::sleep(Duration::from_secs(10));
                                continue $queue_loop
                            }
                            HttpErr(e) => {
                                error!(?e, "Reconnecting to Bonsai");
                                std::thread::sleep(Duration::from_secs(5));
                                continue $client_loop
                            }
                            HttpHeaderErr(e) => {
                                error!(?e, "Reconnecting to Bonsai");
                                std::thread::sleep(Duration::from_secs(5));
                                continue $client_loop
                            }
                            e => {
                                error!(?e, "Got unrecoverable error from Bonsai");
                                panic!("Bonsai API error: {}", e);
                            }
                        }
                    }
                }
            );
        }
        let risc0_version = risc0_version.to_string();
        let (queue, rx) = std::sync::mpsc::channel();
        let join_handle = std::thread::spawn(move || {
            let mut last_request: Option<BonsaiRequest> = None;
            'client: loop {
                debug!("Connecting to Bonsai");
                let client = match bonsai_sdk::Client::from_parts(
                    api_url.clone(),
                    api_key.clone(),
                    &risc0_version,
                ) {
                    Ok(client) => client,
                    Err(e) => {
                        error!(?e, "Failed to connect to Bonsai");
                        std::thread::sleep(Duration::from_secs(5));
                        continue 'client;
                    }
                };
                'queue: loop {
                    let request = if let Some(last_request) = last_request.clone() {
                        debug!("Retrying last request after reconnection");
                        last_request
                    } else {
                        trace!("Waiting for a new request");
                        let req: BonsaiRequest = rx.recv().expect("bonsai client sender is dead");
                        // Save request for retries
                        last_request = Some(req.clone());
                        req
                    };
                    match request {
                        BonsaiRequest::UploadImg {
                            image_id,
                            buf,
                            notify,
                        } => {
                            debug!(%image_id, "Bonsai:upload_img");
                            let res = client.upload_img(&image_id, buf);
                            let res = unwrap_bonsai_response!(res, 'client, 'queue);
                            let _ = notify.send(res);
                        }
                        BonsaiRequest::UploadInput { buf, notify } => {
                            debug!("Bonsai:upload_input");
                            let res = client.upload_input(buf);
                            let res = unwrap_bonsai_response!(res, 'client, 'queue);
                            let _ = notify.send(res);
                        }
                        BonsaiRequest::Download { url, notify } => {
                            debug!(%url, "Bonsai:download");
                            let res = client.download(&url);
                            let res = unwrap_bonsai_response!(res, 'client, 'queue);
                            let _ = notify.send(res);
                        }
                        BonsaiRequest::CreateSession {
                            img_id,
                            input_id,
                            assumptions,
                            notify,
                        } => {
                            debug!(%img_id, %input_id, "Bonsai:create_session");
                            let res = client.create_session(img_id, input_id, assumptions);
                            let res = unwrap_bonsai_response!(res, 'client, 'queue);
                            let _ = notify.send(res);
                        }
                        BonsaiRequest::Status { session, notify } => {
                            debug!(?session, "Bonsai:session_status");
                            let res = session.status(&client);
                            let res = unwrap_bonsai_response!(res, 'client, 'queue);
                            let _ = notify.send(res);
                        }
                        BonsaiRequest::CreateSnark { session, notify } => {
                            debug!(?session, "Bonsai:create_snark");
                            let res = client.create_snark(session.uuid);
                            let res = unwrap_bonsai_response!(res, 'client, 'queue);
                            let _ = notify.send(res);
                        }
                        BonsaiRequest::SnarkStatus { session, notify } => {
                            debug!(?session, "Bonsai:snark_status");
                            let res = session.status(&client);
                            let res = unwrap_bonsai_response!(res, 'client, 'queue);
                            let _ = notify.send(res);
                        }
                    };
                    // We arrive here only on a successful response
                    last_request = None;
                }
            }
        });
        let _join_handle = Arc::new(join_handle);
        Self {
            queue,
            _join_handle,
        }
    }

    #[instrument(level = "trace", skip(self, buf), ret)]
    fn upload_img(&self, image_id: String, buf: Vec<u8>) -> bool {
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

    #[instrument(level = "trace", skip_all, ret)]
    fn upload_input(&self, buf: Vec<u8>) -> String {
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BonsaiRequest::UploadInput { buf, notify })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    #[instrument(level = "trace", skip(self))]
    fn download(&self, url: String) -> Vec<u8> {
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BonsaiRequest::Download { url, notify })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    #[instrument(level = "trace", skip(self, assumptions), ret)]
    fn create_session(
        &self,
        img_id: String,
        input_id: String,
        assumptions: Vec<String>,
    ) -> bonsai_sdk::SessionId {
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

    #[instrument(level = "trace", skip(self))]
    fn status(&self, session: &bonsai_sdk::SessionId) -> bonsai_sdk::responses::SessionStatusRes {
        let session = session.clone();
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BonsaiRequest::Status { session, notify })
            .expect("Bonsai processing queue is dead");
        let status = rx.recv().unwrap();
        debug!(
            status.status,
            status.receipt_url, status.error_msg, status.state, status.elapsed_time
        );
        status
    }

    #[instrument(level = "trace", skip(self), ret)]
    fn create_snark(&self, session: &bonsai_sdk::SessionId) -> bonsai_sdk::SnarkId {
        let session = session.clone();
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BonsaiRequest::CreateSnark { session, notify })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    #[instrument(level = "trace", skip(self))]
    fn snark_status(
        &self,
        snark_session: &bonsai_sdk::SnarkId,
    ) -> bonsai_sdk::responses::SnarkStatusRes {
        let snark_session = snark_session.clone();
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BonsaiRequest::SnarkStatus {
                session: snark_session,
                notify,
            })
            .expect("Bonsai processing queue is dead");
        let status = rx.recv().unwrap();
        debug!(status.status, ?status.output, status.error_msg);
        status
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

impl<'a> Risc0BonsaiHost<'a> {
    /// Create a new Risc0Host to prove the given binary.
    pub fn new(elf: &'a [u8], api_url: String, api_key: String) -> Self {
        // Compute the image_id, then upload the ELF with the image_id as its key.
        // handle error
        let image_id = compute_image_id(elf).unwrap();

        tracing::trace!("Calculated image id: {:?}", image_id.as_words());

        // handle error
        let client = if !api_url.is_empty() && !api_key.is_empty() {
            let client = BonsaiClient::from_parts(api_url, api_key, risc0_zkvm::VERSION);

            tracing::debug!("Uploading image with id: {}", image_id);
            // handle error

            client.upload_img(hex::encode(image_id), elf.to_vec());

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

    fn add_hint_bonsai<T: BorshSerialize>(&mut self, item: T) {
        // For running in "prove" mode.

        // Prepare input data and upload it.
        let client = self.client.as_ref().unwrap();

        let mut input_data = vec![];
        let mut buf = borsh::to_vec(&item).unwrap();
        // append [0..] alignment
        let rem = buf.len() % 4;
        if rem > 0 {
            buf.extend(vec![0; 4 - rem]);
        }
        let buf_u32: &[u32] = bytemuck::cast_slice(&buf);
        // write len(u64) in LE
        let len = buf_u32.len() as u64;
        input_data.extend(len.to_le_bytes());
        // write buf
        input_data.extend(buf);

        // handle error
        let input_id = client.upload_input(input_data);
        tracing::info!("Uploaded input with id: {}", input_id);
        self.last_input_id = Some(input_id);
    }
}

impl<'a> ZkvmHost for Risc0BonsaiHost<'a> {
    type Guest = Risc0Guest;

    fn add_hint<T: BorshSerialize>(&mut self, item: T) {
        // For running in "execute" mode.

        let mut buf = borsh::to_vec(&item).expect("Risc0 hint serialization is infallible");
        // append [0..] alignment to cast &[u8] to &[u32]
        let rem = buf.len() % 4;
        if rem > 0 {
            buf.extend(vec![0; 4 - rem]);
        }
        let buf: &[u32] = bytemuck::cast_slice(&buf);
        // write len(u64) in LE
        let len = buf.len() as u64;
        let len_buf = &len.to_le_bytes()[..];
        let len_buf: &[u32] = bytemuck::cast_slice(len_buf);
        println!("LEN: {}", len);
        // !! UNCOMMENT WHEN TESTING WITH VEC ALLOC !!
        // self.env.extend_from_slice(len_buf);
        // write buf
        self.env.extend_from_slice(buf);

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
            let env =
                sov_risc0_adapter::host::add_benchmarking_callbacks(ExecutorEnvBuilder::default())
                    .write_slice(&self.env)
                    .build()
                    .unwrap();
            let mut executor = ExecutorImpl::from_elf(env, self.elf)?;

            let session = executor.run()?;
            // don't delete useful while benchmarking
            println!(
                "user cycles: {}\ntotal cycles: {}\nsegments: {}",
                session.user_cycles,
                session.total_cycles,
                session.segments.len()
            );
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
            let session = client.create_session(hex::encode(self.image_id), input_id, vec![]);
            tracing::info!("Session created: {}", session.uuid);
            let receipt = loop {
                // handle error
                let res = client.status(&session);

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
                    let receipt_buf = client.download(receipt_url);

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

            let snark_session = client.create_snark(&session);

            tracing::info!("SNARK session created: {}", snark_session.uuid);

            loop {
                let res = client.snark_status(&snark_session);
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

    fn verify_and_extract_output<
        Da: sov_rollup_interface::da::DaSpec,
        Root: Serialize + DeserializeOwned,
    >(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let receipt: Receipt = bincode::deserialize(serialized_proof)?;

        #[allow(clippy::clone_on_copy)]
        receipt.verify(code_commitment.clone())?;

        Ok(receipt.journal.decode()?)
    }
}

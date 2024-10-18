//! This module implements the [`ZkvmHost`] trait for the RISC0 VM.
use core::panic;
use std::str::FromStr;
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;

use alloy::hex::FromHex;
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::aliases::U96;
use alloy_primitives::utils::parse_ether;
use alloy_primitives::{Address, Bytes, U256};
use anyhow::anyhow;
use borsh::{BorshDeserialize, BorshSerialize};
use boundless_market::contracts::{Input, Offer, Predicate, ProvingRequest, Requirements};
use boundless_market::sdk::client::ClientError::{self};
use boundless_market::sdk::client::{self, Client};
use boundless_market::storage::BuiltinStorageProviderError;
use risc0_zkvm::sha::{Digest, Digestible};
use risc0_zkvm::{
    compute_image_id, default_executor, ExecutorEnv, ExecutorImpl, Groth16Receipt, InnerReceipt,
    Journal, MaybePruned, Receipt, ReceiptClaim,
};
use sov_db::ledger_db::LedgerDB;
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, instrument, trace, warn};
use url::Url;

#[derive(Clone)]
enum BoundlessRequest {
    UploadImg {
        elf: Vec<u8>,
        notify: Sender<String>,
    },
    UploadInput {
        input: Vec<u8>,
        notify: Sender<String>,
    },
    SubmitReq {
        proving_request: ProvingRequest,
        notify: Sender<U256>,
    },
    WaitForReqFulfillment {
        request_id: U256,
        check_interval: std::time::Duration,
        timeout: Option<std::time::Duration>,
        notify: Sender<Result<(Bytes, Bytes), ClientError>>,
    },
    Slash {
        request_id: U256,
        notify: Sender<Result<U256, ClientError>>,
    },
}

#[derive(Clone)]
struct BoundlessClient {
    queue: std::sync::mpsc::Sender<BoundlessRequest>,
    _join_handle: Arc<tokio::task::JoinHandle<()>>,
}

impl BoundlessClient {
    async fn from_parts(
        requestor_private_key: PrivateKeySigner,
        rpc_url: Url,
        proof_market_address: Address,
        set_verifier_address: Address,
    ) -> Self {
        macro_rules! unwrap_boundless_response {
            ($response:expr, $queue_loop:lifetime) => (
                match $response.await {
                    Ok(r) => r,
                    Err(e) => {
                        use ::boundless_market::sdk::client::ClientError;
                        match e {
                            // Match against the ClientError enum variants
                            ClientError::MarketError(e) => {
                                error!(?e, "Boundless Market Error");
                                sleep(Duration::from_secs(5)).await;
                                continue $queue_loop
                            }
                            ClientError::StorageProviderError(s) => {
                                warn!(%s, "Boundless Storage Provider Error");
                                sleep(Duration::from_secs(10)).await;
                                continue $queue_loop
                            }
                            ClientError::Error(e) => {
                                error!(?e, "Boundless Error");
                                sleep(Duration::from_secs(5)).await;
                                continue $queue_loop
                            }
                            _ => {
                                error!(?e, "Got unrecoverable error from Boundless");
                                panic!("Boundless API error: {}", e);
                            }
                        }
                    }
                }
            );
        }
        let (queue, rx) = std::sync::mpsc::channel();
        let join_handle = tokio::spawn(async move {
            let mut last_request: Option<BoundlessRequest> = None;
            'client: loop {
                debug!("Boundless client loop");
                let client = match Client::from_parts(
                    requestor_private_key.clone(),
                    rpc_url.clone(),
                    proof_market_address,
                    set_verifier_address,
                )
                .await
                {
                    Ok(client) => client,
                    Err(ClientError::StorageProviderError(BuiltinStorageProviderError::File(
                        _,
                    )))
                    | Err(ClientError::StorageProviderError(
                        BuiltinStorageProviderError::NoProvider,
                    )) => {
                        panic!("Failed to create boundless client: no storage provider or temp file storage provider error");
                    }
                    Err(e) => {
                        error!(?e, "Failed to create boundless client");
                        continue 'client;
                    }
                };
                'queue: loop {
                    let request = if let Some(last_request) = last_request.clone() {
                        debug!("Retrying last request after reconnection");
                        last_request
                    } else {
                        trace!("Waiting for a new request");
                        let req: BoundlessRequest =
                            rx.recv().expect("bonsai client sender is dead");
                        // Save request for retries
                        last_request = Some(req.clone());
                        req
                    };
                    match request {
                        BoundlessRequest::UploadImg { elf, notify } => {
                            let res = client.upload_image(&elf);
                            let res = unwrap_boundless_response!(res, 'queue);
                            let _ = notify.send(res);
                        }
                        BoundlessRequest::UploadInput { input, notify } => {
                            debug!("Boundless: upload_input");
                            let res = client.upload_input(&input);
                            let res = unwrap_boundless_response!(res, 'queue);
                            let _ = notify.send(res);
                        }
                        BoundlessRequest::SubmitReq {
                            proving_request,
                            notify,
                        } => {
                            debug!("Boundless: submit_req");
                            let res = client.submit_request(&proving_request);
                            let res = unwrap_boundless_response!(res, 'queue);
                            let _ = notify.send(res);
                        }
                        BoundlessRequest::WaitForReqFulfillment {
                            request_id,
                            check_interval,
                            timeout,
                            notify,
                        } => {
                            debug!("Boundless: wait_for_req_fulfillment");
                            let res = client
                                .wait_for_request_fulfillment(request_id, check_interval, timeout)
                                .await;
                            // There is no need to retry this request as this already has a retry mechanism inside
                            let _ = notify.send(res);
                        }
                        BoundlessRequest::Slash { request_id, notify } => {
                            debug!("Boundless: slash");
                            let res = client
                                .proof_market
                                .slash(request_id)
                                .await
                                .map_err(ClientError::MarketError);
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

    #[instrument(level = "trace", skip(self), ret)]
    fn upload_img(&self, elf: Vec<u8>) -> String {
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BoundlessRequest::UploadImg { elf, notify })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    #[instrument(level = "trace", skip_all, ret)]
    fn upload_input(&self, input: Vec<u8>) -> String {
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BoundlessRequest::UploadInput { input, notify })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    #[instrument(level = "trace", skip_all, ret)]
    fn submit_request(&self, proving_request: ProvingRequest) -> U256 {
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BoundlessRequest::SubmitReq {
                proving_request,
                notify,
            })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    #[instrument(level = "trace", skip_all, ret)]
    fn wait_for_request_fulfillment(
        &self,
        request_id: U256,
        check_interval: std::time::Duration,
        timeout: Option<std::time::Duration>,
    ) -> Result<(Bytes, Bytes), client::ClientError> {
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BoundlessRequest::WaitForReqFulfillment {
                request_id,
                check_interval,
                timeout,
                notify,
            })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }

    #[instrument(level = "trace", skip_all, ret)]
    fn slash(&self, request_id: U256) -> Result<U256, ClientError> {
        let (notify, rx) = mpsc::channel();
        self.queue
            .send(BoundlessRequest::Slash { request_id, notify })
            .expect("Bonsai processing queue is dead");
        rx.recv().unwrap()
    }
}

/// A [`Risc0BoundlessHost`] stores a binary to execute in the Risc0 VM and prove in the Risc0 Boundless Network.
#[derive(Clone)]
pub struct Risc0BoundlessHost<'a> {
    elf: &'a [u8],
    env: Vec<u8>,
    image_id: Digest,
    image_url: String,
    client: BoundlessClient,
    last_input_url: Option<String>,
    ledger_db: LedgerDB,
    proof_market_address: Address,
    set_verifier_address: Address,
}

impl<'a> Risc0BoundlessHost<'a> {
    /// Create a new Risc0Host to prove the given binary.
    pub async fn new(
        elf: &'a [u8],
        ledger_db: LedgerDB,
        requestor_private_key: String,
        rpc_url: Url,
        proof_market_address: String,
        set_verifier_address: String,
    ) -> Self {
        // Creates a storage provider based on the environment variables.
        //
        // If the environment variable `RISC0_DEV_MODE` is set, a temporary file storage provider is used.
        // Otherwise, the following environment variables are checked in order:
        // - `PINATA_JWT`, `PINATA_API_URL`, `IPFS_GATEWAY_URL`: Pinata storage provider;
        // - `S3_ACCESS`, `S3_SECRET`, `S3_BUCKET`, `S3_URL`, `AWS_REGION`: S3 storage provider.
        let proof_market_address = Address::from_hex(proof_market_address).unwrap();
        let set_verifier_address = Address::from_hex(set_verifier_address).unwrap();
        let pk = PrivateKeySigner::from_str(&requestor_private_key).unwrap();
        let client =
            BoundlessClient::from_parts(pk, rpc_url, proof_market_address, set_verifier_address)
                .await;

        let image_id = compute_image_id(elf).unwrap();

        tracing::trace!("Calculated image id: {:?}", image_id.as_words());

        let image_url = client.upload_img(elf.to_vec());
        tracing::info!("Uploaded image to {}", image_url);

        Self {
            elf,
            env: Default::default(),
            image_id,
            image_url,
            client,
            last_input_url: None,
            ledger_db,
            proof_market_address,
            set_verifier_address,
        }
    }

    fn upload_input_to_boundless(&mut self, input: &[u8]) {
        let client = self.client.clone();

        // Retry backoff
        let input_url = client.upload_input(input.to_vec());
        tracing::info!("Uploaded input to {}", input_url);

        self.last_input_url = Some(input_url);
    }
}

impl<'a> ZkvmHost for Risc0BoundlessHost<'a> {
    type Guest = Risc0Guest;

    fn add_hint<T: BorshSerialize>(&mut self, item: T) {
        // For running in "execute" mode.

        let buf = borsh::to_vec(&item).expect("Risc0 hint serialization is infallible");

        // write buf
        self.env.extend_from_slice(&buf);
        info!("Added hint to guest with size {}", buf.len());

        self.upload_input_to_boundless(&buf);
    }

    fn simulate_with_hints(&mut self) -> Self::Guest {
        Risc0Guest::with_hints(std::mem::take(&mut self.env))
    }

    fn run(&mut self, with_proof: bool) -> Result<Proof, anyhow::Error> {
        if !with_proof {
            let env = sov_risc0_adapter::host::add_benchmarking_callbacks(ExecutorEnv::builder())
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
            let input_url = self
                .last_input_url
                .clone()
                .take()
                .ok_or(anyhow!("No input URL"))?;
            // Dry run the ECHO ELF with the input to get the journal and cycle count.
            // This can be useful to estimate the cost of the proving request.
            // It can also be useful to ensure the guest can be executed correctly and we do not send into
            // the market unprovable proving requests. If you have a different mechanism to get the expected
            // journal and set a price, you can skip this step.
            let env = ExecutorEnv::builder().write_slice(&self.env).build()?;
            let session_info = default_executor().execute(env, self.elf)?;
            let mcycles_count = session_info
                .segments
                .iter()
                .map(|segment| 1 << segment.po2)
                .sum::<u64>()
                .div_ceil(1_000_000);
            let journal = session_info.journal;

            // Create a proving request with the image, input, requirements and offer.
            // The ELF (i.e. image) is specified by the image URL.
            // The input can be specified by a URL, as in this example, or can be posted on chain by using
            // the `with_inline` method with the input bytes.
            // The requirements are the IMAGE_ID and the digest of the journal. In this way, the market can
            // verify that the proof is correct by checking both the committed image id and digest of the
            // journal. The offer specifies the price range and the timeout for the request.
            // Additionally, the offer can also specify:
            // - the bidding start time: the block number when the bidding starts;
            // - the ramp up period: the number of blocks before the price start increasing until reaches
            //   the maxPrice, starting from the the bidding start;
            // - the lockin price: the price at which the request can be locked in by a prover, if the
            //   request is not fulfilled before the timeout, the prover can be slashed.
            let request = ProvingRequest::default()
                .with_image_url(&self.image_url)
                .with_input(Input::url(input_url))
                .with_requirements(Requirements::new(
                    self.image_id,
                    Predicate::digest_match(journal.digest()),
                ))
                .with_offer(
                    Offer::default()
                        // The market uses a reverse Dutch auction mechanism to match requests with provers.
                        // Each request has a price range that a prover can bid on. One way to set the price
                        // is to choose a desired (min and max) price per million cycles and multiply it
                        // by the number of cycles. Alternatively, you can use the `with_min_price` and
                        // `with_max_price` methods to set the price directly.
                        // TODO: Work on pricing
                        .with_min_price_per_mcycle(
                            U96::from::<u128>(parse_ether("0.0001")?.try_into()?),
                            mcycles_count,
                        )
                        // NOTE: If your offer is not being accepted, try increasing the max price.
                        .with_max_price_per_mcycle(
                            U96::from::<u128>(parse_ether("0.002")?.try_into()?),
                            mcycles_count,
                        )
                        // The timeout is the maximum number of blocks the request can stay
                        // unfulfilled in the market before it expires. If a prover locks in
                        // the request and does not fulfill it before the timeout, the prover can be
                        // slashed.
                        .with_timeout(2000),
                );
            // Send the request and wait for it to be completed.
            let request_id = self.client.submit_request(request);
            tracing::info!("Request {} submitted", request_id);

            // Wait for the request to be fulfilled by the market. The market will return the journal and
            // seal.
            tracing::info!("Waiting for request {} to be fulfilled", request_id);
            let (journal, seal) = match self.client.wait_for_request_fulfillment(
                request_id,
                Duration::from_secs(5), // check every 5 seconds
                None,                   // no timeout
            ) {
                Ok((journal, seal)) => {
                    tracing::info!("Request {} fulfilled", request_id);
                    (journal, seal)
                }
                Err(e) => {
                    tracing::error!("Request {} failed: {:?}", request_id, e);
                    // Slash operator and retry
                    // TODO: Handle error
                    let _ = self.client.slash(request_id);
                    // TODO: Retry mechanism, maybe a retry trait with:
                    // - max retries
                    // - backoff strategy
                    // - retry condition : sp1, risc0bonsai, risc0 boundless, risc0 local, sp1 local everything will have different retry conditions, for every host we will have a retry condition
                    // - retry action : sp1, risc0bonsai, risc0 boundless, risc0 local, sp1 local everything will have different retry actions, for every host we will have a retry action
                    // - retry error    : sp1, risc0bonsai, risc0 boundless, risc0 local, sp1 local everything will have different retry errors, for every host we will have a retry error
                    return Err(anyhow!("Request {} failed: {:?}", request_id, e));
                }
            };

            let claim = ReceiptClaim::ok(self.image_id, journal.clone().to_vec());

            let inner = InnerReceipt::Groth16(Groth16Receipt::new(
                seal.clone().to_vec(),
                MaybePruned::Value(claim),
                risc0_zkvm::Groth16ReceiptVerifierParameters::default().digest(),
            ));

            let full_snark_receipt = Receipt::new(inner, journal.to_vec());

            tracing::info!("Full snark proof!: {full_snark_receipt:?}");

            let full_serialized_snark_receipt = bincode::serialize(&full_snark_receipt)?;

            Ok(Proof::Full(full_serialized_snark_receipt))
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

    fn recover_proving_sessions(&self) -> Result<Vec<Proof>, anyhow::Error> {
        unimplemented!()
    }
}

impl<'host> Zkvm for Risc0BoundlessHost<'host> {
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
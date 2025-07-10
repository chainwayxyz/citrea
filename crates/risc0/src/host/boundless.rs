use std::cmp;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use boundless_market::alloy::primitives::U256;
use boundless_market::client::{Client, ClientBuilder, ClientError};
use boundless_market::contracts::{Offer, Predicate, Requirements};
use boundless_market::request_builder::RequestParams;
use boundless_market::GuestEnv;
use citrea_common::utils::current_timestamp_as_secs;
use citrea_common::FromEnv;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    compute_image_id, default_executor, AssumptionReceipt, Digest, ExecutorEnvBuilder,
    Groth16Receipt, InnerReceipt, Journal, MaybePruned, Receipt, ReceiptClaim,
};
use sov_db::ledger_db::{BoundlessLedgerOps, LedgerDB};
use sov_db::schema::types::BoundlessSession;
use sov_rollup_interface::zk::{ProofWithJob, ReceiptType};
use tokio::sync::oneshot;
use tracing::Instrument;
use url::Url;
use uuid::Uuid;

use super::config::{get_boundless_builtin_storage_provider, BoundlessConfig};
use crate::host::pricing_service::{PriceResponse, PricingService};

#[derive(Clone)]
pub struct BoundlessProver {
    pub client: Client,
    pub ledger_db: LedgerDB,
    pub pricing_service: PricingService,
}

impl BoundlessProver {
    pub async fn new(ledger_db: LedgerDB) -> Self {
        assert!(
            std::env::var("RISC0_PROVER").is_ok_and(|prover| prover == "boundless"),
            "RISC0_PROVER must be explicitly set to boundless"
        );
        let client = Self::boundless_client()
            .await
            .expect("Failed to create boundless client");

        assert!(
            client.storage_provider.is_some(),
            "a storage provider is required to upload the zkVM guest ELF"
        );
        Self {
            client,
            ledger_db,
            pricing_service: PricingService::new(),
        }
    }

    async fn boundless_client() -> anyhow::Result<Client> {
        let config = BoundlessConfig::from_env().expect("Failed to load boundless config");

        // If in dev mode, uses a temporary file as storage provider
        // Otherwise first tries to parse pinata env variables
        // If fails then tries to parse s3 env variables
        // If the environment variable `RISC0_DEV_MODE` is set, a temporary file storage provider is used.
        // Otherwise, the following environment variables are checked in order:
        // - `PINATA_JWT`, `PINATA_API_URL`, `IPFS_GATEWAY_URL`: Pinata storage provider;
        // - `S3_ACCESS`, `S3_SECRET`, `S3_BUCKET`, `S3_URL`, `AWS_REGION`: S3 storage provider.
        let storage_provider = get_boundless_builtin_storage_provider().await?;

        // Create a Boundless client from the provided parameters.
        ClientBuilder::new()
            .with_deployment(config.deployment)
            .with_rpc_url(config.rpc_url)
            .with_storage_provider(Some(storage_provider))
            .with_private_key(config.wallet_private_key)
            .build()
            .await
    }

    pub async fn prove(
        &self,
        job_id: Uuid,
        elf: Vec<u8>,
        input: Vec<u8>,
        assumptions: Vec<AssumptionReceipt>,
        receipt_type: ReceiptType,
    ) -> anyhow::Result<oneshot::Receiver<ProofWithJob>> {
        // Upload image id
        let image_id = compute_image_id(&elf).expect("Invalid elf program");

        assert!(!risc0_zkvm::is_dev_mode(), "Boundless should not be run with dev mode as provers do not accept fake receipt requests" );

        assert!(
            matches!(receipt_type, ReceiptType::Groth16),
            "Currently, only Groth16 receipts are supported for boundless"
        );

        // Upload the program(elf) to the boundless storage provider
        let image_url = self.client.upload_program(&elf).await?;
        tracing::info!("Image URL: {}", image_url);

        let guest_env = GuestEnv::from_stdin(input.clone())
            .encode()
            .context("Failed to encode input for boundless proving")?;

        // Upload input
        let input_url = self.client.upload_input(&guest_env).await?;
        tracing::info!("Uploaded input to {}", input_url);

        // move non-Send logic to blocking thread
        // I had to do this because the executor env builder is not Send
        let (journal, mcycles_count) = tokio::task::spawn_blocking({
            let elf = elf.clone(); // clone since we move into thread
            let input = input.clone();
            let assumptions = assumptions.clone();

            move || -> anyhow::Result<(Journal, u64)> {
                let mut env = ExecutorEnvBuilder::default();
                for assumption in assumptions {
                    env.add_assumption(assumption);
                }
                let env = env.write_slice(&input).build()?;

                let session_info = default_executor().execute(env, &elf)?;

                let total_cycles_approx = session_info
                    .segments
                    .iter()
                    .map(|segment| 1 << segment.po2)
                    .sum::<u64>();
                let mcycles_count = total_cycles_approx.div_ceil(1_000_000);
                tracing::info!(
                    "Boundless proving session with job id: {} takes {} cycles",
                    job_id,
                    total_cycles_approx
                );

                Ok((session_info.journal, mcycles_count))
            }
        })
        .await??;

        let PriceResponse {
            min_price,
            max_price,
            lock_timeout,
            max_possible_price,
        } = self.pricing_service.get_price(mcycles_count).await?;

        let request = self.build_proof_request(
            image_id,
            journal.digest(),
            image_url,
            input_url,
            U256::from(cmp::min(min_price, max_possible_price)),
            U256::from(cmp::min(max_price, max_possible_price)),
            mcycles_count,
            lock_timeout,
        );

        // Start boundless proving session
        let (req_id, request_expiry) = self
            .send_request(request, job_id, image_id, receipt_type, mcycles_count)
            .await?;

        let rx = self.spawn_handler(
            job_id,
            receipt_type,
            req_id,
            image_id,
            request_expiry,
            mcycles_count,
        );

        Ok(rx)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_proof_request(
        &self,
        image_id: Digest,
        journal_digest: Digest,
        image_url: Url,
        input_url: Url,
        min_price_per_mcycle: U256,
        max_price_per_mcycle: U256,
        mcycles_count: u64,
        lock_timeout: u64,
    ) -> RequestParams {
        self.client
            .new_request()
            .with_program_url(image_url)
            .unwrap()
            .with_input_url(input_url)
            .unwrap()
            .with_requirements(
                Requirements::new(image_id, Predicate::digest_match(journal_digest))
                    .with_groth16_proof(),
            )
            .with_offer(
                Offer::default()
                    .with_min_price_per_mcycle(min_price_per_mcycle, mcycles_count)
                    .with_max_price_per_mcycle(max_price_per_mcycle, mcycles_count)
                    .with_timeout((lock_timeout * 2) as u32) // The offer should be taken in 24 hours
                    .with_lock_timeout(lock_timeout as u32) // The proof should be generated in 12 hours
                    .with_ramp_up_period(300)
                    .with_bidding_start(current_timestamp_as_secs() + 10)
                    // https://github.com/boundless-xyz/boundless/blob/628af072d8ed67a7503e112c8dc09e0d4665f711/documentation/site/pages/developers/tutorials/request.mdx?plain=1#L305
                    // https://github.com/boundless-xyz/boundless/blob/628af072d8ed67a7503e112c8dc09e0d4665f711/documentation/site/pages/developers/tutorials/request.mdx?plain=1#L347C16-L347C35
                    .with_lock_stake(U256::from(5000000000000000000u64)),
            )
    }

    async fn send_request(
        &self,
        request: RequestParams,
        job_id: Uuid,
        image_id: Digest,
        receipt_type: ReceiptType,
        mcycles_count: u64,
    ) -> anyhow::Result<(String, u64)> {
        // Start boundless proving session
        tracing::info!(
            "Submitting boundless proving session request, job_id={} image_id={} with offer: {:?}",
            job_id,
            image_id,
            request.offer
        );
        let (req_id, request_expiry) = match self.client.offchain_client {
            Some(_) => {
                let (req_id, exp) = self.client.submit_offchain(request).await?;
                tracing::info!("Request submitted to offchain boundless service");
                (req_id.to_string(), exp)
            }
            None => {
                let (req_id, exp) = self.client.submit_onchain(request).await?;
                tracing::info!("Request submitted to onchain boundless service");
                (req_id.to_string(), exp)
            }
        };

        tracing::info!(
            "Started boundless proving session, job_id={} request_id={}",
            job_id,
            req_id
        );

        let db_session = BoundlessSession {
            request_id: req_id.clone(),
            request_expiry,
            image_id: image_id.into(),
            receipt_type,
            mcycles_count,
        };
        self.ledger_db
            .upsert_pending_boundless_session(job_id, db_session)
            .context("Failed to upsert boundless session")?;

        Ok((req_id.to_string(), request_expiry))
    }

    fn spawn_handler(
        &self,
        job_id: Uuid,
        receipt_type: ReceiptType,
        request_id: String,
        image_id: Digest,
        request_expiry: u64,
        mcycles_count: u64,
    ) -> oneshot::Receiver<ProofWithJob> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();
        let request_id_span = request_id.clone();
        tokio::spawn(async move {
            let mut request_id = request_id.clone();
            let mut request_expiry = request_expiry;
            loop {
                match this
                    .handle_session(request_id.clone(), image_id, request_expiry)
                    .await
                {
                    Ok(receipt) => {
                        let serialized_receipt = bincode::serialize(&receipt.inner)
                            .expect("Receipt serialization cannot fail");

                        let Ok(_) = tx.send(ProofWithJob {
                            job_id,
                            proof: serialized_receipt,
                        }) else {
                            tracing::error!("Boundless proof receiver channel is closed");
                            return;
                        };

                        if let Err(e) = this.ledger_db.remove_pending_boundless_session(job_id) {
                            tracing::error!(
                                "Failed to remove pending boundless session job: {} err={}",
                                job_id,
                                e
                            );
                        }
                        tracing::info!(
                            "Boundless proving job finished: {} | Boundless request id: {}",
                            job_id,
                            request_id
                        );
                        break;
                    }
                    Err(e) => {
                        tracing::error!(
                    "Failed to handle Boundless proving session job: {} | Boundless request id: {} | err={}",
                    job_id, request_id, e
                );
                        match this.handle_resubmit_on_failed_request(
                            job_id,
                            &mut request_id,
                            &mut request_expiry,
                            mcycles_count,
                            image_id,
                            receipt_type,
                        )
                        .await
                        {
                            Ok(_) => {
                                tracing::info!(
                                    "Resubmitted boundless proving session job: {} | Boundless request id: {}",
                                    job_id,
                                    request_id
                                );

                                continue;
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to resubmit boundless proving session job: {} | Boundless request id: {} | err={}",
                                    job_id,
                                    request_id,
                                    e
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }.instrument(
            tracing::info_span!(
                "BoundlessProver::spawn_handler",
                job_id = %job_id,
                request_id = %request_id_span,
                image_id = %image_id,
            ),
        ));

        rx
    }

    async fn handle_resubmit_on_failed_request(
        &self,
        job_id: Uuid,
        request_id: &mut String,
        request_expiry: &mut u64,
        mcycles_count: u64,
        image_id: Digest,
        receipt_type: ReceiptType,
    ) -> anyhow::Result<()> {
        // Remove failed job from pending boundless sessions
        self.ledger_db
            .remove_pending_boundless_session(job_id)
            .expect("Failed to remove pending boundless session on error");

        // TODO: https://github.com/chainwayxyz/citrea/issues/2418

        // Get data of failed order
        let Ok(failed_order) = self
            .client
            .fetch_order(
                U256::from_str(request_id).expect("Should convert str to u256"),
                None,
                None,
            )
            .await
        else {
            tracing::error!(
                "Failed to fetch failed order for job: {} request_id: {}",
                job_id,
                request_id
            );
            return Ok(());
        };

        // TODO: https://github.com/chainwayxyz/citrea/issues/2417
        // Define new request with updated parameters
        let new_min_price_per_mcycle = failed_order
            .request
            .offer
            .minPrice
            .div_ceil(U256::from(mcycles_count))
            .wrapping_mul(U256::from(15))
            .div_ceil(U256::from(10));

        let new_max_price_per_mcycle = failed_order
            .request
            .offer
            .maxPrice
            .div_ceil(U256::from(mcycles_count))
            .wrapping_mul(U256::from(2));

        let new_lock_timeout = failed_order.request.offer.lockTimeout.wrapping_mul(2);

        let new_request = self.build_proof_request(
            image_id,
            failed_order
                .request
                .requirements
                .predicate
                .data
                .to_vec()
                .try_into()
                .unwrap(),
            Url::parse(&failed_order.request.imageUrl).expect("Invalid image URL"),
            Url::parse(
                core::str::from_utf8(&failed_order.request.input.data).expect("Invalid input URL"),
            )
            .expect("Invalid input URL"),
            new_min_price_per_mcycle,
            new_max_price_per_mcycle,
            mcycles_count,
            new_lock_timeout as u64,
        );
        // Update request_id and request_expiry for the next iteration

        // Resubmit the request with updated parameters
        let Ok((new_req_id, new_exp_time)) = self
            .send_request(new_request, job_id, image_id, receipt_type, mcycles_count)
            .await
        else {
            tracing::error!(
                "Failed to resubmit boundless proving session retrying, job_id={} request_id={}",
                job_id,
                request_id
            );
            return Ok(());
        };

        *request_id = new_req_id;
        *request_expiry = new_exp_time;

        tracing::info!(
            "Resubmitted previously failing boundless proving session, job_id={} request_id={}, new min_price_per_mcycle={:?}, new max_price_per_mcycle={:?}, new lock_timeout={}",
            job_id,
            request_id,
            new_min_price_per_mcycle,
            new_max_price_per_mcycle,
            new_lock_timeout
        );
        Ok(())
    }

    async fn handle_session(
        &self,
        request_id: String,
        image_id: Digest,
        request_expiry: u64,
    ) -> Result<Receipt, ClientError> {
        let (journal, seal) = self
            .client
            .wait_for_request_fulfillment(
                U256::from_str(&request_id).unwrap(),
                Duration::from_secs(5),
                request_expiry,
            )
            .await?;

        let claim = ReceiptClaim::ok(image_id, journal.clone().to_vec());

        // The first 4 bytes of the seal are reserved for metadata; the actual data starts at index 4.
        const SEAL_DATA_OFFSET: usize = 4;
        let inner = InnerReceipt::Groth16(Groth16Receipt::new(
            seal.clone().0.to_vec()[SEAL_DATA_OFFSET..].to_vec(),
            MaybePruned::Value(claim),
            risc0_zkvm::Groth16ReceiptVerifierParameters::default().digest(),
        ));
        let full_snark_receipt = Receipt::new(inner, journal.to_vec());
        full_snark_receipt.verify(image_id).unwrap();

        Ok(full_snark_receipt)
    }

    // Starts the recovery of proving jobs from db by starting a background task, returning list of
    /// receiver channels that return the associated job id and proof result on finish.
    pub fn start_recovery(&self) -> anyhow::Result<Vec<oneshot::Receiver<ProofWithJob>>> {
        let sessions = self.ledger_db.get_pending_boundless_sessions()?;
        if sessions.is_empty() {
            return Ok(vec![]);
        }

        let mut rxs = vec![];
        for (job_id, session) in sessions {
            tracing::info!(
                "Recovering boundless session, job_id={} session={:?}",
                job_id,
                session
            );

            let rx = self.spawn_handler(
                job_id,
                session.receipt_type,
                session.request_id,
                session.image_id.into(),
                session.request_expiry,
                session.mcycles_count,
            );
            rxs.push(rx);
        }
        Ok(rxs)
    }
}

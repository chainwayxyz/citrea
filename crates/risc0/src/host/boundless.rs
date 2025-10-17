use std::cmp;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoff;
use boundless_market::alloy::primitives::U256;
use boundless_market::client::{Client, ClientBuilder, ClientError};
use boundless_market::contracts::boundless_market::MarketError;
use boundless_market::contracts::{Offer, Predicate, Requirements};
use boundless_market::request_builder::{RequestParams, RequirementParams};
use boundless_market::storage::{PinataStorageProvider, S3StorageProvider};
use boundless_market::{GuestEnv, StandardStorageProvider};
use metrics::gauge;
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

use super::config::{BoundlessProverConfig, BoundlessStorageConfig};
use crate::host::pricing_service::{PriceResponse, PricingService};
use crate::is_dev_mode_enabled_via_environment;

/// Using 200 seconds here as this is a decentralized market and we want to give enough time for provers to pick up the job.
const MIN_LOCK_TIMEOUT: u64 = 200; // seconds

/// If a proof was not picked up by any prover within lock timeout, we increase the max price by 2x
const MAX_PRICE_INCREASE_RATIO: u32 = 2; // 2x

/// The total timeout must be greater than lock timeout, currently it is 2x of lock timeout
const TIMEOUT_IS_N_LOCK_TIMEOUT: u64 = 2; // Total timeout is 2x of lock timeout

/// We also ensure that the min price increases by at least 1.5x
const MIN_PRICE_INCREASE_MULTIPLIER: u32 = 15; // 1.5x
const MIN_PRICE_INCREASE_DIVISOR: u32 = 10;

/// If a proof was picked up by a prover but not delivered within lock timeout, we increase the timeout by 2x
const LOCKTIME_INCREASE_RATIO: u32 = 2; // 2x

enum ResubmitResult {
    Retry,
    Success,
}

#[derive(Clone)]
pub struct BoundlessProver {
    pub client: Client,
    pub ledger_db: LedgerDB,
    pub pricing_service: PricingService,
    config: BoundlessProverConfig,
}

impl BoundlessProver {
    pub async fn new(ledger_db: LedgerDB, prover_config: BoundlessProverConfig) -> Self {
        let client = Self::boundless_client(prover_config.clone())
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
            config: prover_config,
        }
    }

    async fn boundless_client(prover_config: BoundlessProverConfig) -> anyhow::Result<Client> {
        let config = &prover_config.boundless;

        // Get storage provider from config
        let storage_provider = match prover_config.storage {
            BoundlessStorageConfig::S3(s3_config) => {
                StandardStorageProvider::S3(S3StorageProvider::from_parts(
                    s3_config.s3_access_key,
                    s3_config.s3_secret_key,
                    s3_config.s3_bucket,
                    s3_config.s3_url,
                    s3_config.aws_region,
                    s3_config.s3_use_presigned,
                ))
            }
            BoundlessStorageConfig::Pinata(pinata_config) => StandardStorageProvider::Pinata(
                PinataStorageProvider::from_parts(
                    pinata_config.pinata_jwt,
                    pinata_config.pinata_api_url.to_string(),
                    pinata_config.ipfs_gateway_url.to_string(),
                )
                .await?,
            ),
        };

        // Create a Boundless client from the provided parameters.
        ClientBuilder::new()
            .with_deployment(config.deployment.clone())
            .with_rpc_url(config.rpc_url.clone())
            .with_storage_provider(Some(storage_provider))
            .with_private_key(config.wallet_private_key.clone())
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

        assert!(
            !is_dev_mode_enabled_via_environment(),
            "RISC0_DEV_MODE should not be set for boundless"
        );

        assert!(
            matches!(receipt_type, ReceiptType::Groth16),
            "Currently, only Groth16 receipts are supported for boundless"
        );

        let BoundlessStorageConfig::S3(s3_config) = &self.config.storage else {
            anyhow::bail!("Boundless prover only supports s3 provider for now");
        };

        let s3_url = s3_config.s3_url.clone();

        let s3_use_presigned = s3_config.s3_use_presigned;

        // Upload the program(elf) to the boundless storage provider
        let mut image_url = self.client.upload_program(&elf).await?;
        tracing::info!("Image URL: {}", image_url);

        // If we are not using presigned:
        if !s3_use_presigned {
            let image_url_string = image_url.as_str().to_string();
            let s3_path = image_url_string
                .strip_prefix("s3://")
                .unwrap_or(&image_url_string);
            image_url = Url::parse(&format!("{s3_url}{s3_path}"))?;
            tracing::info!("Downloadable Image URL: {}", image_url);
        }

        let guest_env = GuestEnv::from_stdin(input.clone())
            .encode()
            .context("Failed to encode input for boundless proving")?;

        // Upload input
        let mut input_url = self.client.upload_input(&guest_env).await?;
        tracing::info!("Uploaded input to {}", input_url);

        // If we are not using presigned:
        if !s3_use_presigned {
            let input_url_string = input_url.as_str().to_string();
            let s3_path = input_url_string
                .strip_prefix("s3://")
                .unwrap_or(&input_url_string);
            input_url = Url::parse(&format!("{s3_url}{s3_path}"))?;
            tracing::info!("Downloadable Input URL: {}", input_url);
        }

        // move non-Send logic to blocking thread
        // I had to do this because the executor env builder is not Send
        let (journal, mcycles_count, total_cycles_approx) = tokio::task::spawn_blocking({
            let elf = elf.clone(); // clone since we move into thread
            let input = input.clone();
            let assumptions = assumptions.clone();

            move || -> anyhow::Result<(Journal, u64, u64)> {
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
                    "Boundless proving session with job id: {job_id} takes {total_cycles_approx} cycles"
                );

                Ok((session_info.journal, mcycles_count, total_cycles_approx))
            }
        })
        .await??;

        gauge!("proving_session_cycle_count").set(total_cycles_approx as f64);

        let exponential_backoff = ExponentialBackoff::default();
        let PriceResponse {
            min_price,
            max_price,
            lock_timeout,
            max_possible_price,
            lock_stake,
            ramp_up_period,
            timeout,
            bidding_start,
            ..
        } = retry_backoff(exponential_backoff, || async move {
            self.pricing_service
                .get_price(mcycles_count.saturating_mul(1_000_000))
                .await
                .map_err(backoff::Error::transient)
        })
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to get price from pricing service for job: {}  | err={}",
                job_id,
                e
            )
        })?;

        let lock_timeout = cmp::max(lock_timeout, MIN_LOCK_TIMEOUT); // at least 200 seconds

        let request = self.build_proof_request(
            image_id,
            journal.digest(),
            image_url,
            input_url,
            U256::from(cmp::min(min_price, max_possible_price)),
            U256::from(cmp::min(max_price, max_possible_price)),
            mcycles_count,
            lock_timeout,
            timeout,
            ramp_up_period,
            lock_stake,
            bidding_start,
            Some(total_cycles_approx),
            Some(journal),
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
        timeout: u64,
        ramp_up_period: u64,
        lock_stake: u64,
        bidding_start: u64,
        total_cycles_approx: Option<u64>,
        journal: Option<Journal>,
    ) -> RequestParams {
        // Note that offer ramp up period must be less than or equal to the lock timeout)
        let mut request_params =
            self.client
                .new_request()
                .with_program_url(image_url)
                .unwrap()
                .with_input_url(input_url)
                .unwrap()
                .with_requirements(
                    TryInto::<RequirementParams>::try_into(Requirements::new(
                        Predicate::digest_match(image_id, journal_digest),
                    ))
                    .expect("TODO: handle error"),
                )
                .with_groth16_proof()
                .with_offer(
                    Offer::default()
                        .with_min_price_per_mcycle(min_price_per_mcycle, mcycles_count)
                        .with_max_price_per_mcycle(max_price_per_mcycle, mcycles_count)
                        .with_lock_timeout(lock_timeout as u32)
                        .with_timeout(timeout as u32)
                        .with_ramp_up_period(ramp_up_period as u32)
                        .with_lock_collateral(U256::from(lock_stake))
                        .with_ramp_up_start(bidding_start),
                );

        // If we can provide these then in the preflight layer of request sending there won't be a double execution of the program
        if let Some(total_cycles_approx) = total_cycles_approx {
            request_params = request_params.with_cycles(total_cycles_approx);
        }
        if let Some(journal) = journal {
            request_params = request_params.with_journal(journal);
        }
        request_params
    }

    async fn send_request(
        &self,
        request: RequestParams,
        job_id: Uuid,
        image_id: Digest,
        receipt_type: ReceiptType,
        mcycles_count: u64,
    ) -> Result<(String, u64), ClientError> {
        // Start boundless proving session
        tracing::info!(
            "Submitting boundless proving session request, job_id={} image_id={} with offer: {:?}",
            job_id,
            image_id,
            request.offer
        );
        let (req_id, request_expiry) = match self.client.offchain_client {
            Some(_) => {
                tracing::info!("Sending request using offchain boundless service");
                let (req_id, exp) = self.client.submit_offchain(request).await?;
                tracing::info!("Request submitted to offchain boundless service");
                (format!("0x{req_id:x}"), exp)
            }
            None => {
                tracing::info!("Sending request onchain to boundless network");
                let (req_id, exp) = self.client.submit_onchain(request).await?;
                tracing::info!("Request submitted to onchain boundless service");
                (format!("0x{req_id:x}"), exp)
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
                        if !matches!(e, ClientError::MarketError(MarketError::RequestHasExpired(_))) {
                            // Only resubmit if the request has expired.
                            // Other possible errors include network errors, or
                            // MarketError::ProofNotFound, which we should not get?
                            continue;
                        }
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
                            Ok(res) => {
                                if matches!(res, ResubmitResult::Success) {
                                    tracing::info!(
                                    "Resubmitted boundless proving session job: {} | Boundless request id: {}",
                                    job_id,
                                    request_id
                                );
                            }
                                tracing::info!(
                                    "Resubmit boundless proving session Failed with job id: {}, and boundless request id: {} retrying...",
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
    ) -> anyhow::Result<ResubmitResult> {
        // Remove failed job from pending boundless sessions
        self.ledger_db
            .remove_pending_boundless_session(job_id)
            .expect("Failed to remove pending boundless session on error");

        // Get data of failed order
        // Queries first offchain, and then onchain.
        let Ok((failed_request, _signature)) = self
            .client
            .fetch_proof_request(
                U256::from_str(request_id).expect("Should convert str to U256"),
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
            return Ok(ResubmitResult::Retry);
        };

        // Retrieve the maximum possible price again from the pricing service as the price of ether may have changed.
        let exponential_backoff = ExponentialBackoff::default();

        let price_response = retry_backoff(exponential_backoff, || async move {
            match self
                .pricing_service
                .get_price(mcycles_count.saturating_mul(1_000_000))
                .await
            {
                Err(e) => {
                    tracing::error!(
                        "Failed to get price from pricing service for job: {}  | err={}",
                        job_id,
                        e
                    );
                    Err(backoff::Error::transient(e))
                }
                Ok(res) => Ok(res),
            }
        })
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to get price from pricing service for job: {} request_id: {} | err={}",
                job_id,
                request_id,
                e
            )
        })?;
        let max_possible_price = price_response.max_possible_price;
        let lock_stake = price_response.lock_stake;

        // TODO: https://github.com/chainwayxyz/citrea/issues/2417
        // Define new request with updated parameters
        let (new_min_price_per_mcycle, new_max_price_per_mcycle, new_lock_timeout) = {
            let is_locked = match self
                .client
                .boundless_market
                .is_locked(U256::from_str(request_id).unwrap())
                .await
            {
                Ok(locked) => locked,
                Err(e) => {
                    tracing::error!(
                        "Failed to check if request is locked for job: {} request_id: {} | err={}",
                        job_id,
                        request_id,
                        e
                    );
                    return Ok(ResubmitResult::Retry);
                }
            };
            // Get old parameters from the failed order
            let min_price_per_mcycle = failed_request
                .offer
                .minPrice
                .div_ceil(U256::from(mcycles_count));
            let max_price_per_mcycle = failed_request
                .offer
                .maxPrice
                .div_ceil(U256::from(mcycles_count));
            let lock_timeout = failed_request.offer.lockTimeout;

            if is_locked {
                // If locked, that means a prover worked on the request but failed to deliver it on time.
                // Increase the lock timeout.
                let lock_timeout = lock_timeout.saturating_mul(LOCKTIME_INCREASE_RATIO);
                (min_price_per_mcycle, max_price_per_mcycle, lock_timeout)
            } else {
                // If not locked, that means the request was never taken by a prover.
                // Increase the min and max price per mcycle.
                let min_price_per_mcycle = min_price_per_mcycle
                    .saturating_mul(U256::from(MIN_PRICE_INCREASE_MULTIPLIER))
                    .div_ceil(U256::from(MIN_PRICE_INCREASE_DIVISOR))
                    .min(U256::from(max_possible_price));
                let max_price_per_mcycle = max_price_per_mcycle
                    .saturating_mul(U256::from(MAX_PRICE_INCREASE_RATIO))
                    .min(U256::from(max_possible_price));
                (min_price_per_mcycle, max_price_per_mcycle, lock_timeout)
            }
        };

        let new_request = self.build_proof_request(
            image_id,
            // this now has image id and digest
            // first 32 bytes is image id
            // second 32 bytes is digest
            failed_request.requirements.predicate.data.to_vec()[32..]
                .try_into()
                .unwrap(),
            Url::parse(&failed_request.imageUrl).expect("Invalid image URL"),
            Url::parse(
                core::str::from_utf8(&failed_request.input.data).expect("Invalid input URL"),
            )
            .expect("Invalid input URL"),
            new_min_price_per_mcycle,
            new_max_price_per_mcycle,
            mcycles_count,
            new_lock_timeout as u64,
            new_lock_timeout as u64 * TIMEOUT_IS_N_LOCK_TIMEOUT,
            failed_request.offer.rampUpPeriod as u64,
            lock_stake,
            price_response.bidding_start,
            // TODO: https://github.com/chainwayxyz/citrea/issues/2820
            None,
            None,
        );

        let (new_req_id, new_exp_time) = match self
            .send_request(new_request, job_id, image_id, receipt_type, mcycles_count)
            .await
        {
            Ok((req_id, exp_time)) => (req_id, exp_time),
            Err(e) => {
                tracing::error!(
                    "Failed to resubmit boundless proving session retrying, job_id={} request_id={} | err={}",
                    job_id,
                    request_id,
                    e
                );
                return Ok(ResubmitResult::Retry);
            }
        };

        // Update request_id and request_expiry for the next iteration
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
        Ok(ResubmitResult::Success)
    }

    async fn handle_session(
        &self,
        request_id: String,
        image_id: Digest,
        request_expiry: u64,
    ) -> Result<Receipt, ClientError> {
        let fulfilled_request = self
            .client
            .wait_for_request_fulfillment(
                U256::from_str(&request_id).unwrap(),
                Duration::from_secs(5),
                request_expiry,
            )
            .await?;
        let fulfillment_data = fulfilled_request.data().expect("TODO: handle error");
        let journal = fulfillment_data.journal().expect("TODO: handle error");
        let seal = fulfilled_request.seal;

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

        tracing::info!(
            "Successfully verified boundless Groth16 receipt for request_id={}",
            request_id
        );

        Ok(full_snark_receipt)
    }

    // Starts the recovery of proving jobs from db by starting a background task, returning list of
    /// receiver channels that return the associated job id and proof result on finish.
    pub fn start_recovery(&self) -> anyhow::Result<Vec<oneshot::Receiver<ProofWithJob>>> {
        let sessions = self.ledger_db.get_pending_boundless_sessions()?;
        tracing::info!(
            "Found {} pending boundless sessions to recover",
            sessions.len()
        );
        if sessions.is_empty() {
            tracing::info!("No pending boundless sessions to recover");
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

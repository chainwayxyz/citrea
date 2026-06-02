use std::cmp;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoff;
use boundless_market::alloy::primitives::{Address, U256};
use boundless_market::alloy::providers::Provider;
use boundless_market::alloy::signers::local::PrivateKeySigner;
use boundless_market::client::{Client, ClientBuilder, ClientError};
use boundless_market::contracts::boundless_market::MarketError;
use boundless_market::contracts::{Offer, Predicate, Requirements};
use boundless_market::deployments::BASE;
use boundless_market::request_builder::{
    OfferLayer, OfferLayerConfigBuilder, RequestParams, RequirementParams,
};
use boundless_market::storage::{PinataStorageProvider, S3StorageProvider};
use boundless_market::{GuestEnv, RequestId, StandardStorageProvider};
use citrea_common::config::risc0::{BoundlessProverConfig, BoundlessStorageConfig};
use citrea_common::utils::is_dev_mode_enabled_via_environment;
use metrics::gauge;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    compute_image_id, default_executor, AssumptionReceipt, Digest, ExecutorEnvBuilder,
    Groth16Receipt, InnerReceipt, Journal, MaybePruned, Receipt, ReceiptClaim,
};
use sov_rollup_interface::zk::{
    BoundlessProvingSessionInfo, ProofWithJob, ProvingSessionInfo, ReceiptType,
};
use tokio::sync::oneshot;
use tracing::Instrument;
use url::Url;
use uuid::Uuid;

use crate::host::pricing_service::{PriceResponse, PricingService};

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

/// Average gas price is less than 0.1 gwei
const FALLBACK_BASE_GAS_PRICE: u128 = 1_000_000_000; // 1 gwei

/// Duration to sleep before retrying a failed proof request in seconds
const RETRY_RESUBMISSION_DELAY_SECS: Duration = Duration::from_secs(10);

/// Per-attempt timeout for the `get_gas_price` RPC. A silent hang here would otherwise
/// prevent `backoff` from ever observing an error and retrying.
const GAS_PRICE_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-attempt timeout for the pricing service HTTP call. Same rationale: surface silent
/// hangs as errors so `backoff` can retry.
const PRICING_SERVICE_TIMEOUT: Duration = Duration::from_secs(30);

enum ResubmitResult {
    Retry,
    Success,
}

#[derive(Clone)]
pub struct BoundlessProver {
    pub client: Client,
    pub pricing_service: PricingService,
    config: BoundlessProverConfig,
}

impl BoundlessProver {
    pub async fn new(prover_config: BoundlessProverConfig) -> Self {
        let client = Self::boundless_client(prover_config.clone())
            .await
            .expect("Failed to create boundless client");

        assert!(
            client.storage_provider.is_some(),
            "a storage provider is required to upload the zkVM guest ELF"
        );

        let pricing_service = PricingService::from_config(&prover_config.pricing_service);

        Self {
            client,
            pricing_service,
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
                    pinata_config.pinata_api_url,
                    pinata_config.ipfs_gateway_url,
                )
                .await
                .context("Failed to create Pinata storage provider")?,
            ),
        };

        // TODO: Switch to Deployment::builder after boundless 1.0 release to switch between base mainnet and sepolia
        let mut deployment = BASE;
        if !config.is_offchain {
            deployment.order_stream_url = None;
        }

        let private_key = PrivateKeySigner::from_str(&config.wallet_private_key)
            .context("Failed to parse wallet private key")?;

        let rpc_url = Url::parse(&config.rpc_url).context("Invalid boundless RPC URL")?;
        // Create a Boundless client from the provided parameters.
        ClientBuilder::new()
            .with_deployment(deployment)
            .with_rpc_url(rpc_url)
            .with_storage_provider(Some(storage_provider))
            .with_private_key(private_key)
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
        let (journal, receipt_claim, total_cycles_approx,) = tokio::task::spawn_blocking({
            let elf = elf.clone(); // clone since we move into thread
            let input = input.clone();
            let assumptions = assumptions.clone();

            move || -> anyhow::Result<(Journal, ReceiptClaim, u64)> {
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
                tracing::info!(
                    "Boundless proving session with job id: {job_id} takes {total_cycles_approx} cycles"
                );

                Ok((session_info.journal, session_info.receipt_claim.expect("should exist"), total_cycles_approx))
            }
        })
        .await??;

        gauge!("proving_session_cycle_count").set(total_cycles_approx as f64);

        let exponential_backoff = ExponentialBackoff::default();
        let PriceResponse {
            min_price_wei_per_cycle,
            max_price_wei_per_cycle,
            lock_timeout,
            max_possible_price_wei_per_cycle,
            lock_stake,
            ramp_up_period,
            timeout,
            bidding_start_delay,
            ..
        } = retry_backoff(exponential_backoff, || async move {
            match tokio::time::timeout(
                PRICING_SERVICE_TIMEOUT,
                self.pricing_service.get_price(total_cycles_approx),
            )
            .await
            {
                Ok(Ok(res)) => Ok(res),
                Ok(Err(e)) => Err(backoff::Error::transient(e)),
                Err(_elapsed) => {
                    tracing::error!(
                        "pricing_service.get_price timed out after {:?}, retrying...",
                        PRICING_SERVICE_TIMEOUT
                    );
                    Err(backoff::Error::transient(anyhow::anyhow!(
                        "pricing_service.get_price timed out after {:?}",
                        PRICING_SERVICE_TIMEOUT
                    )))
                }
            }
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

        tracing::info!(
            "Got pricing response, building proof request for job_id={} image_id={} lock_timeout={}s timeout={}s",
            job_id,
            image_id,
            lock_timeout,
            timeout
        );

        let request = self
            .build_proof_request(
                receipt_claim.digest(),
                image_id,
                image_url,
                input_url,
                U256::from(cmp::min(
                    min_price_wei_per_cycle,
                    max_possible_price_wei_per_cycle,
                )),
                U256::from(cmp::min(
                    max_price_wei_per_cycle,
                    max_possible_price_wei_per_cycle,
                )),
                lock_timeout,
                timeout,
                ramp_up_period,
                lock_stake,
                bidding_start_delay,
                total_cycles_approx,
                journal.clone(),
            )
            .await;

        tracing::info!(
            "Built proof request for job_id={} image_id={}, handing off to send_request",
            job_id,
            image_id
        );

        // Start boundless proving session
        let (req_id, request_expiry) = self.send_request(request, job_id, image_id).await?;

        let rx = self.spawn_handler(
            job_id,
            req_id,
            image_id,
            journal,
            receipt_claim,
            request_expiry,
            total_cycles_approx,
        );

        Ok(rx)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn build_proof_request(
        &self,
        receipt_claim_digest: Digest,
        image_id: Digest,
        image_url: Url,
        input_url: Url,
        min_price_per_cycle: U256,
        max_price_per_cycle: U256,
        lock_timeout: u64,
        timeout: u64,
        ramp_up_period: u64,
        lock_stake: U256,
        bidding_start_delay: u64,
        total_cycles_approx: u64,
        journal: Journal,
    ) -> RequestParams {
        // Note that offer ramp up period must be less than or equal to the lock timeout)

        tracing::info!(
            "build_proof_request: entered, image_id={} total_cycles_approx={}",
            image_id,
            total_cycles_approx
        );

        let provider = self.client.provider().clone();

        tracing::info!("build_proof_request: building offer_layer_config");

        let offer_layer_config = OfferLayerConfigBuilder::default()
            .min_price_per_cycle(min_price_per_cycle)
            .max_price_per_cycle(max_price_per_cycle)
            .lock_timeout(lock_timeout as u32)
            .timeout(timeout as u32)
            .ramp_up_period(ramp_up_period as u32)
            .lock_collateral(lock_stake)
            .bidding_start_delay(bidding_start_delay)
            .build()
            .expect("Failed to build offer layer config");

        let exponential_backoff = ExponentialBackoff::default();

        tracing::info!(
            "build_proof_request: fetching gas price via provider.get_gas_price() (per-attempt timeout={:?})",
            GAS_PRICE_RPC_TIMEOUT
        );

        let gas_price = retry_backoff(exponential_backoff, || {
            let p = provider.clone();
            async move {
                match tokio::time::timeout(GAS_PRICE_RPC_TIMEOUT, p.get_gas_price()).await {
                    Ok(Ok(price)) => Ok(price),
                    Ok(Err(e)) => {
                        tracing::error!(
                            "Failed to get gas price from provider, retrying... err={}",
                            e
                        );
                        Err(backoff::Error::transient(anyhow::Error::from(e)))
                    }
                    Err(_elapsed) => {
                        tracing::error!(
                            "get_gas_price timed out after {:?}, retrying...",
                            GAS_PRICE_RPC_TIMEOUT
                        );
                        Err(backoff::Error::transient(anyhow::anyhow!(
                            "get_gas_price timed out after {:?}",
                            GAS_PRICE_RPC_TIMEOUT
                        )))
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|e| {
            tracing::error!(
                "Failed to get gas price from provider, using fallback gas price: {} wei. err={}",
                FALLBACK_BASE_GAS_PRICE,
                e
            );
            FALLBACK_BASE_GAS_PRICE
        });

        tracing::info!(
            "build_proof_request: gas_price={} wei, building OfferLayer and Requirements",
            gas_price
        );

        let offer_layer = OfferLayer::new(provider, offer_layer_config);

        let requirements = Requirements::new(Predicate::claim_digest_match(receipt_claim_digest))
            .with_groth16_proof();

        // Use a dummy request id for gas estimation. The gas cost can depend on the request id,
        // but in our case it does not, because the request is not smart contract signed.
        // We cannot use the actual request id since it is generated after the request is submitted.
        let dummy_request_id = RequestId::new(Address::new([1u8; 20]), 0);

        // Unwrap is safe here because no callbacks exist in requirements
        let gas_cost_estimate = offer_layer
            .estimate_gas_cost_upper_bound(&requirements, &dummy_request_id, gas_price)
            .unwrap();

        tracing::info!(
            "build_proof_request: gas_cost_estimate={}",
            gas_cost_estimate
        );

        let max_price_cycle = max_price_per_cycle * U256::from(total_cycles_approx);

        // https://github.com/boundless-xyz/boundless/blob/eced0f1eab1b0666ac1cd263ce815861a9558925/crates/boundless-market/src/request_builder/offer_layer.rs#L329
        // Add the estimated gas cost plus 10% to the cycle-based max price.
        let max_price =
            max_price_cycle + (gas_cost_estimate + (gas_cost_estimate / U256::from(10)));

        let min_price = min_price_per_cycle * U256::from(total_cycles_approx);

        let ts = get_timestamp();
        let bidding_start = ts + bidding_start_delay;

        tracing::info!(
            "build_proof_request: min_price={} max_price={} bidding_start={}, assembling RequestParams",
            min_price,
            max_price,
            bidding_start
        );

        let params = self
            .client
            .new_request()
            .with_image_id(image_id)
            .with_program_url(image_url)
            .unwrap()
            .with_input_url(input_url)
            .unwrap()
            .with_requirements(TryInto::<RequirementParams>::try_into(requirements).unwrap())
            .with_offer(
                Offer::default()
                    .with_min_price(min_price)
                    .with_max_price(max_price)
                    .with_lock_timeout(lock_timeout as u32)
                    .with_timeout(timeout as u32)
                    .with_ramp_up_period(ramp_up_period as u32)
                    .with_lock_collateral(lock_stake)
                    .with_ramp_up_start(bidding_start),
            )
            .with_cycles(total_cycles_approx)
            .with_journal(journal);

        tracing::info!("build_proof_request: finished assembling RequestParams");

        params
    }

    async fn send_request(
        &self,
        request: RequestParams,
        job_id: Uuid,
        image_id: Digest,
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

        Ok((req_id.to_string(), request_expiry))
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_handler(
        &self,
        job_id: Uuid,
        request_id: String,
        image_id: Digest,
        journal: Journal,
        receipt_claim: ReceiptClaim,
        request_expiry: u64,
        total_cycles_approx: u64,
    ) -> oneshot::Receiver<ProofWithJob> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();
        let request_id_span = request_id.clone();
        tokio::spawn(async move {
            let mut request_id = request_id.clone();
            let mut request_expiry = request_expiry;
            loop {
                match this
                    .handle_session(request_id.clone(), image_id, journal.clone(), receipt_claim.clone(), request_expiry)
                    .await
                {
                    Ok(receipt) => {
                        let serialized_receipt = bincode::serialize(&receipt.inner)
                            .expect("Receipt serialization cannot fail");

                        let Ok(_) = tx.send(ProofWithJob {
                            job_id,
                            proof: serialized_receipt,
                            info: ProvingSessionInfo::Boundless(BoundlessProvingSessionInfo {
                                request_id: request_id.clone(),
                                total_cycles_approx,
                            }),
                        }) else {
                            tracing::error!("Boundless proof receiver channel is closed");
                            return;
                        };

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
                            journal.clone(),
                            receipt_claim.clone(),
                            total_cycles_approx,
                            image_id,
                        )
                        .await
                        {
                            Ok(res) => {
                                match res {
                                    ResubmitResult::Retry => {
                                        tracing::info!(
                                            "Retrying resubmission of boundless proving session job: {} | Boundless request id: {} after {:?}",
                                            job_id,
                                            request_id,
                                            RETRY_RESUBMISSION_DELAY_SECS
                                        );
                                        // Retry resubmission after a delay
                                        tokio::time::sleep(RETRY_RESUBMISSION_DELAY_SECS).await;
                                    }
                                    ResubmitResult::Success => {
                                        // Successfully resubmitted, continue to next iteration to monitor new request
                                        tracing::info!(
                                            "Resubmitted boundless proving session job: {} | Boundless request id: {}",
                                            job_id,
                                            request_id
                                        );
                                    }
                                }
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

    #[allow(clippy::too_many_arguments)]
    async fn handle_resubmit_on_failed_request(
        &self,
        job_id: Uuid,
        request_id: &mut String,
        request_expiry: &mut u64,
        journal: Journal,
        receipt_claim: ReceiptClaim,
        total_cycles_approx: u64,
        image_id: Digest,
    ) -> anyhow::Result<ResubmitResult> {
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
            match tokio::time::timeout(
                PRICING_SERVICE_TIMEOUT,
                self.pricing_service.get_price(total_cycles_approx),
            )
            .await
            {
                Ok(Ok(res)) => Ok(res),
                Ok(Err(e)) => {
                    tracing::error!(
                        "Failed to get price from pricing service for job: {}  | err={}",
                        job_id,
                        e
                    );
                    Err(backoff::Error::transient(e))
                }
                Err(_elapsed) => {
                    tracing::error!(
                        "pricing_service.get_price timed out after {:?} for job: {}, retrying...",
                        PRICING_SERVICE_TIMEOUT,
                        job_id
                    );
                    Err(backoff::Error::transient(anyhow::anyhow!(
                        "pricing_service.get_price timed out after {:?}",
                        PRICING_SERVICE_TIMEOUT
                    )))
                }
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
        let max_possible_price_wei_per_cycle = price_response.max_possible_price_wei_per_cycle;
        let lock_stake = price_response.lock_stake;

        // TODO: https://github.com/chainwayxyz/citrea/issues/2417
        // Define new request with updated parameters
        let (new_min_price_per_cycle, new_max_price_per_cycle, new_lock_timeout) = {
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
            let min_price_per_cycle = failed_request
                .offer
                .minPrice
                .div_ceil(U256::from(total_cycles_approx));
            let max_price_per_cycle = failed_request
                .offer
                .maxPrice
                .div_ceil(U256::from(total_cycles_approx));
            let lock_timeout = failed_request.offer.lockTimeout;

            if is_locked {
                // If locked, that means a prover worked on the request but failed to deliver it on time.
                // Increase the lock timeout.
                let lock_timeout = lock_timeout.saturating_mul(LOCKTIME_INCREASE_RATIO);
                (min_price_per_cycle, max_price_per_cycle, lock_timeout)
            } else {
                // If not locked, that means the request was never taken by a prover.
                // Increase the min and max price per cycle.
                let min_price_per_cycle = min_price_per_cycle
                    .saturating_mul(U256::from(MIN_PRICE_INCREASE_MULTIPLIER))
                    .div_ceil(U256::from(MIN_PRICE_INCREASE_DIVISOR))
                    .min(U256::from(max_possible_price_wei_per_cycle));
                let max_price_per_cycle = max_price_per_cycle
                    .saturating_mul(U256::from(MAX_PRICE_INCREASE_RATIO))
                    .min(U256::from(max_possible_price_wei_per_cycle));
                (min_price_per_cycle, max_price_per_cycle, lock_timeout)
            }
        };

        let new_request = self
            .build_proof_request(
                // this now has receipt claim digest
                receipt_claim.digest(),
                image_id,
                Url::parse(&failed_request.imageUrl).expect("Invalid image URL"),
                Url::parse(
                    core::str::from_utf8(&failed_request.input.data).expect("Invalid input URL"),
                )
                .expect("Invalid input URL"),
                new_min_price_per_cycle,
                new_max_price_per_cycle,
                new_lock_timeout as u64,
                new_lock_timeout as u64 * TIMEOUT_IS_N_LOCK_TIMEOUT,
                failed_request.offer.rampUpPeriod as u64,
                lock_stake,
                price_response.bidding_start_delay,
                // TODO: https://github.com/chainwayxyz/citrea/issues/2820
                total_cycles_approx,
                journal.clone(),
            )
            .await;

        let (new_req_id, new_exp_time) = match self
            .send_request(new_request, job_id, image_id)
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
            "Resubmitted previously failing boundless proving session, job_id={} request_id={}, new min_price_per_cycle={:?}, new max_price_per_cycle={:?}, new lock_timeout={}",
            job_id,
            request_id,
            new_min_price_per_cycle,
            new_max_price_per_cycle,
            new_lock_timeout
        );
        Ok(ResubmitResult::Success)
    }

    async fn handle_session(
        &self,
        request_id: String,
        image_id: Digest,
        journal: Journal,
        receipt_claim: ReceiptClaim,
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

        let seal = fulfilled_request.seal;

        let claim = receipt_claim;

        // The first 4 bytes of the seal are reserved for metadata; the actual data starts at index 4.
        const SEAL_DATA_OFFSET: usize = 4;
        let inner = InnerReceipt::Groth16(Groth16Receipt::new(
            seal.clone().0.to_vec()[SEAL_DATA_OFFSET..].to_vec(),
            MaybePruned::Value(claim),
            risc0_zkvm::Groth16ReceiptVerifierParameters::default().digest(),
        ));
        let full_snark_receipt = Receipt::new(inner, journal.bytes.to_vec());
        full_snark_receipt.verify(image_id).unwrap();

        tracing::info!(
            "Successfully verified boundless Groth16 receipt for request_id={}",
            request_id
        );

        Ok(full_snark_receipt)
    }
}

/// Return UNIX timestamp in seconds
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Cannot fail because there is always a UNIX epoch")
        .as_secs()
}

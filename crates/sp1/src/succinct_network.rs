//! Proving on Succinct's prover network, at a percent of the network's suggested price.
use std::time::{Duration, Instant};

use anyhow::Context;
use citrea_common::sp1::NetworkRequestConfig;
use metrics::{counter, gauge, histogram};
use sov_rollup_interface::zk::{SuccinctNetworkFulfillment, SuccinctNetworkSession};
use sp1_sdk::network::proto::auction::network::prover_network_client::ProverNetworkClient;
use sp1_sdk::network::proto::auction::types::{
    FulfillmentStatus, GetProofRequestDetailsRequest, GetProvePriceRequest,
    GetProversByUptimeRequest, ProofRequest, ProofRequestError,
};
use sp1_sdk::network::proto::GetProofRequestParamsResponse;
use sp1_sdk::network::{Address, NetworkMode};
use sp1_sdk::{
    NetworkProver, ProveRequest, Prover, ProvingKey, SP1ProofMode, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1Stdin,
};

use crate::utils::{execution_stats, record_execution};

/// Runs an SDK call from the blocking thread a network proof runs on.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Handle::current().block_on(future)
}

/// The next step after a failed network request: raise the offer when no prover bid,
/// resubmit requests the network expired, resubmit unfulfillable ones a few times with
/// backoff, back off on RPC and upload errors and while a request is held back, poll an
/// accepted request again after any other failure, and fail when the guest itself cannot be
/// executed.
#[derive(Debug, PartialEq, Eq)]
enum NetworkRetry {
    NoBid,
    Resubmit,
    Unfulfillable,
    Backoff,
    Hold,
    Poll,
    Fail,
}

/// A request not submitted because the network's floor is above the USD limit or its PROVE
/// price is unknown. Retried with backoff, as prices can come back within the limit.
#[derive(Debug)]
struct HeldBack(String);

impl std::fmt::Display for HeldBack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HeldBack {}

/// A failure retrying cannot fix, such as a network response the job cannot price from.
#[derive(Debug)]
struct Permanent(String);

impl std::fmt::Display for Permanent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Permanent {}

/// `pending` is whether the network accepted the request that failed.
fn network_retry(error: &anyhow::Error, pending: bool) -> NetworkRetry {
    use sp1_sdk::network::Error;
    if error.chain().any(|cause| cause.is::<HeldBack>()) {
        return NetworkRetry::Hold;
    }
    if error.chain().any(|cause| cause.is::<Permanent>()) {
        return NetworkRetry::Fail;
    }
    // `downcast_ref` also finds an error attached as context, as the SDK does with
    // `SimulationFailed`.
    let network_error = error.downcast_ref::<Error>().or_else(|| {
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<Error>())
    });
    let status = match network_error {
        Some(Error::RequestAuctionTimedOut { .. }) => return NetworkRetry::NoBid,
        Some(Error::RequestExpired { .. }) => return NetworkRetry::Resubmit,
        // Only the node's clock says the deadline passed: the network can still settle the
        // request, and charge for it, so it is polled until the network ends it.
        Some(Error::RequestTimedOut { .. }) => return NetworkRetry::Poll,
        Some(Error::RequestUnfulfillable { .. }) => return NetworkRetry::Unfulfillable,
        // Unexecutable guests and reverted settlements end the job. The light client prover
        // retries its L1 block with backoff, from a new job; the batch prover reschedules the
        // job when it next starts.
        // The SDK warns that resubmitting a reverted settlement can burn PROVE on a failure
        // that repeats every time.
        Some(
            Error::SimulationFailed
            | Error::RequestUnexecutable { .. }
            | Error::RequestReverted { .. },
        ) => return NetworkRetry::Fail,
        Some(Error::RpcError(status)) => Some(status),
        Some(Error::Other(_)) => None,
        // SP1 6.10.0 propagates tonic::Status directly through anyhow after its
        // internal RPC retries, potentially with additional context.
        None => error
            .chain()
            .find_map(|cause| cause.downcast_ref::<tonic::Status>()),
    };
    match status.map(rpc_retry) {
        // Only the states above end an accepted request. Any other failure is of its status
        // RPC or its proof download, such as an HTTP 500, and says nothing about the request,
        // which may already be fulfilled. Polling it again is safe; a new request pays twice.
        Some(NetworkRetry::Fail) | None if pending => NetworkRetry::Poll,
        Some(retry) => retry,
        // Neither an SP1 error nor a gRPC status, such as an HTTP 503 from the object store
        // on the stdin upload, which the SDK does not retry. Nothing is accepted yet, so
        // retrying is free.
        None => NetworkRetry::Backoff,
    }
}

fn rpc_retry(status: &tonic::Status) -> NetworkRetry {
    use tonic::Code;
    // The SDK's transient statuses, plus any Unknown: tonic reports a connection dropped
    // mid-call as Unknown, which the SDK retries only for a dropped reused channel. Retrying a
    // request the network has not accepted is free.
    match status.code() {
        Code::Unavailable
        | Code::DeadlineExceeded
        | Code::Internal
        | Code::Aborted
        | Code::Cancelled
        | Code::Unknown => NetworkRetry::Backoff,
        _ => NetworkRetry::Fail,
    }
}

/// The network rejects requests whose deadline is more than 24 hours away.
const MAX_REQUEST_TIMEOUT_SECS: u64 = 24 * 60 * 60;

/// The first offer, as a percent of the network's suggested price: the SDK's default.
pub const FIRST_OFFER_PERCENT: u64 = 120;

/// Succinct's reference prover stops trusting a PROVE/USD price after two hours.
const MAX_PROVE_PRICE_AGE_SECS: i64 = 2 * 60 * 60;

/// The deadline of a request for `gas` PGU: `percent` of twice what a 5M PGU/s prover needs,
/// at least 40 minutes, at most the network's 24 hours.
fn deadline_secs(gas: u64, percent: u64) -> u64 {
    let deadline = gas.div_ceil(5_000_000).max(1200).saturating_mul(2);
    percent_of(deadline, percent).min(MAX_REQUEST_TIMEOUT_SECS)
}

/// `percent` of `value`, saturating.
fn percent_of(value: u64, percent: u64) -> u64 {
    u64::try_from(u128::from(value) * u128::from(percent) / 100).unwrap_or(u64::MAX)
}

/// Multiplies a percent or a deadline by `percent` for the next request, up to `cap`, never
/// lowering it.
fn raised(value: u64, percent: u64, cap: u64) -> u64 {
    percent_of(value, percent).min(cap).max(value)
}

/// Rounds a price down to the network's tick, which the auction requires of explicit prices,
/// but never below its floor, under which no prover bids.
fn aligned_price(price: u64, floor: u64, tick: u64) -> u64 {
    let aligned = if tick == 0 {
        price
    } else {
        price - price % tick
    };
    aligned.max(floor)
}

/// The price per PGU a request offers at `percent` of the network's `suggested` price, on the
/// network's tick and floor. Requests start at [`FIRST_OFFER_PERCENT`].
pub fn offered_price(suggested: u64, percent: u64, floor: u64, tick: u64) -> u64 {
    aligned_price(percent_of(suggested, percent), floor, tick)
}

/// The highest price per PGU, in PROVE wei, within `max_usd_per_billion_pgu` at `prove_usd`
/// USD per PROVE.
fn usd_cap_per_pgu(max_usd_per_billion_pgu: f64, prove_usd: f64) -> u64 {
    // USD per PGU, in PROVE, in wei (1e18 per PROVE). The cast saturates.
    (max_usd_per_billion_pgu / 1e9 / prove_usd * 1e18) as u64
}

/// The network's PROVE price in USD, if it is positive and at most two hours old at `now`.
fn prove_usd(price: &str, last_updated: i64, now: i64) -> anyhow::Result<f64> {
    match price.parse::<f64>() {
        Ok(usd)
            if usd.is_finite()
                && usd > 0.0
                && now.saturating_sub(last_updated) <= MAX_PROVE_PRICE_AGE_SECS =>
        {
            Ok(usd)
        }
        _ => Err(HeldBack(format!(
            "No current PROVE/USD price from the prover network: {price:?}, updated at {last_updated}"
        ))
        .into()),
    }
}

/// The network's suggested price per PGU, if it gave a positive one.
fn suggested_price(max_price_per_pgu: &str) -> Option<u64> {
    max_price_per_pgu.parse().ok().filter(|&price| price > 0)
}

/// Proves on Succinct's prover network at a percent of the network's suggested price, retrying
/// until a proof arrives or [`network_retry`] decides to fail. Returns the proof and the job's
/// session info. The batch prover's path, also run by the `network_proof` example. It blocks
/// until the proof arrives, so it must run on a blocking thread inside a Tokio runtime, such as
/// one from `spawn_blocking`.
pub fn prove_on_network(
    client: &NetworkProver,
    pk: &SP1ProvingKey,
    stdin: SP1Stdin,
    mode: SP1ProofMode,
    config: &NetworkRequestConfig,
) -> anyhow::Result<(SP1ProofWithPublicValues, SuccinctNetworkSession)> {
    const MIN_BACKOFF: Duration = Duration::from_secs(5);
    const MAX_BACKOFF: Duration = Duration::from_secs(300);
    // How long an accepted request may keep failing to report its status or deliver its
    // proof, as when the network refuses the download for good.
    const MAX_POLL_FAILURES: Duration = Duration::from_secs(60 * 60);
    // How many times a missing suggested price is retried before the job prices without it.
    const SUGGESTION_RETRIES: u32 = 3;
    // How many unfulfillable requests a job resubmits; the SDK resubmits one. A cause that
    // repeats, such as a proving failure on this input, would otherwise repeat forever.
    const UNFULFILLABLE_RESUBMITS: u32 = 3;
    // Executing first gives the gas the deadline is set from, and the public values the proof
    // must commit to.
    let (public_values, report) = block_on(async {
        client
            .execute(pk.elf().clone(), stdin.clone())
            .calculate_gas(true)
            .await
    })?;
    anyhow::ensure!(
        report.exit_code == 0,
        "SP1 guest exited with code {}",
        report.exit_code
    );
    let execution = execution_stats(&report)?;
    record_execution(&execution);
    let (cycles, gas) = (execution.instruction_count, execution.gas);
    let mut timeout_secs = deadline_secs(gas, config.deadline_percent);
    tracing::info!(cycles, gas, timeout_secs, "Requesting SP1 network proof");
    let auction_timeout = Duration::from_secs(config.auction_timeout_secs);
    // The percent of the suggested price to offer. Only a request no prover bid on raises it,
    // and it stays raised for the rest of the job.
    let mut percent = FIRST_OFFER_PERCENT;
    // The job's highest offer before the USD limit. Offers never go below it.
    let mut highest_offer = 0;
    // Doubles with each failure until a request is submitted.
    let mut backoff = MIN_BACKOFF;
    // The request the network accepted. Only its terminal states clear it, so a proof on its
    // way or already delivered is not paid twice.
    let mut pending = None;
    // When polling the pending request began to fail with a `Poll` error. A successful poll
    // clears it, so only consecutive failures end the job.
    let mut polls_failing_since = None;
    // Consecutive auctions without a suggested price.
    let mut missing_suggestions = 0;
    // Requests the network marked unfulfillable.
    let mut unfulfillable = 0;
    // The network's high-availability provers, once the job requests only from them. None
    // leaves the SDK's default set of reliable provers.
    let mut whitelist = None;
    loop {
        let result = block_on(async {
            let request_id = match pending {
                Some(request_id) => request_id,
                None => {
                    let auction = auction_params(client, mode).await?;
                    match auction.suggested {
                        Some(_) => missing_suggestions = 0,
                        None if missing_suggestions < SUGGESTION_RETRIES => {
                            missing_suggestions += 1;
                            anyhow::bail!("Prover network suggested no price per PGU");
                        }
                        None => {}
                    }
                    let max_price_per_pgu = offer(
                        auction,
                        percent,
                        &mut highest_offer,
                        config.max_usd_per_billion_pgu,
                    )?;
                    let request_id = client
                        .prove(pk, stdin.clone())
                        .mode(mode)
                        // Both limits stop the SDK from executing the guest again, so it sends no
                        // public values hash for the network to check; the proof is checked below.
                        .cycle_limit(cycles)
                        .gas_limit(gas)
                        .max_price_per_pgu(max_price_per_pgu)
                        .min_auction_period(config.min_auction_period_secs)
                        .timeout(Duration::from_secs(timeout_secs))
                        .whitelist(whitelist.clone())
                        .request()
                        .await?;
                    tracing::info!(
                        %request_id,
                        suggested = ?auction.suggested,
                        floor = auction.floor,
                        tick = auction.tick,
                        percent,
                        max_price_per_pgu,
                        prove_usd = auction.prove_usd,
                        usd_per_billion_pgu = max_price_per_pgu as f64 * auction.prove_usd / 1e9,
                        timeout_secs,
                        high_availability_only = whitelist.is_some(),
                        "Submitted SP1 network proof request"
                    );
                    backoff = MIN_BACKOFF;
                    *pending.insert(request_id)
                }
            };
            // The SDK's `wait_proof` loop, polling every 2 seconds. `wait_proof` returns only
            // when polling ends, so a healthy poll could not clear the failure timer. The network
            // enforces each request's deadline, so only the auction is timed here.
            let mut requested_since = None;
            loop {
                let (proof, status) = client.process_proof_status(request_id, None).await?;
                polls_failing_since = None;
                match status {
                    FulfillmentStatus::Fulfilled => {
                        return Ok((
                            proof
                                .context("The SP1 network fulfilled the request without a proof")?,
                            request_id,
                        ));
                    }
                    FulfillmentStatus::Requested
                        if requested_since.get_or_insert_with(Instant::now).elapsed()
                            > auction_timeout =>
                    {
                        client.cancel_request(request_id).await?;
                        return Err(sp1_sdk::network::Error::RequestAuctionTimedOut {
                            request_id: request_id.to_vec(),
                        }
                        .into());
                    }
                    _ => {}
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        let error = match result {
            Ok((proof, request_id)) => {
                // A valid proof of other public values proves nothing about this job.
                // Resubmitting would pay again for the same divergence.
                anyhow::ensure!(
                    proof.public_values.as_slice() == public_values.as_slice(),
                    "SP1 network proof commits to other public values than the local execution"
                );

                let session = SuccinctNetworkSession {
                    request_id: request_id.0,
                    execution,
                    fulfillment: fetch_fulfillment(client, request_id),
                };
                return Ok((proof, session));
            }
            Err(error) => error,
        };
        let retry = network_retry(&error, pending.is_some());
        // A prover took the request and did not deliver it, and could win the next auction
        // too. Like the SDK's single fallback, the job then requests only from the network's
        // high-availability provers, but for the rest of the job.
        // When the network lists none, or cannot be asked, the job keeps the default set and
        // asks again after the next such request.
        if matches!(retry, NetworkRetry::Resubmit | NetworkRetry::Unfulfillable)
            && whitelist.is_none()
        {
            whitelist = block_on(high_availability_provers());
            if whitelist.is_some() {
                counter!("sp1_network_high_availability_fallbacks").increment(1);
                tracing::warn!("Requesting only from the network's high-availability provers for the rest of the job");
            }
        }
        match retry {
            NetworkRetry::NoBid => {
                pending = None;
                polls_failing_since = None;
                counter!("sp1_network_no_bid_resubmits").increment(1);
                percent = raised(
                    percent,
                    config.no_bid_raise_percent,
                    config.max_price_percent,
                );
                tracing::warn!(%error, percent, "No prover bid on the request; resubmitting");
            }
            NetworkRetry::Resubmit => {
                pending = None;
                polls_failing_since = None;
                // The network expired the request undelivered, so give the next one twice as
                // long.
                timeout_secs = raised(timeout_secs, 200, MAX_REQUEST_TIMEOUT_SECS);
                tracing::warn!(%error, timeout_secs, "Network proof was not delivered; resubmitting");
            }
            retry @ (NetworkRetry::Backoff
            | NetworkRetry::Hold
            | NetworkRetry::Poll
            | NetworkRetry::Unfulfillable) => {
                match retry {
                    NetworkRetry::Unfulfillable => {
                        polls_failing_since = None;
                        unfulfillable += 1;
                        let reason = match pending.take() {
                            Some(request_id) => block_on(unfulfillable_reason(
                                request_id.as_slice(),
                            ))
                            .unwrap_or_else(|error| {
                                tracing::warn!(%error, "Could not get why the SP1 network request was unfulfillable");
                                "UNKNOWN"
                            }),
                            None => "UNKNOWN",
                        };
                        counter!("sp1_network_unfulfillable_requests", "reason" => reason)
                            .increment(1);
                        if unfulfillable > UNFULFILLABLE_RESUBMITS {
                            return Err(error.context(format!(
                                "SP1 network request unfulfillable {unfulfillable} times, last for {reason}"
                            )));
                        }
                        tracing::warn!(%error, reason, unfulfillable, ?backoff, "Network marked the proof request unfulfillable; resubmitting");
                    }
                    NetworkRetry::Hold => {
                        counter!("sp1_network_usd_limit_holds").increment(1);
                        tracing::warn!(%error, ?backoff, "Holding the request until the network's prices are known and within the USD limit");
                    }
                    NetworkRetry::Poll => {
                        let since = *polls_failing_since.get_or_insert_with(Instant::now);
                        if since.elapsed() > MAX_POLL_FAILURES {
                            return Err(error.context(
                                "Could not get the status or proof of an accepted SP1 network request",
                            ));
                        }
                        tracing::warn!(%error, ?backoff, "Getting the accepted SP1 network request failed; polling it again");
                    }
                    _ => tracing::warn!(%error, ?backoff, "Prover network RPC failed; retrying"),
                }
                // A Tokio sleep ends when the runtime shuts down; a thread sleep would hold the
                // process open until it ran out.
                block_on(tokio::time::sleep(backoff));
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            NetworkRetry::Fail => return Err(error),
        }
    }
}

/// The network's record of a delivered request.
fn fetch_fulfillment(
    client: &NetworkProver,
    request_id: sp1_sdk::network::B256,
) -> Option<SuccinctNetworkFulfillment> {
    match block_on(client.get_proof_request(request_id)) {
        Ok(Some(request)) => {
            let fulfillment = fulfillment(&request);
            record_fulfillment(&fulfillment);
            Some(fulfillment)
        }
        Ok(None) => {
            tracing::warn!(%request_id, "Prover network has no record of the delivered request");
            None
        }
        Err(error) => {
            tracing::warn!(%request_id, %error, "Could not fetch the delivered request");
            None
        }
    }
}

fn fulfillment(request: &ProofRequest) -> SuccinctNetworkFulfillment {
    SuccinctNetworkFulfillment {
        gas_used: request.gas_used,
        gas_price: request.gas_price,
        base_fee: request.base_fee.clone(),
        created_at: request.created_at,
        fulfilled_at: request.fulfilled_at,
    }
}

fn record_fulfillment(fulfillment: &SuccinctNetworkFulfillment) {
    if let Some(gas_price) = fulfillment.gas_price {
        // Wei per PGU to PROVE per billion PGU
        gauge!("sp1_network_gas_price").set(gas_price as f64 / 1e9);
    }
    if let Some(fulfilled_at) = fulfillment.fulfilled_at {
        histogram!("sp1_network_request_duration_secs")
            .record(fulfilled_at.saturating_sub(fulfillment.created_at) as f64);
    }
}

/// The network's prices per PGU for the next request, and its PROVE price in USD.
#[derive(Debug, Clone, Copy)]
struct AuctionParams {
    suggested: Option<u64>,
    floor: u64,
    tick: u64,
    prove_usd: f64,
}

/// The network's suggested and floor prices, its auction tick and its PROVE price.
async fn auction_params(
    client: &NetworkProver,
    mode: SP1ProofMode,
) -> anyhow::Result<AuctionParams> {
    let GetProofRequestParamsResponse::Auction(params) =
        client.get_proof_request_params(mode).await?
    else {
        return Err(Permanent("Prover network returned no auction parameters".into()).into());
    };
    // The SDK does not wrap this RPC, so it is called on the RPC the SDK uses.
    let price = rpc_client()?
        .get_prove_price(GetProvePriceRequest {})
        .await?
        .into_inner();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(AuctionParams {
        suggested: suggested_price(&params.max_price_per_pgu),
        // Empty on RPCs that predate the field.
        floor: params.network_floor_price_per_pgu.parse().unwrap_or(0),
        tick: params.tick_size,
        prove_usd: prove_usd(
            &price.price,
            price.last_updated,
            i64::try_from(now).unwrap_or(i64::MAX),
        )?,
    })
}

/// The price per PGU to offer at `percent` of the network's suggested price. It never goes
/// below `highest_offer`, which it raises, so a falling suggestion cannot undo a raise. The USD
/// limit applies only to the price sent, so a limit that binds for a while does not lower
/// `highest_offer` either. Priced here rather than by the SDK's buffer setter, which neither
/// keeps it nor clamps to the floor.
fn offer(
    auction: AuctionParams,
    percent: u64,
    highest_offer: &mut u64,
    max_usd_per_billion_pgu: f64,
) -> anyhow::Result<u64> {
    let AuctionParams {
        suggested,
        floor,
        tick,
        prove_usd,
    } = auction;
    // The USD limit always wins: rounded down to the tick, and no request under the floor.
    let usd_cap = aligned_price(usd_cap_per_pgu(max_usd_per_billion_pgu, prove_usd), 0, tick);
    if usd_cap < floor {
        return Err(HeldBack(format!(
            "The network's floor of {floor} wei per PGU is above {max_usd_per_billion_pgu} USD per billion PGU at {prove_usd} USD per PROVE"
        ))
        .into());
    }
    // Without the network's suggestion the first offer is a quarter of the USD limit, so the
    // default 480% reaches the limit.
    let suggested = suggested.unwrap_or_else(|| {
        let first_offer_usd = max_usd_per_billion_pgu / 4.0;
        usd_cap_per_pgu(
            first_offer_usd * 100.0 / FIRST_OFFER_PERCENT as f64,
            prove_usd,
        )
    });
    *highest_offer = aligned_price(
        percent_of(suggested, percent).max(*highest_offer),
        floor,
        tick,
    );
    Ok((*highest_offer).min(usd_cap))
}

/// Why the network marked a request unfulfillable: its `ProofRequestError` name, such as
/// `PROVING_FAILURE`. The SDK does not read it, so it is read on the RPC the SDK uses.
async fn unfulfillable_reason(request_id: &[u8]) -> anyhow::Result<&'static str> {
    let error = rpc_client()?
        .get_proof_request_details(GetProofRequestDetailsRequest {
            request_id: request_id.to_vec(),
        })
        .await?
        .into_inner()
        .request
        .context("Prover network returned no request details")?
        .error;
    Ok(ProofRequestError::try_from(error).map_or("UNKNOWN", |reason| reason.as_str_name()))
}

/// The network's high-availability provers, or `None`, the SDK's default set of reliable
/// provers, when the network lists none or cannot be asked.
async fn high_availability_provers() -> Option<Vec<Address>> {
    let provers = async {
        anyhow::Ok(
            rpc_client()?
                .get_provers_by_uptime(GetProversByUptimeRequest {
                    high_availability_only: true,
                })
                .await?
                .into_inner()
                .provers,
        )
    }
    .await;
    let provers: Vec<Address> = match provers {
        Ok(provers) => provers
            .iter()
            .filter_map(|prover| Address::try_from(prover.as_slice()).ok())
            .collect(),
        Err(error) => {
            tracing::warn!(%error, "Could not get the network's high-availability provers; requesting from its default set");
            return None;
        }
    };
    if provers.is_empty() {
        tracing::warn!(
            "The network lists no high-availability provers; requesting from its default set"
        );
        return None;
    }
    Some(provers)
}

/// A client for the prover network RPC the SDK uses: `NETWORK_RPC_URL`, or Succinct's mainnet.
/// Connects on first use, so it must be built inside the Tokio runtime.
fn rpc_client() -> anyhow::Result<ProverNetworkClient<tonic::transport::Channel>> {
    let url = std::env::var("NETWORK_RPC_URL").unwrap_or_else(|_| {
        sp1_sdk::network::utils::get_default_rpc_url_for_mode(NetworkMode::Mainnet)
    });
    let mut endpoint = tonic::transport::Endpoint::from_shared(url.clone())?
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(15));
    if url.starts_with("https://") {
        endpoint =
            endpoint.tls_config(tonic::transport::ClientTlsConfig::new().with_enabled_roots())?;
    }
    Ok(ProverNetworkClient::new(endpoint.connect_lazy()))
}

#[cfg(test)]
mod tests {
    use sp1_sdk::network::Error;

    use super::*;

    #[test]
    fn deadlines_follow_the_gas_from_forty_minutes_to_a_day() {
        assert_eq!(deadline_secs(0, 100), 2400);
        assert_eq!(deadline_secs(10_000_000_000, 100), 4000);
        // Rounded up to a whole second.
        assert_eq!(deadline_secs(6_000_000_001, 100), 2402);
        assert_eq!(deadline_secs(u64::MAX, 100), MAX_REQUEST_TIMEOUT_SECS);
        // Operators can stretch or shorten them, still within a day.
        assert_eq!(deadline_secs(10_000_000_000, 150), 6000);
        assert_eq!(deadline_secs(0, 50), 1200);
        assert_eq!(
            deadline_secs(100_000_000_000, 400),
            MAX_REQUEST_TIMEOUT_SECS
        );
    }

    #[test]
    fn usd_limits_convert_to_prove_wei_per_pgu() {
        // 5 USD per billion PGU at 0.1921 USD per PROVE is 26.03 PROVE per billion PGU.
        assert_eq!(usd_cap_per_pgu(5.0, 0.1921), 26_028_110_359);
        assert_eq!(usd_cap_per_pgu(5.0, f64::MIN_POSITIVE), u64::MAX);
    }

    #[test]
    fn only_a_recent_positive_prove_price_counts() {
        let now = 1_000_000;
        assert!((prove_usd("0.1921", now - 7200, now).unwrap() - 0.1921).abs() < 1e-12);
        for (price, updated) in [
            ("0.1921", now - 7201),
            ("", now),
            ("0", now),
            ("-1", now),
            ("NaN", now),
            ("inf", now),
        ] {
            let error = prove_usd(price, updated, now).unwrap_err();
            assert_eq!(
                network_retry(&error, false),
                NetworkRetry::Hold,
                "{price:?}"
            );
        }
    }

    #[test]
    fn only_a_positive_suggested_price_counts() {
        assert_eq!(suggested_price("652741514"), Some(652_741_514));
        for missing in ["", "0", "-1", "1.5"] {
            assert_eq!(suggested_price(missing), None, "{missing:?}");
        }
    }

    #[test]
    fn network_failures_follow_the_retry_policy() {
        use tonic::Status;
        use NetworkRetry::*;
        let id = || vec![1];
        // Each error, then the step before and after the network accepted the request.
        let cases: Vec<(anyhow::Error, NetworkRetry, NetworkRetry)> = vec![
            (
                Error::RequestAuctionTimedOut { request_id: id() }.into(),
                NoBid,
                NoBid,
            ),
            (
                Error::RequestTimedOut { request_id: id() }.into(),
                Poll,
                Poll,
            ),
            (
                Error::RequestExpired { request_id: id() }.into(),
                Resubmit,
                Resubmit,
            ),
            (
                Error::RequestUnfulfillable { request_id: id() }.into(),
                Unfulfillable,
                Unfulfillable,
            ),
            (
                Error::RequestReverted { request_id: id() }.into(),
                Fail,
                Fail,
            ),
            (
                Error::RequestUnexecutable { request_id: id() }.into(),
                Fail,
                Fail,
            ),
            // The SDK wraps guest simulation failures as context.
            (
                anyhow::anyhow!("guest panicked").context(Error::SimulationFailed),
                Fail,
                Fail,
            ),
            // A failed artifact upload or download has neither an SP1 error nor a status.
            (
                anyhow::anyhow!("Failed to upload artifact: HTTP 503 Service Unavailable"),
                Backoff,
                Poll,
            ),
            (
                Error::RpcError(Status::unavailable("unavailable")).into(),
                Backoff,
                Backoff,
            ),
            // SP1 6.10.0 returns the status directly after exhausting its RPC retries.
            (
                anyhow::Error::new(Status::cancelled("cancelled"))
                    .context("failed to get proof request status"),
                Backoff,
                Backoff,
            ),
            (
                Status::unknown("Service was not ready: transport error").into(),
                Backoff,
                Backoff,
            ),
            // A connection dropped mid-call.
            (
                Status::unknown("h2 protocol error: error reading a body from connection").into(),
                Backoff,
                Backoff,
            ),
            (
                Status::resource_exhausted("insufficient balance").into(),
                Fail,
                Poll,
            ),
            (HeldBack("over the limit".into()).into(), Hold, Hold),
        ];
        for (error, before, after) in cases {
            assert_eq!(network_retry(&error, false), before, "{error:#}");
            assert_eq!(network_retry(&error, true), after, "pending: {error:#}");
        }
    }

    #[test]
    fn offers_keep_their_raises_within_the_usd_limit() {
        let auction = |suggested, prove_usd| AuctionParams {
            suggested: Some(suggested),
            floor: 0,
            tick: 0,
            prove_usd,
        };
        let mut highest = 0;
        let mut offer_at = |suggested, prove_usd, percent| {
            offer(auction(suggested, prove_usd), percent, &mut highest, 5.0).unwrap()
        };
        assert_eq!(offer_at(100, 1.0, 120), 120);
        // 180% of a halved suggestion would offer 90, under the 120 that got no bid.
        assert_eq!(offer_at(50, 1.0, 180), 120);
        assert_eq!(offer_at(100, 1.0, 270), 270);
        // At 50M USD per PROVE, 5 USD per billion PGU is 100 wei per PGU.
        assert_eq!(offer_at(100, 50_000_000.0, 405), 100);
        // Once the limit stops binding the job keeps its 405, not 405% of a fallen 30.
        assert_eq!(offer_at(30, 1.0, 405), 405);

        // Rounded down to the network's tick, and never under its floor.
        let network = AuctionParams {
            suggested: Some(652_741_514),
            floor: 220_000_000,
            tick: 10_000_000,
            prove_usd: 0.1921,
        };
        assert_eq!(offer(network, 120, &mut 0, 5.0).unwrap(), 780_000_000);
        let low = AuctionParams {
            suggested: Some(100_000_000),
            ..network
        };
        assert_eq!(offer(low, 120, &mut 0, 5.0).unwrap(), 220_000_000);

        // A USD limit under the floor holds the request.
        let held = AuctionParams {
            floor: 150,
            ..auction(100, 50_000_000.0)
        };
        let error = offer(held, 120, &mut 0, 5.0).unwrap_err();
        assert_eq!(network_retry(&error, false), NetworkRetry::Hold);

        // Without a suggestion the first offer is a quarter of the 5e9 wei limit, less float
        // rounding, and the default 480% reaches the limit.
        let unsuggested = AuctionParams {
            suggested: None,
            ..auction(0, 1.0)
        };
        assert_eq!(usd_cap_per_pgu(5.0, 1.0), 5_000_000_000);
        assert_eq!(offer(unsuggested, 120, &mut 0, 5.0).unwrap(), 1_249_999_999);
        assert_eq!(offer(unsuggested, 480, &mut 0, 5.0).unwrap(), 4_999_999_996);
        assert_eq!(offer(unsuggested, 600, &mut 0, 5.0).unwrap(), 5_000_000_000);
    }
}

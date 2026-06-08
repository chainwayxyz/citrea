//! Tx-sender integration helpers for the Bitcoin DA service.
//!
//! This module provides types and utilities for communicating with the external
//! tx-sender service, including job status polling.

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use bitcoin::Txid;
use bitcoincore_rpc::{Client, RpcApi};
use citrea_primitives::compression::compress_blob;
use reth_tasks::shutdown::GracefulShutdown;
use sov_rollup_interface::da::{DaTxRequest, DataOnDa};
use sov_rollup_interface::services::da::TxRequestWithNotifier;
use tokio::select;
use tracing::{debug, error, info, warn};
use tx_sender_jsonrpc_client::{
    BitcoinTxStatus, CitreaTxRequest, CommitRevealKind, CommitRevealStatus, JsonRpcTxSenderClient,
    TrackRequest, TrackResponse, TrackStatus,
};

use crate::error::BitcoinServiceError;
use crate::helpers::builders::TxWithId;
use crate::monitoring::{
    MonitorError, MonitoredTxKind, MonitoringService, TxStatus as MonitoringTxStatus,
};
use crate::service::TxSenderJobId;

/// Convert a [`DaTxRequest`] into a [`CitreaTxRequest`] for the external tx-sender service.
pub(crate) fn to_citrea_tx_request(
    tx_request: &DaTxRequest,
) -> Result<CitreaTxRequest, BitcoinServiceError> {
    match tx_request {
        DaTxRequest::ZKProof(proof) => {
            // Send the compressed proof only. The tx-sender wraps it in
            // `DataOnDa::Complete(bytes)` and borsh-serializes before inscribing,
            // producing `borsh(DataOnDa::Complete(compressed_proof))` which is what
            // `extract_relevant_zk_proofs` expects on the read side.
            let bytes = compress_blob(proof).map_err(BitcoinServiceError::CompressionError)?;
            Ok(CitreaTxRequest::BatchProof {
                bytes,
                chunk_size: None,
            })
        }
        DaTxRequest::SequencerCommitment(commitment) => {
            let bytes = borsh::to_vec(&DataOnDa::SequencerCommitment(commitment.clone()))
                .expect("borsh serialization should not fail");
            Ok(CitreaTxRequest::SequencerCommitment(bytes))
        }
        DaTxRequest::BatchProofMethodId(method_id) => {
            let bytes = borsh::to_vec(&DataOnDa::BatchProofMethodId(method_id.clone()))
                .expect("borsh serialization should not fail");
            Ok(CitreaTxRequest::BatchProofMethodId(bytes))
        }
    }
}

/// Initial delay between `send_citrea_tx` retries when the tx-sender is unavailable.
const SEND_RETRY_BACKOFF_START: Duration = Duration::from_secs(1);
/// Maximum delay between `send_citrea_tx` retries (exponential backoff cap).
const SEND_RETRY_BACKOFF_MAX: Duration = Duration::from_secs(30);

pub(crate) async fn queue_tx_sender_request(
    tx_sender: JsonRpcTxSenderClient,
    bitcoin_client: Arc<Client>,
    monitoring: Arc<MonitoringService>,
    request: TxRequestWithNotifier<TxSenderJobId>,
    poll_interval: Duration,
    shutdown: &mut GracefulShutdown,
) {
    let citrea_request = match to_citrea_tx_request(&request.tx_request) {
        Ok(citrea_request) => citrea_request,
        Err(e) => {
            let _ = request.notify.send(Err(anyhow!(e)));
            return;
        }
    };

    let mut backoff = SEND_RETRY_BACKOFF_START;
    let job_id = loop {
        select! {
            biased;
            _ = &mut *shutdown => {
                let _ = request.notify.send(Err(anyhow!(
                    "DA queue shutting down before tx-sender accepted the request"
                )));
                return;
            }
            res = tx_sender.send_citrea_tx(citrea_request.clone()) => match res {
                Ok(job_id) => {
                    info!(job_id, "Sent DA tx request to tx-sender");
                    break job_id;
                }
                Err(e) => {
                    error!(?e, ?backoff, "Failed to send tx to tx-sender. Retrying...");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(SEND_RETRY_BACKOFF_MAX);
                }
            }
        }
    };

    let _ = request.notify.send(Ok(TxSenderJobId(job_id)));

    tokio::spawn(poll_tx_sender_job(
        tx_sender,
        bitcoin_client,
        monitoring,
        job_id,
        poll_interval,
    ));
}

/// Status of a job submitted to the external tx-sender service.
#[derive(Debug, Clone)]
pub(crate) enum TxSenderJobStatus {
    /// Job is queued but not yet started.
    Pending,
    /// Job is actively being processed (e.g., building/broadcasting transaction).
    Processing,
    /// Job completed successfully with the reveal txid carrying the DA payload.
    Completed {
        /// The reveal or aggregate reveal txid.
        reveal_txid: Txid,
    },
    /// Job failed with an error message.
    Failed {
        /// The error description.
        error: String,
    },
}

/// Polls the tx-sender service for job completion and keeps monitoring in sync.
///
/// This function spawns no tasks itself — it is intended to be called from within
/// a `tokio::spawn` block. It polls until the job reaches a terminal state
/// (Completed or Failed), updating monitoring state along the way.
///
/// # Arguments
/// * `client` - The tx-sender JSON-RPC client.
/// * `job_id` - The tx-sender job ID (insertion_id from `send_citrea_tx`) to poll.
/// * `poll_interval` - How often to poll the tx-sender for status updates.
pub(crate) async fn poll_tx_sender_job(
    client: JsonRpcTxSenderClient,
    bitcoin_client: Arc<Client>,
    monitoring: Arc<MonitoringService>,
    job_id: i64,
    poll_interval: Duration,
) {
    info!(job_id, "Starting to poll tx-sender job status");

    loop {
        match poll_job_status(&client, job_id).await {
            Ok((status, raw_status)) => {
                if let TrackResponse::CommitReveal(commit_reveal_status) = raw_status {
                    sync_monitoring(
                        bitcoin_client.clone(),
                        monitoring.clone(),
                        &commit_reveal_status,
                    )
                    .await;
                }

                match status {
                    TxSenderJobStatus::Completed { reveal_txid } => {
                        info!(job_id, %reveal_txid, "Tx-sender job finalized");
                        return;
                    }
                    TxSenderJobStatus::Failed { error } => {
                        error!(job_id, error, "Tx-sender job failed");
                        return;
                    }
                    TxSenderJobStatus::Pending | TxSenderJobStatus::Processing => {
                        debug!(job_id, "Tx-sender job still in progress, polling again");
                    }
                }
            }
            Err(err) => {
                warn!(
                    job_id,
                    ?err,
                    "Failed to poll tx-sender job status, retrying"
                );
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Wait for a tx-sender job to expose the txid carrying the DA payload.
pub(crate) async fn wait_for_tx_sender_job(
    client: JsonRpcTxSenderClient,
    bitcoin_client: Arc<Client>,
    monitoring: Arc<MonitoringService>,
    job_id: i64,
    poll_interval: Duration,
) -> Result<Txid, anyhow::Error> {
    info!(job_id, "Waiting for tx-sender job to expose payload txid");

    loop {
        let status = poll_job_status(&client, job_id).await;

        match status {
            Ok((status, raw_status)) => {
                if let TrackResponse::CommitReveal(commit_reveal_status) = &raw_status {
                    sync_monitoring(
                        bitcoin_client.clone(),
                        monitoring.clone(),
                        commit_reveal_status,
                    )
                    .await;
                }

                match resolve_wait_outcome(&status, &raw_status) {
                    Some(Ok(txid)) => return Ok(txid),
                    Some(Err(error)) => {
                        return Err(anyhow!("Tx-sender job {job_id} failed: {error}"));
                    }
                    None => {
                        debug!(
                            job_id,
                            "Tx-sender job has no payload txid yet, polling again"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(job_id, ?e, "Failed to poll tx-sender job status, retrying");
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Decide the outcome of a single `wait_for_tx_sender_job` poll.
///
/// Terminal failure takes precedence over an extractable payload txid: a cancelled job
/// may still carry a reveal submission with a txid, but that DA submission has failed and
/// must never be reported as success. Returns `None` while the job is still in progress.
fn resolve_wait_outcome(
    status: &TxSenderJobStatus,
    raw_status: &TrackResponse,
) -> Option<Result<Txid, String>> {
    if let TxSenderJobStatus::Failed { error } = status {
        return Some(Err(error.clone()));
    }

    if let TrackResponse::CommitReveal(commit_reveal_status) = raw_status {
        if let Some(txid) = extract_payload_txid_from_commit_reveal(commit_reveal_status) {
            return Some(Ok(txid));
        }
    }

    None
}

/// Query the tx-sender service for the status of a given job via the `track_tx` RPC.
async fn poll_job_status(
    client: &JsonRpcTxSenderClient,
    job_id: i64,
) -> Result<(TxSenderJobStatus, TrackResponse), anyhow::Error> {
    let request = TrackRequest::CommitReveal {
        insertion_id: job_id,
    };

    let response = client
        .track_tx(request)
        .await
        .map_err(|e| anyhow!("track_tx RPC failed for job {job_id}: {e}"))?;

    let status = map_track_response(response.clone(), job_id)?;

    Ok((status, response))
}

/// Map a `TrackResponse` to a `TxSenderJobStatus`.
fn map_track_response(
    response: TrackResponse,
    job_id: i64,
) -> Result<TxSenderJobStatus, anyhow::Error> {
    match response {
        TrackResponse::CommitReveal(status) => match status.status {
            TrackStatus::Finalized => {
                let reveal_txid =
                    extract_payload_txid_from_commit_reveal(&status).ok_or_else(|| {
                        anyhow!("Commit-reveal job {job_id} finalized without a reveal txid")
                    })?;
                Ok(TxSenderJobStatus::Completed { reveal_txid })
            }
            TrackStatus::Cancelled => {
                let error = format!("Commit-reveal job {job_id} was cancelled");
                Ok(TxSenderJobStatus::Failed { error })
            }
            TrackStatus::Pending => Ok(TxSenderJobStatus::Pending),
            TrackStatus::InProgress | TrackStatus::Mined => Ok(TxSenderJobStatus::Processing),
        },
        TrackResponse::Transaction(_) => Err(anyhow!(
            "Expected CommitReveal response for job {job_id}, got Transaction"
        )),
    }
}

/// Extract finalized txids from a commit-reveal status response.
#[cfg(test)]
fn extract_txids_from_commit_reveal(
    status: &tx_sender_jsonrpc_client::CommitRevealStatus,
) -> Vec<Txid> {
    let mut txids = Vec::new();

    // Collect txids from reveals that have been finalized.
    for reveal in &status.reveals {
        if let Some(ref submission) = reveal.submission {
            if let Ok(txid) = submission.tx_info.txid.parse::<Txid>() {
                txids.push(txid);
            }
        }
    }

    // If there's an aggregate commit tx, include it.
    if let Some(ref aggregate_commit) = status.aggregate_commit_tx {
        if let Ok(txid) = aggregate_commit.txid.parse::<Txid>() {
            txids.push(txid);
        }
    }

    // If there's a commit tx, include it.
    if let Some(ref commit) = status.commit_tx {
        if let Ok(txid) = commit.txid.parse::<Txid>() {
            txids.push(txid);
        }
    }

    txids
}

fn extract_payload_txid_from_commit_reveal(
    status: &tx_sender_jsonrpc_client::CommitRevealStatus,
) -> Option<Txid> {
    status
        .reveals
        .iter()
        .find(|reveal| matches!(reveal.kind, CommitRevealKind::Aggregate))
        .and_then(|reveal| reveal.submission.as_ref())
        .and_then(|submission| submission.tx_info.txid.parse::<Txid>().ok())
        .or_else(|| {
            status
                .reveals
                .iter()
                .rev()
                .filter(|reveal| {
                    !matches!(
                        reveal.kind,
                        CommitRevealKind::Aggregate | CommitRevealKind::Chunk
                    )
                })
                .filter_map(|reveal| reveal.submission.as_ref())
                .find_map(|submission| submission.tx_info.txid.parse::<Txid>().ok())
        })
}

#[derive(Debug, Clone)]
struct TxSenderMonitoredTx {
    txid: Txid,
    kind: MonitoredTxKind,
    tx_info: BitcoinTxStatus,
    fee_sat_kvb: Option<u64>,
}

fn tx_sender_monitored_txs(status: &CommitRevealStatus) -> Vec<TxSenderMonitoredTx> {
    let mut txs = Vec::new();

    if let Some(commit) = &status.commit_tx {
        if let Ok(txid) = commit.txid.parse::<Txid>() {
            txs.push(TxSenderMonitoredTx {
                txid,
                kind: MonitoredTxKind::Commit,
                tx_info: commit.clone(),
                fee_sat_kvb: None,
            });
        }
    }

    txs.extend(status.reveals.iter().filter_map(|reveal| {
        if matches!(reveal.kind, CommitRevealKind::Aggregate) {
            return None;
        }

        reveal.submission.as_ref().and_then(|submission| {
            submission
                .tx_info
                .txid
                .parse::<Txid>()
                .ok()
                .map(|txid| TxSenderMonitoredTx {
                    txid,
                    kind: MonitoredTxKind::Reveal,
                    tx_info: submission.tx_info.clone(),
                    fee_sat_kvb: submission.fee_sat_kvb,
                })
        })
    }));

    if let Some(aggregate_commit) = &status.aggregate_commit_tx {
        if let Ok(txid) = aggregate_commit.txid.parse::<Txid>() {
            txs.push(TxSenderMonitoredTx {
                txid,
                kind: MonitoredTxKind::Commit,
                tx_info: aggregate_commit.clone(),
                fee_sat_kvb: None,
            });
        }
    }

    txs.extend(status.reveals.iter().filter_map(|reveal| {
        if !matches!(reveal.kind, CommitRevealKind::Aggregate) {
            return None;
        }

        reveal.submission.as_ref().and_then(|submission| {
            submission
                .tx_info
                .txid
                .parse::<Txid>()
                .ok()
                .map(|txid| TxSenderMonitoredTx {
                    txid,
                    kind: MonitoredTxKind::Reveal,
                    tx_info: submission.tx_info.clone(),
                    fee_sat_kvb: submission.fee_sat_kvb,
                })
        })
    }));

    txs
}

async fn map_tx_sender_status(
    bitcoin_client: Arc<Client>,
    monitoring: Arc<MonitoringService>,
    tx: &TxSenderMonitoredTx,
) -> Option<MonitoringTxStatus> {
    if tx.tx_info.in_mempool {
        return Some(MonitoringTxStatus::InMempool {
            base_fee: tx
                .fee_sat_kvb
                .map(|fee_sat_kvb| fee_sat_kvb as f64 / 1000.0)
                .unwrap_or_default(),
            timestamp: 0,
            height: 0,
        });
    }

    let mined_at_height = u64::from(tx.tx_info.mined_at_height?);
    let block_hash = bitcoin_client.get_block_hash(mined_at_height).await.ok()?;
    let current_height = bitcoin_client.get_block_count().await.ok()?;
    let confirmations = current_height.saturating_sub(mined_at_height) + 1;

    if confirmations >= monitoring.finality_depth() {
        Some(MonitoringTxStatus::Finalized {
            block_hash,
            block_height: mined_at_height,
            confirmations,
        })
    } else {
        Some(MonitoringTxStatus::Confirmed {
            block_hash,
            block_height: mined_at_height,
            confirmations,
        })
    }
}

async fn sync_monitoring(
    bitcoin_client: Arc<Client>,
    monitoring: Arc<MonitoringService>,
    status: &CommitRevealStatus,
) {
    let mut monitored_txids = Vec::new();
    let mut previous_txid = None;

    for monitored_tx in tx_sender_monitored_txs(status) {
        let txid = monitored_tx.txid;
        let tx = match bitcoin_client.get_raw_transaction(&txid, None).await {
            Ok(tx) => tx,
            Err(_) => continue,
        };

        if monitoring.get_monitored_tx(&txid).await.is_none() {
            let prev_txid = match previous_txid {
                Some(prev_txid) if monitoring.get_monitored_tx(&prev_txid).await.is_some() => {
                    Some(prev_txid)
                }
                _ => None,
            };

            let result = monitoring
                .monitor_transaction(
                    TxWithId {
                        id: txid,
                        tx: tx.clone(),
                    },
                    prev_txid,
                    None,
                    monitored_tx.kind,
                )
                .await;

            match result {
                Ok(()) | Err(MonitorError::AlreadyMonitored) => {}
                Err(MonitorError::PrevTxNotMonitored(_)) => {
                    if let Err(err) = monitoring
                        .monitor_transaction(
                            TxWithId { id: txid, tx },
                            None,
                            None,
                            monitored_tx.kind,
                        )
                        .await
                    {
                        debug!(?err, %txid, "Skipping tx-sender monitoring sync");
                    }
                }
                Err(err) => {
                    debug!(?err, %txid, "Skipping tx-sender monitoring sync");
                }
            }
        }

        if let Some(prev_txid) = previous_txid {
            monitoring.set_next_tx(&prev_txid, txid).await;
        }

        if let Some(status) =
            map_tx_sender_status(bitcoin_client.clone(), monitoring.clone(), &monitored_tx).await
        {
            monitoring.set_tx_status(&txid, status).await;
        }

        monitored_txids.push(txid);
        previous_txid = Some(txid);
    }

    if let Err(err) = monitoring.update_txs_status(&monitored_txids).await {
        debug!(?err, "Failed to update tx-sender monitored tx statuses");
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use borsh::BorshDeserialize;
    use sov_rollup_interface::da::{
        BatchProofMethodId, BatchProofMethodIdBody, DaTxRequest, DataOnDa, SequencerCommitment,
    };
    use sov_rollup_interface::zk::Proof;
    use tx_sender_jsonrpc_client::{
        ActivationState, BitcoinTxStatus, CommitRevealKind, CommitRevealStatus, RevealStatus,
        TrackResponse, TrackStatus, TxStatus,
    };

    use super::*;

    fn btc_tx_status(txid: &str) -> BitcoinTxStatus {
        BitcoinTxStatus {
            txid: txid.to_string(),
            mined_at_height: Some(100),
            in_mempool: false,
        }
    }

    fn tx_status(txid: &str) -> TxStatus {
        TxStatus {
            status: TrackStatus::Finalized,
            activation: ActivationState::Active,
            tx_info: btc_tx_status(txid),
            fee_sat_kvb: None,
            fee_payer_txs: vec![],
            last_error: None,
        }
    }

    fn reveal_with_kind_and_submission(kind: CommitRevealKind, txid: &str) -> RevealStatus {
        RevealStatus {
            kind,
            submission: Some(tx_status(txid)),
        }
    }

    fn reveal_with_submission(txid: &str) -> RevealStatus {
        reveal_with_kind_and_submission(CommitRevealKind::Complete, txid)
    }

    fn reveal_without_submission() -> RevealStatus {
        RevealStatus {
            kind: CommitRevealKind::Chunk,
            submission: None,
        }
    }

    #[test]
    fn extract_txids_single_reveal() {
        // A valid 64-char hex txid (all zeros).
        let txid_hex = "0000000000000000000000000000000000000000000000000000000000000000";
        let status = CommitRevealStatus {
            status: TrackStatus::Finalized,
            commit_tx: None,
            reveals: vec![reveal_with_submission(txid_hex)],
            aggregate_commit_tx: None,
        };

        let txids = extract_txids_from_commit_reveal(&status);
        assert_eq!(txids.len(), 1);
        assert_eq!(txids[0], Txid::all_zeros());
    }

    #[test]
    fn extract_txids_multiple_reveals_with_commit() {
        let reveal_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let commit_txid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let status = CommitRevealStatus {
            status: TrackStatus::Finalized,
            commit_tx: Some(btc_tx_status(commit_txid)),
            reveals: vec![
                reveal_with_submission(reveal_txid),
                reveal_without_submission(), // no submission — should be skipped
            ],
            aggregate_commit_tx: None,
        };

        let txids = extract_txids_from_commit_reveal(&status);
        // reveal txid first, then commit txid
        assert_eq!(txids.len(), 2);
        assert_eq!(txids[0], reveal_txid.parse::<Txid>().unwrap());
        assert_eq!(txids[1], commit_txid.parse::<Txid>().unwrap());
    }

    #[test]
    fn extract_txids_with_aggregate_commit() {
        let reveal_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let agg_txid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let commit_txid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let status = CommitRevealStatus {
            status: TrackStatus::Finalized,
            commit_tx: Some(btc_tx_status(commit_txid)),
            reveals: vec![reveal_with_submission(reveal_txid)],
            aggregate_commit_tx: Some(btc_tx_status(agg_txid)),
        };

        let txids = extract_txids_from_commit_reveal(&status);
        // order: reveals, aggregate_commit, commit
        assert_eq!(txids.len(), 3);
        assert_eq!(txids[0], reveal_txid.parse::<Txid>().unwrap());
        assert_eq!(txids[1], agg_txid.parse::<Txid>().unwrap());
        assert_eq!(txids[2], commit_txid.parse::<Txid>().unwrap());
    }

    #[test]
    fn extract_txids_empty_reveals() {
        let status = CommitRevealStatus {
            status: TrackStatus::Finalized,
            commit_tx: None,
            reveals: vec![],
            aggregate_commit_tx: None,
        };

        let txids = extract_txids_from_commit_reveal(&status);
        assert!(txids.is_empty());
    }

    #[test]
    fn extract_txids_skips_invalid_txid_strings() {
        let status = CommitRevealStatus {
            status: TrackStatus::Finalized,
            commit_tx: Some(btc_tx_status("not-a-valid-txid")),
            reveals: vec![reveal_with_submission("also-invalid")],
            aggregate_commit_tx: None,
        };

        let txids = extract_txids_from_commit_reveal(&status);
        assert!(txids.is_empty());
    }

    #[test]
    fn extract_payload_txid_prefers_last_reveal_when_no_aggregate() {
        let first_reveal_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let last_reveal_txid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let commit_txid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let status = CommitRevealStatus {
            status: TrackStatus::Finalized,
            commit_tx: Some(btc_tx_status(commit_txid)),
            reveals: vec![
                reveal_with_submission(first_reveal_txid),
                reveal_with_submission(last_reveal_txid),
            ],
            aggregate_commit_tx: None,
        };

        let reveal_txid = extract_payload_txid_from_commit_reveal(&status).unwrap();
        assert_eq!(reveal_txid, last_reveal_txid.parse::<Txid>().unwrap());
    }

    #[test]
    fn extract_payload_txid_does_not_return_chunk_reveal_before_aggregate() {
        let chunk_reveal_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let commit_txid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let status = CommitRevealStatus {
            status: TrackStatus::InProgress,
            commit_tx: Some(btc_tx_status(commit_txid)),
            reveals: vec![reveal_with_kind_and_submission(
                CommitRevealKind::Chunk,
                chunk_reveal_txid,
            )],
            aggregate_commit_tx: None,
        };

        assert!(extract_payload_txid_from_commit_reveal(&status).is_none());
    }

    #[test]
    fn extract_payload_txid_prefers_aggregate_reveal_over_aggregate_commit() {
        let reveal_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let agg_txid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let commit_txid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let agg_reveal_txid = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let status = CommitRevealStatus {
            status: TrackStatus::Finalized,
            commit_tx: Some(btc_tx_status(commit_txid)),
            reveals: vec![
                reveal_with_submission(reveal_txid),
                reveal_with_kind_and_submission(CommitRevealKind::Aggregate, agg_reveal_txid),
            ],
            aggregate_commit_tx: Some(btc_tx_status(agg_txid)),
        };

        let reveal_txid = extract_payload_txid_from_commit_reveal(&status).unwrap();
        assert_eq!(reveal_txid, agg_reveal_txid.parse::<Txid>().unwrap());
    }

    #[test]
    fn extract_payload_txid_ignores_commit_only_status() {
        let commit_txid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let status = CommitRevealStatus {
            status: TrackStatus::Finalized,
            commit_tx: Some(btc_tx_status(commit_txid)),
            reveals: vec![],
            aggregate_commit_tx: None,
        };

        assert!(extract_payload_txid_from_commit_reveal(&status).is_none());
    }

    #[test]
    fn tx_sender_monitored_txs_orders_commit_reveals_and_aggregate_pair() {
        let commit_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let chunk_txid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let aggregate_commit_txid =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let aggregate_reveal_txid =
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let status = CommitRevealStatus {
            status: TrackStatus::InProgress,
            commit_tx: Some(btc_tx_status(commit_txid)),
            reveals: vec![
                reveal_with_kind_and_submission(CommitRevealKind::Aggregate, aggregate_reveal_txid),
                reveal_with_kind_and_submission(CommitRevealKind::Chunk, chunk_txid),
            ],
            aggregate_commit_tx: Some(btc_tx_status(aggregate_commit_txid)),
        };

        let txs = tx_sender_monitored_txs(&status)
            .into_iter()
            .map(|tx| (tx.txid, tx.kind))
            .collect::<Vec<_>>();
        let expected = vec![
            (
                commit_txid.parse::<Txid>().unwrap(),
                MonitoredTxKind::Commit,
            ),
            (chunk_txid.parse::<Txid>().unwrap(), MonitoredTxKind::Reveal),
            (
                aggregate_commit_txid.parse::<Txid>().unwrap(),
                MonitoredTxKind::Commit,
            ),
            (
                aggregate_reveal_txid.parse::<Txid>().unwrap(),
                MonitoredTxKind::Reveal,
            ),
        ];

        assert_eq!(txs, expected);
    }

    #[test]
    fn map_finalized_response() {
        let txid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let response = TrackResponse::CommitReveal(CommitRevealStatus {
            status: TrackStatus::Finalized,
            commit_tx: None,
            reveals: vec![reveal_with_submission(txid_hex)],
            aggregate_commit_tx: None,
        });

        let result = map_track_response(response, 42).unwrap();
        match result {
            TxSenderJobStatus::Completed { reveal_txid } => {
                assert_eq!(reveal_txid, txid_hex.parse::<Txid>().unwrap());
            }
            other => panic!("Expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn map_finalized_response_without_reveal_txid_is_error() {
        let response = TrackResponse::CommitReveal(CommitRevealStatus {
            status: TrackStatus::Finalized,
            commit_tx: Some(btc_tx_status(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )),
            reveals: vec![],
            aggregate_commit_tx: None,
        });

        let result = map_track_response(response, 42);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("without a reveal txid"));
    }

    #[test]
    fn map_cancelled_response() {
        let response = TrackResponse::CommitReveal(CommitRevealStatus {
            status: TrackStatus::Cancelled,
            commit_tx: None,
            reveals: vec![],
            aggregate_commit_tx: None,
        });

        let result = map_track_response(response, 99).unwrap();
        match result {
            TxSenderJobStatus::Failed { error } => {
                assert!(error.contains("99"));
                assert!(error.contains("cancelled"));
            }
            other => panic!("Expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn map_pending_response() {
        let response = TrackResponse::CommitReveal(CommitRevealStatus {
            status: TrackStatus::Pending,
            commit_tx: None,
            reveals: vec![],
            aggregate_commit_tx: None,
        });

        let result = map_track_response(response, 1).unwrap();
        assert!(matches!(result, TxSenderJobStatus::Pending));
    }

    #[test]
    fn map_in_progress_response() {
        let response = TrackResponse::CommitReveal(CommitRevealStatus {
            status: TrackStatus::InProgress,
            commit_tx: None,
            reveals: vec![],
            aggregate_commit_tx: None,
        });

        let result = map_track_response(response, 1).unwrap();
        assert!(matches!(result, TxSenderJobStatus::Processing));
    }

    #[test]
    fn map_mined_response() {
        let response = TrackResponse::CommitReveal(CommitRevealStatus {
            status: TrackStatus::Mined,
            commit_tx: None,
            reveals: vec![],
            aggregate_commit_tx: None,
        });

        let result = map_track_response(response, 1).unwrap();
        assert!(matches!(result, TxSenderJobStatus::Processing));
    }

    #[test]
    fn map_transaction_response_is_error() {
        let response = TrackResponse::Transaction(tx_status(
            "0000000000000000000000000000000000000000000000000000000000000000",
        ));

        let result = map_track_response(response, 7);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Expected CommitReveal"));
        assert!(err_msg.contains("7"));
    }

    #[test]
    fn resolve_wait_outcome_prefers_failure_over_existing_reveal_txid() {
        // A cancelled job (mapped to Failed) that still carries a reveal submission with
        // a txid must be reported as a failure, never as a successful DA submission.
        let reveal_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let raw_status = TrackResponse::CommitReveal(CommitRevealStatus {
            status: TrackStatus::Cancelled,
            commit_tx: None,
            reveals: vec![reveal_with_submission(reveal_txid)],
            aggregate_commit_tx: None,
        });
        let status = TxSenderJobStatus::Failed {
            error: "Commit-reveal job 1 was cancelled".to_string(),
        };

        match resolve_wait_outcome(&status, &raw_status) {
            Some(Err(error)) => assert!(error.contains("cancelled")),
            other => panic!("Expected Some(Err(..)), got {other:?}"),
        }
    }

    #[test]
    fn resolve_wait_outcome_returns_txid_when_in_progress() {
        let reveal_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let raw_status = TrackResponse::CommitReveal(CommitRevealStatus {
            status: TrackStatus::Mined,
            commit_tx: None,
            reveals: vec![reveal_with_submission(reveal_txid)],
            aggregate_commit_tx: None,
        });
        let status = TxSenderJobStatus::Processing;

        match resolve_wait_outcome(&status, &raw_status) {
            Some(Ok(txid)) => assert_eq!(txid, reveal_txid.parse::<Txid>().unwrap()),
            other => panic!("Expected Some(Ok(..)), got {other:?}"),
        }
    }

    #[test]
    fn resolve_wait_outcome_pending_without_txid_is_none() {
        let raw_status = TrackResponse::CommitReveal(CommitRevealStatus {
            status: TrackStatus::Pending,
            commit_tx: None,
            reveals: vec![],
            aggregate_commit_tx: None,
        });
        let status = TxSenderJobStatus::Pending;

        assert!(resolve_wait_outcome(&status, &raw_status).is_none());
    }

    #[test]
    fn to_citrea_tx_request_sequencer_commitment() {
        let commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 5,
            l2_end_block_number: 100,
        };
        let request = DaTxRequest::SequencerCommitment(commitment.clone());

        let result = to_citrea_tx_request(&request).unwrap();
        match result {
            CitreaTxRequest::SequencerCommitment(bytes) => {
                let decoded =
                    DataOnDa::try_from_slice(&bytes).expect("should deserialize as DataOnDa");
                match decoded {
                    DataOnDa::SequencerCommitment(c) => {
                        assert_eq!(c.merkle_root, commitment.merkle_root);
                        assert_eq!(c.index, commitment.index);
                        assert_eq!(c.l2_end_block_number, commitment.l2_end_block_number);
                    }
                    other => panic!("Expected SequencerCommitment, got {other:?}"),
                }
            }
            other => panic!("Expected CitreaTxRequest::SequencerCommitment, got {other:?}"),
        }
    }

    #[test]
    fn to_citrea_tx_request_zk_proof() {
        let proof: Proof = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let request = DaTxRequest::ZKProof(proof.clone());

        let result = to_citrea_tx_request(&request).unwrap();
        match result {
            CitreaTxRequest::BatchProof { bytes, chunk_size } => {
                assert!(chunk_size.is_none());
                let decompressed = citrea_primitives::compression::decompress_blob(&bytes)
                    .expect("should decompress");
                assert_eq!(decompressed, proof);
            }
            other => panic!("Expected CitreaTxRequest::BatchProof, got {other:?}"),
        }
    }

    #[test]
    fn to_citrea_tx_request_batch_proof_method_id() {
        let method_id = BatchProofMethodId {
            body: BatchProofMethodIdBody {
                method_id: [1, 2, 3, 4, 5, 6, 7, 8],
                activation_l2_height: 500,
                chain_id: 1,
            },
            signatures_with_index: [([0xAA; 64], 0), ([0xBB; 64], 1), ([0xCC; 64], 2)],
        };
        let request = DaTxRequest::BatchProofMethodId(method_id.clone());

        let result = to_citrea_tx_request(&request).unwrap();
        match result {
            CitreaTxRequest::BatchProofMethodId(bytes) => {
                let decoded =
                    DataOnDa::try_from_slice(&bytes).expect("should deserialize as DataOnDa");
                match decoded {
                    DataOnDa::BatchProofMethodId(m) => {
                        assert_eq!(m.body.method_id, method_id.body.method_id);
                        assert_eq!(
                            m.body.activation_l2_height,
                            method_id.body.activation_l2_height
                        );
                    }
                    other => panic!("Expected BatchProofMethodId, got {other:?}"),
                }
            }
            other => panic!("Expected CitreaTxRequest::BatchProofMethodId, got {other:?}"),
        }
    }
}

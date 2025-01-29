use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_primitives::U64;
use anyhow::anyhow;
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use metrics::Histogram;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_ledger_rpc::LedgerRpcClient;
use sov_rollup_interface::da::{BlockHeaderTrait, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::zk::Proof;
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::cache::L1BlockCache;
use crate::FullNodeConfig;

pub async fn sync_l1<Da>(
    last_scanned_l1_height: u64,
    da_service: Arc<Da>,
    sender: mpsc::Sender<Da::FilteredBlock>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    l1_block_scan_histogram: Histogram,
) where
    Da: DaService,
{
    let mut last_scanned_l1_height = last_scanned_l1_height;
    info!("Starting to sync from L1 height {}", last_scanned_l1_height);

    let start = Instant::now();

    loop {
        let last_finalized_l1_block_header =
            match da_service.get_last_finalized_block_header().await {
                Ok(header) => header,
                Err(e) => {
                    error!("Could not fetch last finalized L1 block header: {}", e);
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

        let new_l1_height = last_finalized_l1_block_header.height();

        for block_number in last_scanned_l1_height + 1..=new_l1_height {
            let l1_block =
                match get_da_block_at_height(&da_service, block_number, l1_block_cache.clone())
                    .await
                {
                    Ok(block) => block,
                    Err(e) => {
                        error!("Could not fetch last finalized L1 block: {}", e);
                        sleep(Duration::from_secs(2)).await;
                        // In case of a failure in fetching the L1 block, trigger the retry loop.
                        break;
                    }
                };

            if block_number > last_scanned_l1_height {
                if let Err(e) = sender.send(l1_block).await {
                    error!("Could not notify about L1 block: {}", e);
                    // We should not continue with the internal loop since we were not
                    // able to notify about the L1 block
                    break;
                }
                // If the send above does not succeed, we don't set new values
                // nor do we record any metrics.
                last_scanned_l1_height = block_number;
                l1_block_scan_histogram.record(
                    Instant::now()
                        .saturating_duration_since(start)
                        .as_secs_f64(),
                );
            }
        }

        sleep(Duration::from_secs(2)).await;
    }
}

pub async fn get_da_block_at_height<Da: DaService>(
    da_service: &Arc<Da>,
    height: u64,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
) -> anyhow::Result<Da::FilteredBlock> {
    if let Some(l1_block) = l1_block_cache.lock().await.get(&height) {
        return Ok(l1_block.clone());
    }
    let exponential_backoff = ExponentialBackoffBuilder::new()
        .with_initial_interval(Duration::from_secs(1))
        .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
        .build();

    let l1_block = retry_backoff(exponential_backoff.clone(), || async {
        da_service
            .get_block_at(height)
            .await
            .map_err(backoff::Error::transient)
    })
    .await
    .map_err(|e| anyhow!("Error while fetching L1 block: {}", e))?;
    l1_block_cache
        .lock()
        .await
        .put(l1_block.header().height(), l1_block.clone());
    Ok(l1_block)
}

pub fn extract_sequencer_commitments<Da>(
    da_service: Arc<Da>,
    l1_block: &Da::FilteredBlock,
    sequencer_da_pub_key: &[u8],
) -> Vec<SequencerCommitment>
where
    Da: DaService,
{
    let mut sequencer_commitments = da_service
        .as_ref()
        .extract_relevant_sequencer_commitments(l1_block, sequencer_da_pub_key)
        .inspect_err(|e| {
            warn!("Failed to get sequencer commitments: {e}");
        })
        .unwrap_or_default();

    // Make sure all sequencer commitments are stored in ascending order.
    // We sort before checking ranges to prevent substraction errors.
    sequencer_commitments.sort();

    sequencer_commitments
}

pub async fn extract_zk_proofs<Da: DaService>(
    da_service: Arc<Da>,
    l1_block: &Da::FilteredBlock,
    prover_da_pub_key: &[u8],
) -> anyhow::Result<Vec<Proof>> {
    da_service
        .extract_relevant_zk_proofs(l1_block, prover_da_pub_key)
        .await
}

pub async fn get_initial_slot_height(client: &HttpClient) -> u64 {
    loop {
        match client.get_soft_confirmation_by_number(U64::from(1)).await {
            Ok(Some(batch)) => return batch.da_slot_height,
            _ => {
                // sleep 1
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        }
    }
}

pub async fn get_start_l1_height<Da>(
    rollup_config: &FullNodeConfig<Da>,
    ledger_db: &LedgerDB,
) -> anyhow::Result<u64> {
    let last_scanned_l1_height = ledger_db.get_last_scanned_l1_height()?;

    let height = match last_scanned_l1_height {
        Some(height) => height.0,
        None => {
            let runner_config = rollup_config
                .runner
                .clone()
                .expect("Runner config should be set");
            let sequencer_client =
                HttpClientBuilder::default().build(runner_config.sequencer_client_url)?;
            get_initial_slot_height(&sequencer_client).await
        }
    };
    Ok(height)
}

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use sov_rollup_interface::da::{BlockHeaderTrait, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::zk::Proof;
use tokio::sync::Mutex;
use tracing::warn;

use crate::cache::L1BlockCache;

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

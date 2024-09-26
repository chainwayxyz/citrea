use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_rollup_interface::services::da::{DaService, SlotData};
use tokio::sync::Mutex;

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

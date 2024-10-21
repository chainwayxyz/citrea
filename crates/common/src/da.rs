use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use borsh::de::BorshDeserialize;
use sov_rollup_interface::da::{
    BlobReaderTrait, BlockHeaderTrait, DaDataBatchProof, DaDataLightClient, DaSpec,
    SequencerCommitment,
};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::zk::Proof;
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

pub fn extract_sequencer_commitments<Da>(
    da_service: Arc<Da>,
    l1_block: Da::FilteredBlock,
    sequencer_da_pub_key: &[u8],
) -> Vec<SequencerCommitment>
where
    Da: DaService,
{
    let mut da_data: Vec<<<Da as DaService>::Spec as DaSpec>::BlobTransaction> =
        da_service.extract_relevant_blobs(&l1_block);

    let mut sequencer_commitments = vec![];
    da_data.iter_mut().for_each(|tx| {
        let data = DaDataBatchProof::try_from_slice(tx.full_data());
        // Check for commitment
        if tx.sender().as_ref() == sequencer_da_pub_key {
            if let Ok(DaDataBatchProof::SequencerCommitment(seq_com)) = data {
                sequencer_commitments.push(seq_com);
            }
        }
    });

    // Make sure all sequencer commitments are stored in ascending order.
    // We sort before checking ranges to prevent substraction errors.
    sequencer_commitments.sort();

    sequencer_commitments
}

pub async fn extract_zk_proofs<Da: DaService>(
    da_service: Arc<Da>,
    l1_block: Da::FilteredBlock,
    prover_da_pub_key: &[u8],
) -> anyhow::Result<Vec<Proof>> {
    let mut zk_proofs = vec![];
    da_service
        .extract_relevant_proofs(&l1_block, prover_da_pub_key)
        .await?
        .into_iter()
        .for_each(|data| match data {
            DaDataLightClient::ZKProof(proof) => {
                zk_proofs.push(proof);
            }
        });

    Ok(zk_proofs)
}

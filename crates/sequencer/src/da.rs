use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use sov_modules_api::da::BlockHeaderTrait;
use sov_rollup_interface::services::da::DaService;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

/// Represents information about the current DA state.
///
/// Contains latest finalized block and fee rate.
pub(crate) type L1Data<Da> = (<Da as DaService>::FilteredBlock, u128);

pub(crate) async fn da_block_monitor<Da>(
    da_service: Arc<Da>,
    sender: mpsc::Sender<L1Data<Da>>,
    loop_interval: u64,
    cancellation_token: CancellationToken,
) where
    Da: DaService,
{
    loop {
        tokio::select! {
            biased;
            _ = cancellation_token.cancelled() => {
                return;
            }
            l1_data = get_da_block_data(da_service.clone()) => {
                let l1_data = match l1_data {
                    Ok(l1_data) => l1_data,
                    Err(e) => {
                        error!("Could not fetch L1 data, {}", e);
                        continue;
                    }
                };

                let _ = sender.send(l1_data).await;

                sleep(Duration::from_millis(loop_interval)).await;
            },
        }
    }
}

pub(crate) async fn get_da_block_data<Da>(da_service: Arc<Da>) -> anyhow::Result<L1Data<Da>>
where
    Da: DaService,
{
    let last_finalized_height = da_service
        .get_last_finalized_block_header()
        .await
        .map(|v| v.height())
        .map_err(|e| anyhow!("{:?}", e))?;

    let last_finalized_block = da_service
        .get_block_at(last_finalized_height)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    debug!(
        "Sequencer: last finalized L1 height: {:?}",
        last_finalized_height
    );

    let l1_fee_rate = da_service
        .get_fee_rate()
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    Ok((last_finalized_block, l1_fee_rate))
}

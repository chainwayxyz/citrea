use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use reth_tasks::shutdown::GracefulShutdown;
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::SlotData;
use sov_rollup_interface::services::da::DaService;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, instrument};

/// Represents latest finalized block.
pub(crate) type DaBlockData<Da> = <Da as DaService>::FilteredBlock;

/// Run a DA block monitor which sends L1 data signals
/// when a new L1 block is detected.
#[instrument(name = "L1BlockMonitor", skip_all)]
pub(crate) async fn da_block_monitor<Da>(
    da_service: Arc<Da>,
    sender: mpsc::Sender<DaBlockData<Da>>,
    loop_interval: u64,
    mut shutdown_signal: GracefulShutdown,
) where
    Da: DaService,
{
    let mut last_block_hash: Option<[u8; 32]> = None;
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown_signal => {
                return;
            }
            block = get_finalized_block(da_service.clone()) => {
                match block {
                    Ok(block) => {
                        let block_hash = block.hash();
                        if last_block_hash.as_ref() != Some(&block_hash) {
                            last_block_hash = Some(block_hash);
                            let _ = sender.send(block).await;
                        }
                    },
                    Err(e) => error!("Could not fetch L1 block, {e}")
                }
                sleep(Duration::from_millis(loop_interval)).await;
            },
        }
    }
}

/// Run a fee rate monitor which sends L1 fee rate signals periodically.
#[instrument(name = "FeeRateMonitor", skip_all)]
pub(crate) async fn fee_rate_monitor<Da>(
    da_service: Arc<Da>,
    sender: mpsc::Sender<u128>,
    loop_interval: u64,
    mut shutdown_signal: GracefulShutdown,
) where
    Da: DaService,
{
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown_signal => {
                return;
            }
            _ = async {
                match da_service.get_fee_rate().await {
                    Ok(rate) => {
                        let _ = sender.send(rate).await;
                    },
                    Err(e) => error!("Could not fetch fee rate: {e:?}")
                }
                sleep(Duration::from_millis(loop_interval)).await;
            } => {},
        }
    }
}

/// Fetch the finalized L1 block
pub(crate) async fn get_finalized_block<Da>(
    da_service: Arc<Da>,
) -> anyhow::Result<Da::FilteredBlock>
where
    Da: DaService,
{
    let last_finalized_height = da_service
        .get_last_finalized_block_header()
        .await
        .map(|v| v.height())
        .map_err(|e| anyhow!("{e:?}"))?;

    debug!("Sequencer: last finalized L1 height: {last_finalized_height:?}",);

    da_service
        .get_block_at(last_finalized_height)
        .await
        .map_err(|e| anyhow!("{e:?}"))
}

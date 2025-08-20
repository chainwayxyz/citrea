use std::sync::Arc;

use alloy_primitives::U64;
use anyhow::{bail, Context as _};
use backoff::exponential::ExponentialBackoffBuilder;
use backoff::future::retry as retry_backoff;
use citrea_primitives::merkle::compute_tx_hashes;
use citrea_primitives::types::L2BlockHash;
use citrea_stf::runtime::CitreaRuntime;
use jsonrpsee::core::client::Error as JsonrpseeError;
use jsonrpsee::http_client::HttpClient;
use sov_db::ledger_db::SharedLedgerOps;
use sov_keys::default_signature::K256PublicKey;
use sov_ledger_rpc::LedgerRpcClient;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{L2Block, StateDiff};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::rpc::block::L2BlockResponse;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::StorageRootHash;
use sov_state::storage::NativeStorage;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

use crate::utils::decode_sov_tx_and_update_short_header_proofs;

/// Result from applying an L2 block before committing
pub struct AppliedL2Block {
    pub l2_height: u64,
    pub l2_block: L2Block,
    pub state_diff: StateDiff,
    pub state_root: StorageRootHash,
    pub tx_hashes: Vec<[u8; 32]>,
    pub tx_bodies: Option<Vec<Vec<u8>>>,
    pub block_size: usize,
}

enum SyncError {
    ResponseOverLimit,
    Call(String),
    Connection(String),
    Unknown(String),
}

/// Apply an L2 block and return intermediate results before committing
/// This is the first step of processing an L2 block
#[allow(clippy::too_many_arguments)]
pub async fn apply_l2_block<Da: DaService, DB: SharedLedgerOps>(
    l2_block_response: &L2BlockResponse,
    storage_manager: &ProverStorageManager,
    fork_manager: &mut ForkManager<'_>,
    da_service: Arc<Da>,
    ledger_db: &DB,
    stf: &mut StfBlueprint<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>,
    current_l2_block_hash: L2BlockHash,
    current_state_root: StorageRootHash,
    sequencer_pub_key: &K256PublicKey,
    include_tx_body: bool,
) -> anyhow::Result<AppliedL2Block> {
    let l2_height = l2_block_response.header.height.to();

    info!(
        "Running l2 block batch #{} with hash: 0x{}",
        l2_height,
        hex::encode(l2_block_response.header.hash),
    );

    if current_l2_block_hash != l2_block_response.header.prev_hash {
        bail!("Previous hash mismatch at height: {}", l2_height);
    }

    let pre_state = storage_manager.create_storage_for_next_l2_height();
    assert_eq!(
        pre_state.version(),
        l2_height,
        "Prover storage version is corrupted"
    );
    let tx_bodies = Some(
        l2_block_response
            .txs
            .clone()
            .into_iter()
            .map(|tx| tx.tx)
            .collect::<Vec<_>>(),
    );

    // Register this new block with the fork manager to active
    // the new fork on the next block.
    fork_manager.register_block(l2_height)?;
    let current_spec = fork_manager.active_fork().spec_id;

    let l2_block: L2Block = l2_block_response
        .clone()
        .try_into()
        .context("Failed to parse transactions")?;

    let block_size = l2_block.calculate_size();

    let l2_block_result = {
        // Post tangerine, we do not have the slot hash in l2 blocks we inspect the txs and get the slot hashes from set block infos
        // Then store the short header proofs of those blocks in the ledger db

        decode_sov_tx_and_update_short_header_proofs(l2_block_response, ledger_db, da_service)
            .await?;

        stf.apply_l2_block(
            current_spec,
            sequencer_pub_key,
            &current_state_root,
            pre_state,
            None,
            None,
            Default::default(),
            Default::default(),
            &l2_block,
        )?
    };

    let next_state_root = l2_block_result.state_root_transition.final_root;
    // Check if post state root is the same as the one in the l2 block
    if next_state_root.as_ref().to_vec() != l2_block.state_root() {
        bail!("Post state root mismatch at height: {}", l2_height)
    }

    storage_manager.finalize_storage(l2_block_result.change_set);

    let tx_hashes = compute_tx_hashes(&l2_block.txs, current_spec);
    let tx_bodies = if include_tx_body { tx_bodies } else { None };

    info!(
        "New State Root after l2 block #{} is: 0x{}",
        l2_height,
        hex::encode(next_state_root)
    );

    Ok(AppliedL2Block {
        l2_height,
        l2_block,
        state_diff: l2_block_result.state_diff,
        state_root: next_state_root,
        tx_hashes,
        tx_bodies,
        block_size,
    })
}

/// Commit an L2 block to the ledger database
/// This is the second step of processing an L2 block
pub fn commit_l2_block<DB: SharedLedgerOps>(
    ledger_db: &DB,
    applied: AppliedL2Block,
) -> anyhow::Result<()> {
    ledger_db.commit_l2_block(applied.l2_block, applied.tx_hashes, applied.tx_bodies)?;
    Ok(())
}

pub async fn sync_l2(
    mut start_l2_height: u64,
    sequencer_client: HttpClient,
    sender: mpsc::Sender<Vec<L2BlockResponse>>,
    sync_blocks_count: u64,
) {
    let mut current_sync_blocks_count = sync_blocks_count;

    info!("Starting to sync from L2 height {}", start_l2_height);
    loop {
        let end_l2_height = start_l2_height + current_sync_blocks_count - 1;

        let inner_client = &sequencer_client;
        let mut l2_blocks = match get_l2_blocks_range(inner_client, start_l2_height, end_l2_height)
            .await
        {
            Ok(l2_blocks) => {
                // request has succeeded, try to increase sync blocks back up until original
                current_sync_blocks_count *= 2;
                if current_sync_blocks_count > sync_blocks_count {
                    current_sync_blocks_count = sync_blocks_count;
                }
                l2_blocks
            }
            Err(e) => match e {
                SyncError::ResponseOverLimit => {
                    debug!("Sync response size over limit, retrying...");
                    current_sync_blocks_count /= 2;
                    if current_sync_blocks_count == 1 {
                        warn!("Very slow sync at 1 block/s");
                    } else if current_sync_blocks_count == 0 {
                        error!("L2 blocks are getting too big. It is recommended to increase response size");
                        // Stop the sync since we cannot fetch new soft confirmations.
                        return;
                    }
                    continue;
                }
                SyncError::Connection(e) => {
                    error!("L2 sync: RPC connection error: {:?}", e);
                    continue;
                }
                SyncError::Call(e) => {
                    error!("L2 sync: RPC call error: {:?}", e);
                    continue;
                }
                SyncError::Unknown(e) => {
                    error!("L2 sync: RPC unknown error: {:?}", e);
                    continue;
                }
            },
        };

        if l2_blocks.is_empty() {
            debug!(
                "L2 block: no batch at starting height {}, retrying...",
                start_l2_height
            );

            sleep(Duration::from_secs(1)).await;
            continue;
        }

        start_l2_height += l2_blocks.len() as u64;

        // Make sure L2 blocks are sorted for us to make sure they are processed
        // in the correct order.
        l2_blocks.sort_by_key(|l2_block| l2_block.header.height);

        if let Err(e) = sender.send(l2_blocks).await {
            error!("Could not notify about L2 block: {}", e);
        }
    }
}

async fn get_l2_blocks_range(
    sequencer_client: &HttpClient,
    start_l2_height: u64,
    end_l2_height: u64,
) -> Result<Vec<L2BlockResponse>, SyncError> {
    let inner_client = &sequencer_client;

    let exponential_backoff = ExponentialBackoffBuilder::<backoff::SystemClock>::new()
        .with_initial_interval(Duration::from_secs(1))
        .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
        .with_multiplier(1.5)
        .build();

    retry_backoff(exponential_backoff, || async move {
        let l2_blocks = inner_client
            .get_l2_block_range(U64::from(start_l2_height), U64::from(end_l2_height))
            .await;
        match l2_blocks {
            Ok(l2_blocks) => Ok(l2_blocks.into_iter().flatten().collect::<Vec<_>>()),
            Err(e) => match e {
                JsonrpseeError::Call(e) => {
                    if e.message().eq("Response is too big") {
                        return Err(backoff::Error::Permanent(SyncError::ResponseOverLimit));
                    }
                    let error_msg = format!("L2 block: call error during RPC call: {:?}", e);
                    error!(error_msg);
                    Err(backoff::Error::Transient {
                        err: SyncError::Call(error_msg),
                        retry_after: None,
                    })
                }
                JsonrpseeError::Transport(e) => {
                    let error_msg = format!("L2 block: connection error during RPC call: {:?}", e);
                    error!(error_msg);
                    Err(backoff::Error::Transient {
                        err: SyncError::Connection(error_msg),
                        retry_after: None,
                    })
                }
                _ => Err(backoff::Error::Transient {
                    err: SyncError::Unknown(format!(
                        "L2 block: unknown error from RPC call: {:?}",
                        e
                    )),
                    retry_after: None,
                }),
            },
        }
    })
    .await
}

use std::sync::Arc;
use std::time::Instant;

use alloy_primitives::U64;
use anyhow::{bail, Context as _};
use backoff::exponential::ExponentialBackoffBuilder;
use backoff::future::retry as retry_backoff;
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
use tracing::{debug, error, info};

use crate::utils::{compute_tx_hashes, decode_sov_tx_and_update_short_header_proofs};

pub struct ProcessL2BlockResult {
    pub l2_height: u64,
    pub l2_block_hash: L2BlockHash,
    pub state_root: StorageRootHash,
    pub state_diff: StateDiff,
    pub process_duration: f64,
}

pub async fn process_l2_block<Da: DaService, DB: SharedLedgerOps>(
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
) -> anyhow::Result<ProcessL2BlockResult> {
    let start = Instant::now();

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

    let l2_block_result = {
        // Since Post fork2 we do not have the slot hash in l2 blocks we inspect the txs and get the slot hashes from set block infos

        // Then store the short header proofs of those blocks in the ledger db

        decode_sov_tx_and_update_short_header_proofs(l2_block_response, ledger_db, da_service)
            .await?;

        stf.apply_l2_block(
            current_spec,
            &sequencer_pub_key,
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

    let tx_hashes = compute_tx_hashes::<DefaultContext>(&l2_block.txs, current_spec);
    let tx_bodies = if include_tx_body { tx_bodies } else { None };

    ledger_db.commit_l2_block(l2_block, tx_hashes, tx_bodies)?;

    // TODO: https://github.com/chainwayxyz/citrea/issues/1992
    // self.ledger_db.extend_l2_range_of_l1_slot(
    //     SlotNumber(current_l1_block.header().height()),
    //     L2BlockNumber(l2_height),
    // )?;

    info!(
        "New State Root after l2 block #{} is: 0x{}",
        l2_height,
        hex::encode(next_state_root)
    );

    let duration = Instant::now()
        .saturating_duration_since(start)
        .as_secs_f64();

    Ok(ProcessL2BlockResult {
        l2_height,
        l2_block_hash: l2_block_response.header.hash,
        state_root: next_state_root,
        state_diff: l2_block_result.state_diff,
        process_duration: duration,
    })
}

pub async fn sync_l2(
    start_l2_height: u64,
    sequencer_client: HttpClient,
    sender: mpsc::Sender<Vec<L2BlockResponse>>,
    sync_blocks_count: u64,
) {
    let mut l2_height = start_l2_height;
    info!("Starting to sync from L2 height {}", l2_height);
    loop {
        let exponential_backoff = ExponentialBackoffBuilder::<backoff::SystemClock>::new()
            .with_initial_interval(Duration::from_secs(1))
            .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
            .with_multiplier(1.5)
            .build();

        let inner_client = &sequencer_client;
        let mut l2_blocks = match retry_backoff(exponential_backoff, || async move {
            let l2_blocks = inner_client
                .get_l2_block_range(
                    U64::from(l2_height),
                    U64::from(l2_height + sync_blocks_count - 1),
                )
                .await;
            match l2_blocks {
                Ok(l2_blocks) => Ok(l2_blocks.into_iter().flatten().collect::<Vec<_>>()),
                Err(e) => match e {
                    JsonrpseeError::Transport(e) => {
                        let error_msg =
                            format!("L2 Block: connection error during RPC call: {:?}", e);
                        debug!(error_msg);
                        Err(backoff::Error::Transient {
                            err: error_msg,
                            retry_after: None,
                        })
                    }
                    _ => Err(backoff::Error::Transient {
                        err: format!("L2 Block: unknown error from RPC call: {:?}", e),
                        retry_after: None,
                    }),
                },
            }
        })
        .await
        {
            Ok(l2_blocks) => l2_blocks,
            Err(_) => {
                continue;
            }
        };

        if l2_blocks.is_empty() {
            debug!(
                "L2 Block: no batch at starting height {}, retrying...",
                l2_height
            );

            sleep(Duration::from_secs(1)).await;
            continue;
        }

        l2_height += l2_blocks.len() as u64;

        // Make sure l2 blocks are sorted for us to make sure they are processed
        // in the correct order.
        l2_blocks.sort_by_key(|l2_block| l2_block.header.height);

        if let Err(e) = sender.send(l2_blocks).await {
            error!("Could not notify about L2 block: {}", e);
        }
    }
}

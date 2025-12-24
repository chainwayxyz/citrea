use std::collections::HashMap;
use std::time::Duration;

use citrea_network::types::{NetworkRequest, StatusResponse};
use libp2p::PeerId;
use sov_db::ledger_db::SharedLedgerOps;
use tokio::select;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

const HEAD_BLOCK_MARGIN: u64 = 5;

pub struct DownloadInfo {
    pub peer_id: PeerId,
    pub start: u64,
    pub end: u64,
}

pub enum BatchProcessingError {
    DownloadFailed,
    ValidationError,
}

pub(crate) enum SyncManagerMessage {
    // P2P-TODO: add gossip block to update known head
    // so that we can prune some peers that are not useful
    // we may also remove ledger db import and just rely on messages from l2 syncer
    // or implement a threshold where we dont download blocks if we are close to head of the peer
    NewPeer(PeerId),
    DisconnectedPeer(PeerId),
    PeerStatus((PeerId, StatusResponse)),
    BatchProcessed(DownloadInfo, Result<(), BatchProcessingError>),
}

enum DownloadState {
    Idle,
    Syncing(DownloadInfo),
}

pub(crate) struct SyncManager<DB>
where
    DB: SharedLedgerOps + Clone,
{
    ledger_db: DB,
    event_rx: mpsc::Receiver<SyncManagerMessage>,
    network_tx: mpsc::Sender<NetworkRequest>,
    peer_states: HashMap<PeerId, Option<StatusResponse>>,
    sync_blocks_count: u64,
    status_interval: Duration,
    sync_interval: Duration,
    download_state: DownloadState,
}

impl<DB> SyncManager<DB>
where
    DB: SharedLedgerOps + Clone,
{
    pub fn new(
        ledger_db: DB,
        event_rx: mpsc::Receiver<SyncManagerMessage>,
        network_tx: mpsc::Sender<NetworkRequest>,
        sync_blocks_count: u64,
        status_interval: Duration,
        sync_interval: Duration,
    ) -> Self {
        Self {
            ledger_db,
            event_rx,
            network_tx,
            peer_states: HashMap::new(),
            sync_blocks_count,
            status_interval,
            sync_interval,
            download_state: DownloadState::Idle,
        }
    }

    pub async fn run(mut self) {
        let mut status_interval = tokio::time::interval(self.status_interval);
        let mut sync_interval = tokio::time::interval(self.sync_interval);

        loop {
            select! {
                Some(event) = self.event_rx.recv() => {
                    self.on_sync_manager_event(event).await;
                }
                _ = status_interval.tick() => {
                    for peer_id in self.peer_states.keys() {
                        let request = NetworkRequest::GetPeerStatus(*peer_id);
                        self.send_network_message(request).await;
                        debug!("Requested status from peer {}", peer_id);
                    }
                }
                _ = sync_interval.tick() => {
                    if let DownloadState::Idle = self.download_state {
                        if let Err(e) = self.download_from_best_peer().await {
                            error!("Failed to download from best peer: {}", e);
                        }
                    }
                }
            }
        }
    }

    async fn on_sync_manager_event(&mut self, event: SyncManagerMessage) {
        match event {
            SyncManagerMessage::BatchProcessed(download_info, result) => {
                let DownloadState::Syncing(ds_info) = &self.download_state else {
                    unreachable!("Received BatchProcessed while not downloading");
                };
                assert_eq!(ds_info.peer_id, download_info.peer_id);
                assert_eq!(ds_info.start, download_info.start);
                // Set download state to idle regardless of success or failure
                self.download_state = DownloadState::Idle;
                if let Err(e) = result {
                    self.on_batch_processing_error(download_info.peer_id, e)
                        .await;
                } else {
                    debug!(
                        "Successfully processed L2 blocks {}-{} from peer {}",
                        download_info.start, download_info.end, download_info.peer_id
                    );
                    if let Err(e) = self.download_from_best_peer().await {
                        error!("Failed to download from best peer: {}", e);
                    }
                }
            }
            SyncManagerMessage::NewPeer(peer_id) => {
                self.peer_states.insert(peer_id, None);
            }
            SyncManagerMessage::DisconnectedPeer(peer_id) => {
                // even if downloading from this peer,
                // not resetting the download state here,
                // expecting BatchProcessed to handle it
                self.peer_states.remove(&peer_id);
            }
            SyncManagerMessage::PeerStatus((peer_id, status)) => {
                self.peer_states.insert(peer_id, Some(status));
            }
        }
    }

    async fn download_from_best_peer(&mut self) -> anyhow::Result<()> {
        let head_block = self.ledger_db.get_head_l2_block_height()?.unwrap_or(0);
        // P2P-TODO: handle pruned blocks

        // filter peers such that:
        // - have status
        // - has tx bodies
        // - have head block + HEAD_BLOCK_MARGIN > local head block
        // - last pruned block <= local head height

        let best_peer = self
            .peer_states
            .iter()
            .filter_map(|(peer_id, status_opt)| {
                status_opt.as_ref().map(|status| (*peer_id, status))
            })
            .filter(|(_, status)| status.has_tx_bodies)
            .filter(|(_, status)| status.head_block + HEAD_BLOCK_MARGIN > head_block)
            .filter(|(_, status)| {
                status
                    .last_pruned_block
                    .is_none_or(|pruned_height| pruned_height <= head_block)
            })
            .max_by_key(|(_, status)| status.head_block);

        let Some((peer_id, _)) = best_peer else {
            warn!("No suitable peer found for downloading L2 blocks");
            // P2P-TODO: slash some peers here
            // may be started with peers that don't have tx bodies
            return Ok(());
        };
        let start = head_block + 1;
        let end = start + self.sync_blocks_count - 1;
        // P2P-TODO: dynamically change sync blocks count if there is response errors
        let request = NetworkRequest::GetL2BlockRange {
            peer_id,
            start,
            end,
        };
        self.send_network_message(request).await;
        self.download_state = DownloadState::Syncing(DownloadInfo {
            peer_id,
            start,
            end,
        });
        Ok(())
    }

    async fn send_network_message(&self, request: NetworkRequest) {
        self.network_tx
            .send(request)
            .await
            .expect("Network channel closed");
    }

    async fn on_batch_processing_error(&mut self, peer_id: PeerId, error: BatchProcessingError) {
        match error {
            BatchProcessingError::DownloadFailed => {
                warn!("Download failed from peer {peer_id}");
                // P2P-TODO: slash peer or reduce trust score
            }
            BatchProcessingError::ValidationError => {
                warn!("Validation error when downloading from peer {peer_id}");
                // P2P-TODO: slash peer or reduce trust score
            }
        }
    }
}

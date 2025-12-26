use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use citrea_common::NetworkConfig;
use reth_tasks::shutdown::GracefulShutdown;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_rollup_interface::rpc::block::L2BlockResponse;
use sov_rollup_interface::rpc::LedgerRpcProvider;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::peer_manager::{HeartbeatResult, PeerManager, ReportPeerResult};
use crate::types::{
    BlocksByRangeRequest, Eth2Request, Eth2Response, L2SyncMessage, NetworkEvent, NetworkRequest,
    PeerStatus, SCORE_HALFLIFE,
};
use crate::{Network, NetworkGlobals};

// Peer Manager Heartbeat interval
pub const PM_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

pub struct NetworkService {
    network: Network,
    network_globals: Arc<NetworkGlobals>,
    peer_manager: PeerManager,
    ledger_db: LedgerDB,
    request_rx: mpsc::Receiver<NetworkRequest>,
    l2_sync_tx: Option<mpsc::Sender<L2SyncMessage>>,
    has_tx_bodies: bool,
}

impl NetworkService {
    pub fn build(
        network_config: NetworkConfig,
        network_globals: Arc<NetworkGlobals>,
        ledger_db: LedgerDB,
        request_rx: mpsc::Receiver<NetworkRequest>,
        l2_sync_tx: Option<mpsc::Sender<L2SyncMessage>>,
        has_tx_bodies: bool,
    ) -> Result<Self> {
        let target_peers = network_config.target_peers;
        let network = Network::build(network_config).context("Failed to build network")?;
        let peer_manager = PeerManager::new(network_globals.clone(), target_peers, SCORE_HALFLIFE);
        Ok(Self {
            network,
            network_globals,
            ledger_db,
            request_rx,
            l2_sync_tx,
            has_tx_bodies,
            peer_manager,
        })
    }

    pub async fn run(mut self, mut shutdown_signal: GracefulShutdown) {
        // P2P-TODO: parameterize channel size
        let (response_tx, mut response_rx) = mpsc::channel(100);
        let mut pm_heartbeat = tokio::time::interval(PM_HEARTBEAT_INTERVAL);
        loop {
            tokio::select! {
                Some(request) = self.request_rx.recv() => self.on_network_request(request).await,
                network_event = self.network.next_event() => {
                    let event = network_event.expect("Failed to get network event");
                    match event {
                        NetworkEvent::RequestReceived { request_id, request } => {
                            let ledger_db = self.ledger_db.clone();
                            let tx = response_tx.clone();
                            // don't block the event loop
                            tokio::spawn(async move {
                                let result = Self::on_inbound_request(&ledger_db, request, self.has_tx_bodies);
                                let _ = tx.send((request_id, result)).await;
                            });
                        }
                        NetworkEvent::ResponseReceived { peer_id, response } => {
                            if let Err(e) = self.on_response_received(peer_id, response).await {
                                error!("Error handling response from peer {peer_id}: {e:?}");
                            }
                        }
                        NetworkEvent::GossipBlock { peer_id, l2_block_response, message_id } => {
                            let message = L2SyncMessage::GossipBlock(peer_id, l2_block_response, message_id);
                            send_l2_sync_message(self.l2_sync_tx.clone(), message);
                        }
                        NetworkEvent::RPCFailed { peer_id, request } => {
                            error!("RPC request {:?} to peer {} failed", request, peer_id);
                            let message = L2SyncMessage::RPCFailed(peer_id, request);
                            send_l2_sync_message(self.l2_sync_tx.clone(), message);
                        }
                    }
                }
                Some((request_id, result)) = response_rx.recv() => {
                    match result {
                        // P2P-TODO: propagate the error to the caller peer
                        Ok(response) => {
                            if let Err(e) = self.network.send_rpc_response(request_id, response) {
                                error!("Error sending RPC response: {e:?}");
                            }
                        }
                        Err(e) => {
                            error!("Error handling incoming RPC request: {e:?}");
                        }
                    }
                }
                _ = pm_heartbeat.tick() => self.on_pm_heartbeat_tick().await,
                _ = &mut shutdown_signal => {
                    info!("Shutting down NetworkService");
                    return;
                }
            }
        }
    }

    async fn on_network_request(&mut self, request: NetworkRequest) {
        match request {
            NetworkRequest::PublishMessage { topic, message } => {
                self.network.publish_message(&topic, message);
            }
            // P2P-TODO: add rpc endpoint for these
            NetworkRequest::AddPeer(_peer_id) => {
                unimplemented!();
            }
            NetworkRequest::RemovePeer(_peer_id) => {
                unimplemented!();
            }
            NetworkRequest::GetL2BlockRange {
                peer_id,
                start,
                end,
            } => {
                self.network.send_rpc_request(
                    peer_id,
                    Eth2Request::BlocksByRange(BlocksByRangeRequest { start, end }),
                );
            }
            // P2P-TODO: add slashing
            NetworkRequest::ReportPeer(peer_id, action) => {
                match self.peer_manager.report_peer(&peer_id, action).await {
                    ReportPeerResult::Ban => {
                        info!("Peer {} has been banned by PeerManager", peer_id);
                        self.network.disconnect_peer(&peer_id);
                    }
                    ReportPeerResult::NoAction => {}
                }
            }
            NetworkRequest::GetPeerStatus(peer_id) => {
                self.network.send_rpc_request(peer_id, Eth2Request::Status);
            }
            NetworkRequest::GossipBlockValidationResult {
                peer_id,
                message_id,
                validation_result,
            } => {
                self.network.report_message_validation_result(
                    &peer_id,
                    message_id,
                    validation_result,
                );
            }
        }
    }

    fn on_inbound_request(
        ledger_db: &LedgerDB,
        request: Eth2Request,
        has_tx_bodies: bool,
    ) -> Result<Eth2Response> {
        match request {
            Eth2Request::Status => {
                // Handle status request
                let last_pruned_block = ledger_db.get_last_pruned_l2_height()?;
                let head_block = LedgerRpcProvider::get_head_l2_block_height(ledger_db)?;
                Ok(Eth2Response::Status(PeerStatus {
                    head_block,
                    last_pruned_block,
                    has_tx_bodies,
                }))
            }
            Eth2Request::BlocksByRange(blocks_request) => {
                let blocks =
                    l2_blocks_by_range(ledger_db, blocks_request.start, blocks_request.end)?;
                Ok(Eth2Response::BlocksByRange(blocks))
            }
        }
    }

    async fn on_response_received(
        &self,
        peer_id: libp2p::PeerId,
        response: Eth2Response,
    ) -> anyhow::Result<()> {
        match response {
            Eth2Response::Status(status) => {
                info!("Received status from peer {}: {:?}", peer_id, status);
                self
                    .network_globals.peers
                    .write()
                    .await
                    // update or insert peer status
                    .get_mut(&peer_id)
                    .map(|peers| {
                        peers.status = Some(status);
                    });
                Ok(())
            }
            Eth2Response::BlocksByRange(blocks) => {
                info!("Received {} blocks from peer {}", blocks.len(), peer_id);
                let message = L2SyncMessage::BlockBatch(peer_id, blocks);
                send_l2_sync_message(self.l2_sync_tx.clone(), message);
                Ok(())
            }
        }
        }

    async fn on_pm_heartbeat_tick(&mut self) {
        match self.peer_manager.heartbeat().await {
            HeartbeatResult::WantedPeers(wanted) => {
                // P2P-TODO: request from discovery
                info!("PeerManager requests {} more peers", wanted);
            }
            HeartbeatResult::ExcessPeers(excess_peers) => {
                info!("PeerManager suggests dropping {} excess peers", excess_peers.len());
                for peer_id in excess_peers {
                    self.network.disconnect_peer(&peer_id);
                }
            }
            HeartbeatResult::NoAction => {},
        }
    }
}

// P2P-TODO: Fix error/response type
pub fn l2_blocks_by_range(
    ledger_db: &LedgerDB,
    start: u64,
    end: u64,
) -> Result<Vec<L2BlockResponse>> {
    if end < start {
        return Err(anyhow::anyhow!("Invalid range"));
    }
    let diff = end - start;

    // P2P-TODO: Make this configurable
    if diff > 1000 {
        return Err(anyhow::anyhow!(
            "Requested block range too large. Max range is 1000 blocks"
        ));
    }

    let head_block = LedgerRpcProvider::get_head_l2_block_height(ledger_db)?;
    let end = end.min(head_block);

    // P2P-TODO: check if start > pruned && end <= head
    // return error
    ledger_db
        .get_l2_blocks_range(start, end)?
        .into_iter()
        .map(|block_opt| block_opt.ok_or_else(|| anyhow::anyhow!("Block not found")))
        .collect()
}


fn send_l2_sync_message(l2_sync_tx: Option<mpsc::Sender<L2SyncMessage>>, message: L2SyncMessage) {
    if let Some(l2_sync_tx) = l2_sync_tx {
        tokio::spawn(async move {
            if let Err(e) = l2_sync_tx.send(message).await {
                error!("Failed to send L2 sync message: {:?}", e);
            }
        });
    }
}
use anyhow::{Context, Result};
use citrea_common::NetworkConfig;
use reth_tasks::shutdown::GracefulShutdown;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_rollup_interface::rpc::block::L2BlockResponse;
use sov_rollup_interface::rpc::LedgerRpcProvider;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::types::{
    BlocksByRangeRequest, Eth2Request, Eth2Response, L2SyncMessage, NetworkEvent, NetworkRequest,
    StatusResponse,
};
use crate::Network;

pub struct NetworkService {
    network: Network,
    ledger_db: LedgerDB,
    request_rx: mpsc::Receiver<NetworkRequest>,
    l2_sync_tx: Option<mpsc::Sender<L2SyncMessage>>,
}

impl NetworkService {
    pub fn build(
        network_config: NetworkConfig,
        ledger_db: LedgerDB,
        request_rx: mpsc::Receiver<NetworkRequest>,
        l2_sync_tx: Option<mpsc::Sender<L2SyncMessage>>,
    ) -> Result<Self> {
        let network = Network::build(network_config).context("Failed to build network")?;
        Ok(Self {
            network,
            ledger_db,
            request_rx,
            l2_sync_tx,
        })
    }

    pub async fn run(mut self, mut shutdown_signal: GracefulShutdown) {
        // P2P-TODO: parameterize channel size
        let (response_tx, mut response_rx) = mpsc::channel(100);
        loop {
            tokio::select! {
                Some(request) = self.request_rx.recv() => {
                    self.on_network_request(request);
                }
                network_event = self.network.next_event() => {
                    let event = network_event.expect("Failed to get network event");
                    match event {
                        NetworkEvent::RequestReceived { request_id, request } => {
                            let ledger_db = self.ledger_db.clone();
                            let tx = response_tx.clone();
                            // don't block the event loop
                            tokio::spawn(async move {
                                let result = Self::on_inbound_request(&ledger_db, request);
                                let _ = tx.send((request_id, result)).await;
                            });
                        }
                        NetworkEvent::ResponseReceived { peer_id, response } => {
                            if let Err(e) = self.on_response_received(peer_id, response) {
                                error!("Error handling response from peer {peer_id}: {e:?}");
                            }
                        }
                        NetworkEvent::NewPeer(peer_id) => {
                            let message = L2SyncMessage::NewPeer(peer_id);
                            if let Err(e) = self.send_l2_sync_message(message) {
                                error!("Failed to notify L2 syncer of new peer {}: {:?}", peer_id, e);
                            }
                        }
                        NetworkEvent::GossipBlock(peer_id, block) => {
                            let message = L2SyncMessage::GossipBlock(peer_id, block);
                            if let Err(e) = self.send_l2_sync_message(message) {
                                error!("Failed to notify L2 syncer of gossiped block from peer {}: {:?}", peer_id, e);
                            }
                        }
                        NetworkEvent::RPCFailed { peer_id, request } => {
                            error!("RPC request {:?} to peer {} failed", request, peer_id);
                            let message = L2SyncMessage::RPCFailed { peer_id, request };
                            if let Err(e) = self.send_l2_sync_message(message) {
                                error!("Failed to notify L2 syncer of failed RPC to peer {}: {:?}", peer_id, e);
                            }
                        }
                        NetworkEvent::DisconnectedPeer(peer_id) => {
                            let message = L2SyncMessage::DisconnectedPeer(peer_id);
                            if let Err(e) = self.send_l2_sync_message(message) {
                                error!("Failed to notify L2 syncer of disconnected peer {}: {:?}", peer_id, e);
                            }
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
                _ = &mut shutdown_signal => {
                    info!("Shutting down NetworkService");
                    return;
                }
            }
        }
    }

    fn on_network_request(&mut self, request: NetworkRequest) {
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
            NetworkRequest::ReportPeer(_peer_id) => {
                unimplemented!();
            }
            NetworkRequest::GetPeerStatus(peer_id) => {
                self.network.send_rpc_request(peer_id, Eth2Request::Status);
            }
        }
    }

    fn on_inbound_request(ledger_db: &LedgerDB, request: Eth2Request) -> Result<Eth2Response> {
        match request {
            Eth2Request::Status => {
                // Handle status request
                // P2P-TODO: Implement proper status response
                let last_pruned_block = ledger_db.get_last_pruned_l2_height()?;
                let head_block = LedgerRpcProvider::get_head_l2_block_height(ledger_db)?;
                Ok(Eth2Response::Status(StatusResponse {
                    head_block,
                    last_pruned_block,
                }))
            }
            Eth2Request::BlocksByRange(blocks_request) => {
                let blocks =
                    l2_blocks_by_range(ledger_db, blocks_request.start, blocks_request.end)?;
                Ok(Eth2Response::BlocksByRange(blocks))
            }
        }
    }

    fn on_response_received(
        &self,
        peer_id: libp2p::PeerId,
        response: Eth2Response,
    ) -> anyhow::Result<()> {
        match response {
            Eth2Response::Status(status) => {
                info!("Received status from peer {}: {:?}", peer_id, status);
                let message = L2SyncMessage::PeerStatus(peer_id, status);
                self.send_l2_sync_message(message)
            }
            Eth2Response::BlocksByRange(blocks) => {
                info!("Received {} blocks from peer {}", blocks.len(), peer_id);
                let message = L2SyncMessage::BlockBatch(peer_id, blocks);
                self.send_l2_sync_message(message)
            }
        }
    }

    fn send_l2_sync_message(&self, message: L2SyncMessage) -> anyhow::Result<()> {
        if let Some(l2_sync_tx) = &self.l2_sync_tx {
            if let Err(e) = l2_sync_tx.try_send(message) {
                return Err(anyhow::anyhow!("Failed to send L2 sync message: {:?}", e));
            }
        }
        Ok(())
    }
}

// P2P-TODO: Fix error/response type
pub fn l2_blocks_by_range(
    ledger_db: &LedgerDB,
    start: u64,
    end: u64,
) -> Result<Vec<L2BlockResponse>> {
    let diff = end - start;

    // P2P-TODO: Make this configurable
    if diff > 1000 {
        return Err(anyhow::anyhow!(
            "Requested block range too large. Max range is 1000 blocks"
        ));
    }

    ledger_db
        .get_l2_blocks_range(start, end)?
        .into_iter()
        .map(|block_opt| block_opt.ok_or_else(|| anyhow::anyhow!("Block not found")))
        .collect()
}

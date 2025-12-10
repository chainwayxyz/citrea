use libp2p::request_response::InboundRequestId;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::rpc::block::L2BlockResponse;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocksByRangeRequest {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Eth2Request {
    Status,
    BlocksByRange(BlocksByRangeRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub head_block: u64,
    pub last_pruned_block: Option<u64>,
    // P2P-TODO: add include_tx_body here
    // and dont pull blocks from this peer/ disconnect if necessary
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Eth2Response {
    Status(StatusResponse),
    // P2P-TODO: use Result<Vec<L2BlockResponse>, Error> instead,
    // Errors: invalid range, too many blocks, size limit exceeded
    BlocksByRange(Vec<L2BlockResponse>),
}

pub enum NetworkRequest {
    PublishMessage {
        topic: String,
        message: Vec<u8>,
    },
    AddPeer(PeerId),
    RemovePeer(PeerId),
    GetL2BlockRange {
        peer_id: PeerId,
        start: u64,
        end: u64,
    },
    ReportPeer(PeerId), // P2P-TODO: add degree/reason
    GetPeerStatus(PeerId),
}

pub enum L2SyncMessage {
    GossipBlock(PeerId, L2BlockResponse),
    BlockBatch(PeerId, Vec<L2BlockResponse>),
    NewPeer(PeerId),
    DisconnectedPeer(PeerId),
    PeerStatus(PeerId, StatusResponse),
    RPCFailed {
        peer_id: PeerId,
        request: Eth2Request,
    },
}

pub(crate) enum NetworkEvent {
    GossipBlock(PeerId, L2BlockResponse),
    RequestReceived {
        request_id: InboundRequestId,
        request: Eth2Request,
    },
    ResponseReceived {
        peer_id: PeerId,
        response: Eth2Response,
    },
    RPCFailed {
        peer_id: PeerId,
        request: Eth2Request,
    },
    NewPeer(PeerId),
    DisconnectedPeer(PeerId),
}

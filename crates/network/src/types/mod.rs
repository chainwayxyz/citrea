use libp2p::gossipsub::{MessageAcceptance, MessageId};
use libp2p::request_response::InboundRequestId;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::rpc::block::L2BlockResponse;

mod peers;
pub use peers::{PeerAction, PeerInfo, PeerStatus, Score, SCORE_HALFLIFE};

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
pub enum Eth2Response {
    Status(PeerStatus),
    // P2P-TODO: use Result<Vec<L2BlockResponse>, Error> instead,
    // Errors: invalid range, too many blocks, size limit exceeded
    // on size limit we might be getting IO error!
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
    ReportPeer(PeerId, PeerAction),
    GetPeerStatus(PeerId),
    GossipBlockValidationResult {
        peer_id: PeerId,
        message_id: MessageId,
        validation_result: MessageAcceptance,
    },
}

pub enum L2SyncMessage {
    GossipBlock(PeerId, L2BlockResponse, MessageId),
    BlockBatch(PeerId, Vec<L2BlockResponse>),
    RPCFailed(PeerId, Eth2Request),
}

pub(crate) enum NetworkEvent {
    GossipBlock {
        peer_id: PeerId,
        l2_block_response: L2BlockResponse,
        message_id: MessageId,
    },
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
}
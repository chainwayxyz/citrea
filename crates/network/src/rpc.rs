use libp2p::request_response::json::codec::Codec as JsonCodec;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::StreamProtocol;

use crate::types::{Eth2Request, Eth2Response};

// P2P-TODO: consider cbor codec and measure performance
pub(crate) fn create_eth2_behaviour() -> request_response::json::Behaviour<Eth2Request, Eth2Response>
{
    let protocols = vec![
        (
            StreamProtocol::new("/eth2/req/status/1/json"),
            ProtocolSupport::Full,
        ),
        (
            StreamProtocol::new("/eth2/req/blocks_by_range/2/json"),
            ProtocolSupport::Full,
        ),
    ];
    // P2P-TODO: consider overriding max request/response sizes here
    let codec = JsonCodec::default();

    // P2P-TODO: consider custom config
    request_response::Behaviour::with_codec(codec, protocols, request_response::Config::default())
}

pub(crate) type Eth2Behaviour = request_response::json::Behaviour<Eth2Request, Eth2Response>;

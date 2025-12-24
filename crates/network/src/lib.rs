use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use anyhow::Result;
use citrea_common::NetworkConfig;
use futures::stream::StreamExt;
use gossipsub::Message as GossipsubMessage;
use libp2p::gossipsub::{MessageAcceptance, MessageId};
use libp2p::request_response::{InboundRequestId, OutboundRequestId, ResponseChannel};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    gossipsub, mdns, noise, request_response, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use sov_rollup_interface::rpc::block::L2BlockResponse;
use tracing::{error, info};

use crate::types::{Eth2Request, Eth2Response, NetworkEvent};

mod rpc;
pub mod service;
pub mod types;
pub use service::NetworkService;

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    eth2_rpc: rpc::Eth2Behaviour,
}

struct Network {
    swarm: Swarm<MyBehaviour>,
    pending_inbound_requests: HashMap<InboundRequestId, ResponseChannel<Eth2Response>>,
    pending_outbound_requests: HashMap<OutboundRequestId, Eth2Request>,
}

impl Network {
    fn build(network_config: NetworkConfig) -> Result<Self> {
        let heartbeat_interval =
            Duration::from_secs(network_config.gossipsub_config.heartbeat_interval_secs);

        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_behaviour(|key| {
                // To content-address message, we can take the hash of message and use it as an ID.
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut s = DefaultHasher::new();
                    message.data.hash(&mut s);
                    gossipsub::MessageId::from(s.finish().to_string())
                };
                // Set a custom gossipsub configuration
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(heartbeat_interval) // This is set to aid debugging by not cluttering the log space
                    .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message
                    // signing)
                    .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
                    .build()
                    .map_err(tokio::io::Error::other)?; // Temporary hack because `build` does not return a proper `std::error::Error`.

                // build a gossipsub network behaviour
                let gossipsub: gossipsub::Behaviour = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;
                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?;

                Ok(MyBehaviour {
                    gossipsub,
                    mdns,
                    eth2_rpc: rpc::create_eth2_behaviour(),
                })
            })?
            .build();

        // Create a Gossipsub topic
        let topic = gossipsub::IdentTopic::new("new-head");
        // subscribes to our topic
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        // Listen on all interfaces and whatever port the OS assigns
        swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        let dial_addr = network_config.dial_addr;

        // P2P-TODO: implement for multiple addresses
        // Dial the peer identified by the multi-address given as the second
        // command-line argument, if any.
        if let Some(addr) = dial_addr.as_ref() {
            let remote: Multiaddr = addr.parse()?;
            swarm.dial(remote)?;
            info!("Dialed {addr}");
        }

        Ok(Self {
            swarm,
            pending_inbound_requests: HashMap::new(),
            pending_outbound_requests: HashMap::new(),
        })
    }

    pub async fn next_event(&mut self) -> Result<NetworkEvent> {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(event) => {
                    let network_event = match event {
                        MyBehaviourEvent::Eth2Rpc(event) => self.on_eth2_rpc_event(event).await,
                        MyBehaviourEvent::Mdns(event) => self.on_mdns_event(event).await,
                        MyBehaviourEvent::Gossipsub(event) => self.on_gossipsub_event(event).await,
                    };
                    if let Some(event) = network_event {
                        return Ok(event);
                    }
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Local node is listening on {address}");
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    return Ok(NetworkEvent::NewPeer(peer_id));
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    return Ok(NetworkEvent::DisconnectedPeer(peer_id));
                }
                _ => {}
            }
        }
    }

    pub fn send_rpc_request(&mut self, peer_id: PeerId, request: Eth2Request) {
        let request_id = self
            .swarm
            .behaviour_mut()
            .eth2_rpc
            .send_request(&peer_id, request.clone());

        self.pending_outbound_requests.insert(request_id, request);
    }

    // P2P-TODO: what happens when the response is too large?
    pub fn send_rpc_response(
        &mut self,
        request_id: InboundRequestId,
        response: Eth2Response,
    ) -> anyhow::Result<()> {
        let channel = self
            .pending_inbound_requests
            .remove(&request_id)
            .ok_or_else(|| {
                anyhow::anyhow!("No pending inbound request found for the request id: {request_id}")
            })?;

        if let Err(_failed_response) = self
            .swarm
            .behaviour_mut()
            .eth2_rpc
            .send_response(channel, response)
        {
            error!("Failed to send response, request id: {request_id}");
        };
        Ok(())
    }

    pub fn publish_message(&mut self, topic: &str, message: Vec<u8>) {
        let gossipsub_topic = gossipsub::IdentTopic::new(topic);
        if let Err(e) = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(gossipsub_topic, message)
        {
            error!("Failed to publish message: {:?}", e);
        }
    }

    async fn on_mdns_event(&mut self, event: mdns::Event) -> Option<NetworkEvent> {
        match event {
            mdns::Event::Discovered(list) => {
                for (peer_id, _multiaddr) in list {
                    info!("mDNS discovered a new peer: {peer_id}");
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer_id);
                }
            }
            mdns::Event::Expired(list) => {
                for (peer_id, _multiaddr) in list {
                    info!("mDNS discover peer has expired: {peer_id}");
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .remove_explicit_peer(&peer_id);
                }
            }
        }
        None
    }

    async fn on_gossipsub_event(&mut self, event: gossipsub::Event) -> Option<NetworkEvent> {
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            } => {
                let GossipsubMessage { data, .. } = message;
                let l2_block_response: L2BlockResponse = match serde_json::from_slice(&data) {
                    Ok(msg) => msg,
                    Err(_) => {
                        self.report_message_validation_result(
                            &propagation_source,
                            message_id,
                            MessageAcceptance::Reject,
                        );
                        return None;
                    }
                };
                Some(NetworkEvent::GossipBlock {
                    peer_id: propagation_source,
                    l2_block_response,
                    message_id,
                })
            }
            gossipsub::Event::GossipsubNotSupported { .. } => {
                // P2P-TODO: ban peer
                None
            }
            gossipsub::Event::SlowPeer { .. } => {
                // P2P-TODO: slash peer
                None
            }
            gossipsub::Event::Subscribed { .. } | gossipsub::Event::Unsubscribed { .. } => None,
        }
    }

    async fn on_eth2_rpc_event(
        &mut self,
        event: request_response::Event<Eth2Request, Eth2Response>,
    ) -> Option<NetworkEvent> {
        match event {
            request_response::Event::Message { peer, message, .. } => {
                match message {
                    request_response::Message::Request {
                        request_id,
                        request,
                        channel,
                    } => {
                        self.pending_inbound_requests.insert(request_id, channel);
                        // send the request to the upper layer, which will call send_rpc_response once ready
                        // P2P-TODO: consider using peer_id here
                        Some(NetworkEvent::RequestReceived {
                            request_id,
                            request,
                        })
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        self.pending_outbound_requests.remove(&request_id);
                        Some(NetworkEvent::ResponseReceived {
                            peer_id: peer,
                            response,
                        })
                    }
                }
            }
            request_response::Event::OutboundFailure {
                peer, request_id, ..
            } => {
                let failed_request = self
                    .pending_outbound_requests
                    .remove(&request_id)
                    .expect("Failed outbound request must be tracked");
                // P2P-TODO: slashing based on error here?
                Some(NetworkEvent::RPCFailed {
                    peer_id: peer,
                    request: failed_request,
                })
            }
            request_response::Event::InboundFailure { request_id, .. } => {
                // P2P-TODO: Consider taking action on inbound failures based on error,
                // including disconnection, and unsupported protocol
                self.pending_inbound_requests.remove(&request_id);
                None
            }
            request_response::Event::ResponseSent { .. } => None,
        }
    }

    /// Informs the gossipsub about the result of a message validation.
    /// If the message is valid it will get propagated by gossipsub.
    pub fn report_message_validation_result(
        &mut self,
        propagation_source: &PeerId,
        message_id: MessageId,
        validation_result: MessageAcceptance,
    ) {
        self.swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(&message_id, propagation_source, validation_result);
    }
}

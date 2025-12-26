use std::sync::Arc;
use libp2p::PeerId;

use crate::{types::PeerAction, NetworkGlobals};

pub enum ReportPeerResult {
    Ban,
    NoAction,
}

pub enum HeartbeatResult {
    WantedPeers(usize),
    ExcessPeers(Vec<PeerId>),
    NoAction,
}

struct PeerManager {
    network_globals: Arc<NetworkGlobals>,
    target_peers: usize,
    score_halflife_secs: f32,
    last_decay: std::time::Instant,
}

impl PeerManager {
    pub fn new(
        network_globals: Arc<NetworkGlobals>,
        target_peers: usize,
        score_halflife_secs: f32,
    ) -> Self {
        Self { network_globals, target_peers, score_halflife_secs, last_decay: std::time::Instant::now() }
    }

    pub async fn report_peer(&self, peer_id: &PeerId, action: PeerAction) -> ReportPeerResult {
        let mut peers = self.network_globals.peers.write().await;
        if let Some(peer_info) = peers.get_mut(peer_id) {
            let was_banned = peer_info.score.is_banned();
            peer_info.score.apply_peer_action(action);
            if !was_banned && peer_info.score.is_banned() {
                return ReportPeerResult::Ban;
            }
        }
        ReportPeerResult::NoAction
    }

    pub async fn heartbeat(&mut self) -> HeartbeatResult {
        // Decay scores if score halflife has passed
        if self.last_decay.elapsed().as_secs_f32() >= self.score_halflife_secs {
            self.decay_scores().await;
            self.last_decay = std::time::Instant::now();
        }
        // Check peer count against target
        let num_peers = self.network_globals.peers.read().await.len();
        if num_peers < self.target_peers {
            // Need more peers
            let wanted = self.target_peers - num_peers;
            HeartbeatResult::WantedPeers(wanted)
        } else if num_peers > self.target_peers {
            // Too many peers, need to drop some
            let excess_peers = self.prune_peers().await;
            HeartbeatResult::ExcessPeers(excess_peers)
        } else {
            HeartbeatResult::NoAction
        }
    }

    async fn decay_scores(&self) {
        let mut peers = self.network_globals.peers.write().await;
        for (_, peer_info) in peers.iter_mut() {
            peer_info.score.decay();
        }
    }

    async fn prune_peers(&self) -> Vec<PeerId> {
        vec![] // Placeholder for pruning logic
    }
}
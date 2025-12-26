use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// The minimum reputation before a peer is banned.
const MIN_SCORE_BEFORE_BAN: f32 = -50.0;
/// The minimum score a peer can obtain.
const MIN_SCORE: f32 = -100.0;
/// The halflife of a peer's score. I.e the number of seconds it takes for the score to decay to half its value.
const SCORE_HALFLIFE: f32 = 600.0;
/// The number of seconds we ban a peer for before their score begins to decay.
const BANNED_BEFORE_DECAY: Duration = Duration::from_secs(12 * 3600); // 12 hours

pub struct Score {
    val: f32,
    banned_at: Option<Instant>,
}

impl Default for Score {
    fn default() -> Self {
        Self { val: 0.0, banned_at: None }
    }
}

impl Score {
    pub fn add(&mut self, amount: f32) {
        self.val = (self.val + amount).clamp(MIN_SCORE, 0.0);
        if self.val < MIN_SCORE_BEFORE_BAN && self.banned_at.is_none() {
            self.banned_at = Some(Instant::now());
        }
    }

    pub fn score(&self) -> f32 {
        self.val
    }

    pub fn is_banned(&self) -> bool {
        self.banned_at.is_some()
    }

    pub fn decay(&mut self) {
        // if banned, don't decay until after ban period
        if let Some(banned_at) = self.banned_at {
            if Instant::now().duration_since(banned_at) < BANNED_BEFORE_DECAY {
                return;
            }
        }
        // decay score by half
        self.val /= 2.0;
        // unban if score has improved enough
        if self.val > -MIN_SCORE_BEFORE_BAN {
            self.banned_at = None;
        }
    }

    pub fn apply_peer_action(&mut self, action: PeerAction) {
        match action {
            PeerAction::Fatal => self.add(-100.0),
            PeerAction::LowToleranceError => self.add(-10.0),
            PeerAction::MidToleranceError => self.add(-5.0),
            PeerAction::HighToleranceError => self.add(-1.0),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub head_block: u64,
    pub last_pruned_block: Option<u64>,
    pub has_tx_bodies: bool,
}

pub struct PeerInfo {
    pub score: Score,
    pub status: Option<PeerStatus>,
    pub is_connected: bool,
}

pub enum PeerAction {
    Fatal,
    LowToleranceError,
    MidToleranceError,
    HighToleranceError,
}
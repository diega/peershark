//! Pool of real Ethereum peers for tunneled peer connections.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::RwLock;
use std::time::Instant;

use serde::Serialize;

use crate::constants::{PEER_SCORE_RECOVERY_SECS, PEER_SCORE_THRESHOLD};
use crate::p2p::DisconnectReason;

/// Category of connection failure for scoring purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// TCP connection refused or failed.
    ConnectionRefused,
    /// Timeout during handshake or status exchange.
    Timeout,
    /// Peer sent DISCONNECT with a specific reason.
    Disconnected(DisconnectReason),
    /// Genesis hash mismatch (different chain).
    GenesisMismatch,
    /// Other protocol error.
    ProtocolError,
    /// Peer disconnected immediately after successful Status exchange.
    /// This typically indicates an unstable peer or protocol incompatibility.
    ImmediateDisconnect,
}

impl FailureKind {
    /// Get the penalty for this failure type.
    ///
    /// Returns `i32::MAX` for permanent bans (genesis mismatch, incompatible version).
    pub fn penalty(&self) -> i32 {
        match self {
            // Network errors - temporary
            FailureKind::ConnectionRefused => 3,
            FailureKind::Timeout => 2,

            // Genesis mismatch - permanent (different chain)
            FailureKind::GenesisMismatch => i32::MAX,

            // Disconnect reasons with variable penalty
            FailureKind::Disconnected(reason) => match reason {
                // Very temporary - retry soon
                DisconnectReason::TooManyPeers => 1,
                DisconnectReason::ClientQuitting => 1,
                DisconnectReason::Requested => 2,

                // Temporary - network issues
                DisconnectReason::TcpError => 2,
                DisconnectReason::PingTimeout => 2,

                // Our error - don't penalize
                DisconnectReason::AlreadyConnected => 0,
                DisconnectReason::SameIdentity => 0,
                DisconnectReason::UnexpectedIdentity => 1,

                // Incompatibility - permanent
                DisconnectReason::IncompatibleVersion => i32::MAX,
                DisconnectReason::InvalidIdentity => i32::MAX,

                // Protocol issues - severe
                DisconnectReason::ProtocolBreach => 10,
                DisconnectReason::SubprotocolError => 5,
                DisconnectReason::UselessPeer => 3,

                DisconnectReason::Unknown(_) => 3,
            },

            FailureKind::ProtocolError => 5,

            // Immediate disconnect after successful Status exchange
            // Severe penalty - peer is unstable or incompatible
            FailureKind::ImmediateDisconnect => 5,
        }
    }

    /// Whether this failure results in a permanent ban.
    pub fn is_permanent(&self) -> bool {
        self.penalty() == i32::MAX
    }
}

/// Score and metadata for a peer.
#[derive(Debug, Clone)]
struct PeerScore {
    /// Current score (0 = neutral, negative = penalized).
    score: i32,
    /// Last time the score was updated.
    last_update: Instant,
    /// Whether permanently banned (genesis mismatch, incompatible version).
    permanently_banned: bool,
}

impl PeerScore {
    fn new() -> Self {
        Self {
            score: 0,
            last_update: Instant::now(),
            permanently_banned: false,
        }
    }

    /// Calculate effective score with time-based recovery.
    fn effective_score(&self) -> i32 {
        if self.permanently_banned {
            return i32::MIN;
        }

        let elapsed_secs = self.last_update.elapsed().as_secs();
        let recovery = (elapsed_secs / PEER_SCORE_RECOVERY_SECS) as i32;
        (self.score + recovery).min(0) // Cap at 0 (neutral)
    }

    /// Record a failure and return true if peer becomes banned.
    fn record_failure(&mut self, kind: FailureKind) -> bool {
        if kind.is_permanent() {
            self.permanently_banned = true;
            return true;
        }

        let penalty = kind.penalty();
        self.score -= penalty;
        self.last_update = Instant::now();
        self.score <= PEER_SCORE_THRESHOLD
    }

    /// Reset score to neutral (called on successful connection).
    fn reset(&mut self) {
        if !self.permanently_banned {
            self.score = 0;
            self.last_update = Instant::now();
        }
    }
}

/// A pool of real peers that tunneled peers can connect to.
///
/// Tracks which peers are currently in use and uses a scoring system
/// to prioritize peers and temporarily ban unreliable ones.
///
/// Uses `std::sync::RwLock` instead of `tokio::sync::RwLock` because:
/// - Pool operations are fast (HashMap/HashSet lookups/inserts)
/// - Avoids async overhead for simple state access
/// - Lock contention is expected to be low
pub struct PeerPool {
    /// All known peer URLs.
    peers: RwLock<Vec<String>>,
    /// Peers currently in use by active tunnels.
    in_use: RwLock<HashSet<String>>,
    /// Peer scores for prioritization and banning.
    scores: RwLock<HashMap<String, PeerScore>>,
}

impl PeerPool {
    /// Create a new peer pool from a list of enode URLs.
    pub fn new(peers: Vec<String>) -> Self {
        PeerPool {
            peers: RwLock::new(peers),
            in_use: RwLock::new(HashSet::new()),
            scores: RwLock::new(HashMap::new()),
        }
    }

    /// Add peers to the pool (used when discovery completes asynchronously).
    pub fn add_peers(&self, new_peers: Vec<String>) {
        let mut peers = self.peers.write().unwrap_or_else(|e| e.into_inner());
        for peer in new_peers {
            if !peers.contains(&peer) {
                peers.push(peer);
            }
        }
    }

    /// Try to reserve an available peer (not in use, not banned).
    ///
    /// Peers are sorted by effective score (best first).
    /// The `start_idx` parameter helps distribute load among peers with similar scores.
    /// Returns the peer URL if successful, `None` if no peers are available.
    pub fn try_reserve(&self, start_idx: usize) -> Option<String> {
        let peers = self.peers.read().unwrap_or_else(|e| e.into_inner());
        let mut in_use = self.in_use.write().unwrap_or_else(|e| e.into_inner());
        let scores = self.scores.read().unwrap_or_else(|e| e.into_inner());

        // Collect available peers (not in use, not banned)
        let mut available: Vec<&String> = peers
            .iter()
            .filter(|peer| !in_use.contains(*peer))
            .filter(|peer| {
                scores
                    .get(*peer)
                    .map(|s| s.effective_score() > PEER_SCORE_THRESHOLD)
                    .unwrap_or(true) // No score = available
            })
            .collect();

        if available.is_empty() {
            return None;
        }

        // Sort by effective score (higher/better first)
        available.sort_by(|a, b| {
            let score_a = scores.get(*a).map(|s| s.effective_score()).unwrap_or(0);
            let score_b = scores.get(*b).map(|s| s.effective_score()).unwrap_or(0);
            score_b.cmp(&score_a)
        });

        // Use start_idx to distribute among peers with similar scores
        let idx = start_idx % available.len();
        let peer = available[idx].clone();
        in_use.insert(peer.clone());
        Some(peer)
    }

    /// Record a connection failure for a peer.
    ///
    /// The peer is removed from in_use and its score is penalized.
    pub fn record_failure(&self, peer: &str, kind: FailureKind) {
        {
            let mut in_use = self.in_use.write().unwrap_or_else(|e| e.into_inner());
            in_use.remove(peer);
        }
        {
            let mut scores = self.scores.write().unwrap_or_else(|e| e.into_inner());
            let score = scores
                .entry(peer.to_string())
                .or_insert_with(PeerScore::new);
            score.record_failure(kind);
        }
    }

    /// Release a peer after a successful connection.
    ///
    /// The peer is removed from in_use and its score is reset to neutral
    /// (successful connections "forgive all sins").
    pub fn release(&self, peer: &str) {
        {
            let mut in_use = self.in_use.write().unwrap_or_else(|e| e.into_inner());
            in_use.remove(peer);
        }
        {
            let mut scores = self.scores.write().unwrap_or_else(|e| e.into_inner());
            if let Some(score) = scores.get_mut(peer) {
                score.reset();
            }
        }
    }

    /// Get pool statistics.
    ///
    /// Returns a tuple of `(available, in_use, banned)` counts.
    pub fn stats(&self) -> (usize, usize, usize) {
        let peers = self.peers.read().unwrap_or_else(|e| e.into_inner());
        let in_use = self.in_use.read().unwrap_or_else(|e| e.into_inner());
        let scores = self.scores.read().unwrap_or_else(|e| e.into_inner());

        let banned = scores
            .values()
            .filter(|s| s.effective_score() <= PEER_SCORE_THRESHOLD)
            .count();
        let available = peers.len().saturating_sub(in_use.len() + banned);

        (available, in_use.len(), banned)
    }

    /// Total number of peers in the pool (regardless of status).
    pub fn total(&self) -> usize {
        let peers = self.peers.read().unwrap_or_else(|e| e.into_inner());
        peers.len()
    }

    /// Get a copy of all peer URLs in the pool.
    pub fn get_peers(&self) -> Vec<String> {
        let peers = self.peers.read().unwrap_or_else(|e| e.into_inner());
        peers.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_recovers_score_over_time() {
        let mut score = PeerScore::new();
        score.record_failure(FailureKind::Timeout); // -2
        score.record_failure(FailureKind::Timeout); // -4

        assert_eq!(score.score, -4);

        // Simulate time passing (10 minutes = 600 seconds)
        score.last_update = Instant::now() - std::time::Duration::from_secs(600);

        // Should recover 2 points (600s / 300s = 2)
        assert_eq!(score.effective_score(), -2);
    }

    #[test]
    fn genesis_mismatch_is_permanent() {
        let mut score = PeerScore::new();
        score.record_failure(FailureKind::GenesisMismatch);

        assert!(score.permanently_banned);
        assert_eq!(score.effective_score(), i32::MIN);
    }

    #[test]
    fn too_many_peers_has_low_penalty() {
        let kind = FailureKind::Disconnected(DisconnectReason::TooManyPeers);
        assert_eq!(kind.penalty(), 1);
        assert!(!kind.is_permanent());
    }

    #[test]
    fn incompatible_version_is_permanent() {
        let kind = FailureKind::Disconnected(DisconnectReason::IncompatibleVersion);
        assert!(kind.is_permanent());
    }

    #[test]
    fn pool_prefers_better_scored_peers() {
        let pool = PeerPool::new(vec![
            "enode://a@1.1.1.1:30303".to_string(),
            "enode://b@2.2.2.2:30303".to_string(),
        ]);

        // Penalize peer A
        pool.record_failure("enode://a@1.1.1.1:30303", FailureKind::Timeout);
        pool.record_failure("enode://a@1.1.1.1:30303", FailureKind::Timeout);

        // Should prefer peer B (score 0) over A (score -4)
        let reserved = pool.try_reserve(0).unwrap();
        assert_eq!(reserved, "enode://b@2.2.2.2:30303");
    }

    #[test]
    fn peer_becomes_unavailable_at_threshold() {
        let pool = PeerPool::new(vec!["enode://a@1.1.1.1:30303".to_string()]);

        // Penalize until threshold (-10)
        for _ in 0..5 {
            pool.record_failure("enode://a@1.1.1.1:30303", FailureKind::Timeout); // -2 each
        }

        // Score = -10, should be at threshold and unavailable
        assert!(pool.try_reserve(0).is_none());
    }

    #[test]
    fn successful_connection_resets_score() {
        let pool = PeerPool::new(vec!["enode://a@1.1.1.1:30303".to_string()]);
        let peer = "enode://a@1.1.1.1:30303";

        // Penalize
        pool.record_failure(peer, FailureKind::Timeout);
        pool.record_failure(peer, FailureKind::Timeout);

        // Reserve and release successfully
        let reserved = pool.try_reserve(0).unwrap();
        pool.release(&reserved);

        // Score should be reset to 0
        let scores = pool.scores.read().unwrap();
        assert_eq!(scores.get(peer).unwrap().score, 0);
    }

    /// TDD: This test demonstrates the bug where peers that disconnect immediately
    /// after Status exchange are not penalized, so they keep being selected.
    /// The test should FAIL until FailureKind::ImmediateDisconnect is implemented.
    #[test]
    fn immediate_disconnect_has_severe_penalty() {
        // This variant should exist to penalize peers that close connection
        // immediately after successful Status exchange
        let kind = FailureKind::ImmediateDisconnect;

        // Should have high penalty (similar to ProtocolError or worse)
        assert!(
            kind.penalty() >= 5,
            "immediate disconnect should have penalty >= 5"
        );

        // Should NOT be permanent (peer might recover)
        assert!(
            !kind.is_permanent(),
            "immediate disconnect should not be permanent ban"
        );
    }

    /// TDD: Verify that recording ImmediateDisconnect penalizes the peer
    #[test]
    fn immediate_disconnect_penalizes_peer() {
        let pool = PeerPool::new(vec!["enode://a@1.1.1.1:30303".to_string()]);
        let peer = "enode://a@1.1.1.1:30303";

        // Reserve peer (simulating tunnel establishment)
        let reserved = pool.try_reserve(0).unwrap();
        assert_eq!(reserved, peer);

        // Peer disconnects immediately - should be penalized
        pool.record_failure(peer, FailureKind::ImmediateDisconnect);

        // Verify peer was penalized
        let scores = pool.scores.read().unwrap();
        let score = scores.get(peer).unwrap();
        assert!(
            score.score < 0,
            "peer should be penalized after immediate disconnect"
        );
        assert!(score.score <= -5, "penalty should be severe (at least -5)");
    }
}

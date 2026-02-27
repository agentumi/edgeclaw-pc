//! Peer connection management and device tracking.
//!
//! Maintains a registry of connected peers with role assignment,
//! last-seen timestamps, and configurable connection limits.

use crate::error::AgentError;

/// Peer connection information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub device_name: String,
    pub device_type: String,
    pub address: String,
    pub role: String,
    pub capabilities: Vec<String>,
    pub last_seen: String,
    pub is_connected: bool,
}

struct PeerEntry {
    info: PeerInfo,
    connected_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Manages connected peers (controllers and other agents)
pub struct PeerManager {
    peers: std::collections::HashMap<String, PeerEntry>,
    max_peers: usize,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new(50)
    }
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: std::collections::HashMap::new(),
            max_peers,
        }
    }

    /// Register or update a peer
    pub fn add_peer(
        &mut self,
        peer_id: &str,
        device_name: &str,
        device_type: &str,
        address: &str,
        role: &str,
    ) -> Result<PeerInfo, AgentError> {
        if self.peers.len() >= self.max_peers && !self.peers.contains_key(peer_id) {
            return Err(AgentError::ConnectionError(format!(
                "max peers reached: {}/{}",
                self.peers.len(),
                self.max_peers
            )));
        }

        let now = chrono::Utc::now();
        let info = PeerInfo {
            peer_id: peer_id.to_string(),
            device_name: device_name.to_string(),
            device_type: device_type.to_string(),
            address: address.to_string(),
            role: role.to_string(),
            capabilities: vec![],
            last_seen: now.to_rfc3339(),
            is_connected: true,
        };

        self.peers.insert(
            peer_id.to_string(),
            PeerEntry {
                info: info.clone(),
                connected_at: Some(now),
            },
        );

        Ok(info)
    }

    /// Update peer's last seen timestamp
    pub fn update_last_seen(&mut self, peer_id: &str) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.info.last_seen = chrono::Utc::now().to_rfc3339();
        }
    }

    /// Set peer connection state
    pub fn set_connected(&mut self, peer_id: &str, connected: bool) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.info.is_connected = connected;
            if connected {
                entry.connected_at = Some(chrono::Utc::now());
            } else {
                entry.connected_at = None;
            }
        }
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, peer_id: &str) -> bool {
        self.peers.remove(peer_id).is_some()
    }

    /// Get peer info
    pub fn get_peer(&self, peer_id: &str) -> Option<&PeerInfo> {
        self.peers.get(peer_id).map(|e| &e.info)
    }

    /// List all peers
    pub fn list_peers(&self) -> Vec<PeerInfo> {
        self.peers.values().map(|e| e.info.clone()).collect()
    }

    /// List connected peers
    pub fn connected_peers(&self) -> Vec<PeerInfo> {
        self.peers
            .values()
            .filter(|e| e.info.is_connected)
            .map(|e| e.info.clone())
            .collect()
    }

    /// Get number of connected peers
    pub fn connected_count(&self) -> usize {
        self.peers.values().filter(|e| e.info.is_connected).count()
    }

    /// Get peer's role
    pub fn get_peer_role(&self, peer_id: &str) -> Option<String> {
        self.peers.get(peer_id).map(|e| e.info.role.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_peer() {
        let mut mgr = PeerManager::new(10);
        let peer = mgr
            .add_peer("p1", "iPhone", "mobile", "192.168.1.10", "admin")
            .unwrap();
        assert_eq!(peer.peer_id, "p1");
        assert!(peer.is_connected);

        let got = mgr.get_peer("p1").unwrap();
        assert_eq!(got.device_name, "iPhone");
        assert_eq!(got.role, "admin");
    }

    #[test]
    fn test_remove_peer() {
        let mut mgr = PeerManager::new(10);
        mgr.add_peer("p1", "test", "pc", "127.0.0.1", "viewer")
            .unwrap();
        assert!(mgr.remove_peer("p1"));
        assert!(mgr.get_peer("p1").is_none());
    }

    #[test]
    fn test_connected_peers() {
        let mut mgr = PeerManager::new(10);
        mgr.add_peer("p1", "a", "pc", "1.1.1.1", "viewer").unwrap();
        mgr.add_peer("p2", "b", "mobile", "2.2.2.2", "admin")
            .unwrap();
        mgr.set_connected("p1", false);

        assert_eq!(mgr.connected_count(), 1);
        assert_eq!(mgr.connected_peers().len(), 1);
        assert_eq!(mgr.connected_peers()[0].peer_id, "p2");
    }

    #[test]
    fn test_max_peers_limit() {
        let mut mgr = PeerManager::new(2);
        mgr.add_peer("p1", "a", "pc", "1.1.1.1", "viewer").unwrap();
        mgr.add_peer("p2", "b", "pc", "2.2.2.2", "viewer").unwrap();
        assert!(mgr.add_peer("p3", "c", "pc", "3.3.3.3", "viewer").is_err());
    }

    #[test]
    fn test_get_peer_role() {
        let mut mgr = PeerManager::new(10);
        mgr.add_peer("p1", "ctrl", "mobile", "10.0.0.1", "owner")
            .unwrap();
        assert_eq!(mgr.get_peer_role("p1").unwrap(), "owner");
        assert!(mgr.get_peer_role("unknown").is_none());
    }

    #[test]
    fn test_update_last_seen() {
        let mut mgr = PeerManager::new(10);
        mgr.add_peer("p1", "test", "pc", "1.1.1.1", "viewer")
            .unwrap();
        let before = mgr.get_peer("p1").unwrap().last_seen.clone();
        std::thread::sleep(std::time::Duration::from_millis(10));
        mgr.update_last_seen("p1");
        let after = mgr.get_peer("p1").unwrap().last_seen.clone();
        assert_ne!(before, after);
    }
}

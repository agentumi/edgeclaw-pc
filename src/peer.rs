//! Peer connection management and device tracking.
//!
//! Maintains a registry of connected peers with role assignment,
//! last-seen timestamps, and configurable connection limits.
//! Provides ECDH handshake, encrypted ECNP messaging, connection
//! pooling, and automatic reconnection (3 attempts).

use crate::ecnp::EcnpCodec;
use crate::error::AgentError;
use crate::protocol::MessageType;
use crate::session::SessionManager;

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

// ---------------------------------------------------------------------------
// ECDH handshake + encrypted ECNP communication
// ---------------------------------------------------------------------------

/// Handshake payload exchanged during ECDH key agreement
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HandshakePayload {
    /// Hex-encoded X25519 public key (64 hex chars = 32 bytes)
    pub x25519_public_hex: String,
    /// Hex-encoded Ed25519 signature over the X25519 public key
    pub ed25519_signature_hex: String,
    /// Device / agent identifier
    pub device_id: String,
    /// Human-readable agent name
    pub agent_name: String,
}

/// State of a connection in the pool
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ConnectionState {
    /// No active connection
    Disconnected,
    /// TCP connection attempt in progress
    Connecting,
    /// ECDH handshake in progress
    Handshaking,
    /// Fully connected and encrypted
    Connected,
    /// Attempting automatic reconnection
    Reconnecting,
    /// Connection permanently failed
    Failed,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "Disconnected"),
            Self::Connecting => write!(f, "Connecting"),
            Self::Handshaking => write!(f, "Handshaking"),
            Self::Connected => write!(f, "Connected"),
            Self::Reconnecting => write!(f, "Reconnecting"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Tracked connection state for a peer
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerConnectionInfo {
    pub peer_id: String,
    pub address: String,
    pub session_id: Option<String>,
    pub state: ConnectionState,
    pub connected_at: Option<String>,
    pub reconnect_count: u32,
}

/// Connection pool that tracks active peer TCP sessions
pub struct ConnectionPool {
    connections: std::collections::HashMap<String, PeerConnectionInfo>,
    max_reconnect_attempts: u32,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new(3)
    }
}

impl ConnectionPool {
    /// Create a new connection pool with a reconnect limit.
    pub fn new(max_reconnect_attempts: u32) -> Self {
        Self {
            connections: std::collections::HashMap::new(),
            max_reconnect_attempts,
        }
    }

    /// Record a new outbound connection attempt.
    pub fn track_connect(&mut self, peer_id: &str, address: &str) -> PeerConnectionInfo {
        let info = PeerConnectionInfo {
            peer_id: peer_id.to_string(),
            address: address.to_string(),
            session_id: None,
            state: ConnectionState::Connecting,
            connected_at: None,
            reconnect_count: 0,
        };
        self.connections.insert(peer_id.to_string(), info.clone());
        info
    }

    /// Transition a connection to the `Connected` state with a session.
    pub fn mark_connected(&mut self, peer_id: &str, session_id: &str) {
        if let Some(ci) = self.connections.get_mut(peer_id) {
            ci.state = ConnectionState::Connected;
            ci.session_id = Some(session_id.to_string());
            ci.connected_at = Some(chrono::Utc::now().to_rfc3339());
            ci.reconnect_count = 0;
        }
    }

    /// Transition a connection to `Disconnected`.
    pub fn mark_disconnected(&mut self, peer_id: &str) {
        if let Some(ci) = self.connections.get_mut(peer_id) {
            ci.state = ConnectionState::Disconnected;
            ci.session_id = None;
            ci.connected_at = None;
        }
    }

    /// Check whether a reconnection attempt is allowed and bump the counter.
    pub fn try_reconnect(&mut self, peer_id: &str) -> bool {
        if let Some(ci) = self.connections.get_mut(peer_id) {
            if ci.reconnect_count >= self.max_reconnect_attempts {
                ci.state = ConnectionState::Failed;
                return false;
            }
            ci.reconnect_count += 1;
            ci.state = ConnectionState::Reconnecting;
            true
        } else {
            false
        }
    }

    /// Get connection info for a peer.
    pub fn get(&self, peer_id: &str) -> Option<&PeerConnectionInfo> {
        self.connections.get(peer_id)
    }

    /// List all tracked connections.
    pub fn list_all(&self) -> Vec<PeerConnectionInfo> {
        self.connections.values().cloned().collect()
    }

    /// Remove a connection from the pool.
    pub fn remove(&mut self, peer_id: &str) -> bool {
        self.connections.remove(peer_id).is_some()
    }

    /// Return `true` if peer is in `Connected` state.
    pub fn is_connected(&self, peer_id: &str) -> bool {
        self.connections
            .get(peer_id)
            .is_some_and(|ci| ci.state == ConnectionState::Connected)
    }

    /// Get the session ID for a connected peer.
    pub fn session_id(&self, peer_id: &str) -> Option<String> {
        self.connections
            .get(peer_id)
            .and_then(|ci| ci.session_id.clone())
    }
}

/// Build a [`HandshakePayload`] from raw key material.
pub fn build_handshake_payload(
    x25519_public: &[u8; 32],
    ed25519_signature: &[u8],
    device_id: &str,
    agent_name: &str,
) -> HandshakePayload {
    HandshakePayload {
        x25519_public_hex: hex::encode(x25519_public),
        ed25519_signature_hex: hex::encode(ed25519_signature),
        device_id: device_id.to_string(),
        agent_name: agent_name.to_string(),
    }
}

/// Parse the remote peer's [`HandshakePayload`] and extract the X25519 public key.
pub fn parse_handshake_public_key(payload: &HandshakePayload) -> Result<[u8; 32], AgentError> {
    let bytes = hex::decode(&payload.x25519_public_hex).map_err(|_| {
        AgentError::CryptoError("invalid hex in handshake x25519 public key".into())
    })?;
    if bytes.len() != 32 {
        return Err(AgentError::CryptoError(
            "x25519 public key must be 32 bytes".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Perform the client side of an ECDH handshake over a TCP stream.
///
/// 1. Serialize and send our [`HandshakePayload`] as an ECNP `Handshake` frame.
/// 2. Read the remote peer's `Handshake` response.
/// 3. Extract the remote X25519 public key.
/// 4. Derive a shared session via [`SessionManager::create_session`].
///
/// Returns `(session_id, remote_payload)`.
pub async fn perform_handshake(
    stream: &mut tokio::net::TcpStream,
    session_mgr: &mut SessionManager,
    local_secret: &[u8; 32],
    local_payload: &HandshakePayload,
) -> Result<(String, HandshakePayload), AgentError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 1. Send our handshake
    let payload_json = serde_json::to_vec(local_payload)?;
    let frame = EcnpCodec::encode(MessageType::Handshake, &payload_json)?;
    stream
        .write_all(&frame)
        .await
        .map_err(|e| AgentError::ConnectionError(format!("handshake send failed: {e}")))?;

    // 2. Read response
    let mut buf = vec![0u8; 65536];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
        .await
        .map_err(|_| AgentError::Timeout(5))?
        .map_err(|e| AgentError::ConnectionError(format!("handshake read failed: {e}")))?;

    if n == 0 {
        return Err(AgentError::ConnectionError(
            "peer closed during handshake".into(),
        ));
    }

    let msg = EcnpCodec::decode(&buf[..n])?;
    if msg.msg_type != MessageType::Handshake as u8 {
        return Err(AgentError::ConnectionError(
            "expected Handshake frame from peer".into(),
        ));
    }

    let remote_payload: HandshakePayload = serde_json::from_slice(&msg.payload)?;
    let remote_public = parse_handshake_public_key(&remote_payload)?;

    // 3. Derive session
    let info =
        session_mgr.create_session(&remote_payload.device_id, local_secret, &remote_public)?;

    Ok((info.session_id, remote_payload))
}

/// Send an encrypted ECNP message over a stream.
pub async fn send_encrypted_message(
    stream: &mut tokio::net::TcpStream,
    session_mgr: &mut SessionManager,
    session_id: &str,
    msg_type: MessageType,
    plaintext: &[u8],
) -> Result<(), AgentError> {
    use tokio::io::AsyncWriteExt;

    let ciphertext = session_mgr.encrypt(session_id, plaintext)?;
    let frame = EcnpCodec::encode(msg_type, &ciphertext)?;
    stream
        .write_all(&frame)
        .await
        .map_err(|e| AgentError::ConnectionError(format!("send failed: {e}")))?;
    Ok(())
}

/// Receive and decrypt an ECNP message from a stream.
pub async fn receive_encrypted_message(
    stream: &mut tokio::net::TcpStream,
    session_mgr: &mut SessionManager,
    session_id: &str,
) -> Result<(MessageType, Vec<u8>), AgentError> {
    use tokio::io::AsyncReadExt;

    let mut buf = vec![0u8; 65536];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| AgentError::ConnectionError(format!("receive failed: {e}")))?;

    if n == 0 {
        return Err(AgentError::ConnectionError("peer closed connection".into()));
    }

    let msg = EcnpCodec::decode(&buf[..n])?;
    let msg_type = MessageType::try_from(msg.msg_type)?;
    let plaintext = session_mgr.decrypt(session_id, &msg.payload)?;
    Ok((msg_type, plaintext))
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

    // -----------------------------------------------------------------------
    // ConnectionPool tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_connection_pool_track_and_connect() {
        let mut pool = ConnectionPool::new(3);
        let ci = pool.track_connect("peer-1", "192.168.1.10:8443");
        assert_eq!(ci.state, ConnectionState::Connecting);
        assert!(ci.session_id.is_none());

        pool.mark_connected("peer-1", "sess-abc");
        let ci = pool.get("peer-1").unwrap();
        assert_eq!(ci.state, ConnectionState::Connected);
        assert_eq!(ci.session_id.as_deref(), Some("sess-abc"));
        assert!(ci.connected_at.is_some());
    }

    #[test]
    fn test_connection_pool_disconnect() {
        let mut pool = ConnectionPool::new(3);
        pool.track_connect("peer-1", "10.0.0.1:8443");
        pool.mark_connected("peer-1", "sess-1");
        assert!(pool.is_connected("peer-1"));

        pool.mark_disconnected("peer-1");
        assert!(!pool.is_connected("peer-1"));
        assert!(pool.session_id("peer-1").is_none());
    }

    #[test]
    fn test_connection_pool_reconnect_limit() {
        let mut pool = ConnectionPool::new(2);
        pool.track_connect("peer-1", "10.0.0.1:8443");

        assert!(pool.try_reconnect("peer-1")); // attempt 1
        assert!(pool.try_reconnect("peer-1")); // attempt 2
        assert!(!pool.try_reconnect("peer-1")); // exceeds max
        assert_eq!(pool.get("peer-1").unwrap().state, ConnectionState::Failed);
    }

    #[test]
    fn test_connection_pool_list_and_remove() {
        let mut pool = ConnectionPool::new(3);
        pool.track_connect("a", "1.1.1.1:8443");
        pool.track_connect("b", "2.2.2.2:8443");
        assert_eq!(pool.list_all().len(), 2);

        assert!(pool.remove("a"));
        assert_eq!(pool.list_all().len(), 1);
        assert!(!pool.remove("a")); // already removed
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Connected.to_string(), "Connected");
        assert_eq!(ConnectionState::Reconnecting.to_string(), "Reconnecting");
        assert_eq!(ConnectionState::Failed.to_string(), "Failed");
    }

    // -----------------------------------------------------------------------
    // HandshakePayload tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_handshake_payload() {
        let pub_key = [42u8; 32];
        let sig = vec![1u8; 64];
        let hp = build_handshake_payload(&pub_key, &sig, "dev-1", "my-agent");
        assert_eq!(hp.device_id, "dev-1");
        assert_eq!(hp.agent_name, "my-agent");
        assert_eq!(hp.x25519_public_hex.len(), 64); // 32 bytes → 64 hex
        assert_eq!(hp.ed25519_signature_hex.len(), 128); // 64 bytes → 128 hex
    }

    #[test]
    fn test_parse_handshake_public_key() {
        let pub_key = [7u8; 32];
        let hp = HandshakePayload {
            x25519_public_hex: hex::encode(pub_key),
            ed25519_signature_hex: hex::encode([0u8; 64]),
            device_id: "d1".into(),
            agent_name: "a1".into(),
        };
        let parsed = parse_handshake_public_key(&hp).unwrap();
        assert_eq!(parsed, pub_key);
    }

    #[test]
    fn test_parse_handshake_invalid_hex() {
        let hp = HandshakePayload {
            x25519_public_hex: "not-hex!".into(),
            ed25519_signature_hex: "00".into(),
            device_id: "d".into(),
            agent_name: "a".into(),
        };
        assert!(parse_handshake_public_key(&hp).is_err());
    }

    #[test]
    fn test_parse_handshake_wrong_length() {
        let hp = HandshakePayload {
            x25519_public_hex: hex::encode([0u8; 16]), // 16 bytes, not 32
            ed25519_signature_hex: hex::encode([0u8; 64]),
            device_id: "d".into(),
            agent_name: "a".into(),
        };
        assert!(parse_handshake_public_key(&hp).is_err());
    }

    #[test]
    fn test_handshake_payload_roundtrip_json() {
        let hp = build_handshake_payload(&[9u8; 32], &[0u8; 64], "dev", "agent");
        let json = serde_json::to_string(&hp).unwrap();
        let hp2: HandshakePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(hp2.device_id, "dev");
        assert_eq!(hp2.x25519_public_hex, hp.x25519_public_hex);
    }

    // -----------------------------------------------------------------------
    // Async handshake integration test (loopback)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_handshake_and_encrypted_communication() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Generate keys for both sides
        let secret_a = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_a = x25519_dalek::PublicKey::from(&secret_a);
        let secret_b = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let _public_b = x25519_dalek::PublicKey::from(&secret_b);

        let payload_a =
            build_handshake_payload(public_a.as_bytes(), &[0u8; 64], "agent-a", "Alice");

        // Server task: accept, read handshake, reply with handshake
        let secret_b_clone = secret_b.to_bytes();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            // Read client handshake
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).await.unwrap();
            let msg = EcnpCodec::decode(&buf[..n]).unwrap();
            let client_hs: HandshakePayload = serde_json::from_slice(&msg.payload).unwrap();

            // Send server handshake
            let secret_b_s = x25519_dalek::StaticSecret::from(secret_b_clone);
            let public_b_s = x25519_dalek::PublicKey::from(&secret_b_s);
            let server_hs =
                build_handshake_payload(public_b_s.as_bytes(), &[0u8; 64], "agent-b", "Bob");
            let resp_json = serde_json::to_vec(&server_hs).unwrap();
            let resp_frame = EcnpCodec::encode(MessageType::Handshake, &resp_json).unwrap();
            stream.write_all(&resp_frame).await.unwrap();

            // Derive session on server side
            let remote_pub = parse_handshake_public_key(&client_hs).unwrap();
            let mut session_mgr = SessionManager::new();
            let info = session_mgr
                .create_session("agent-a", &secret_b_clone, &remote_pub)
                .unwrap();

            // Receive encrypted data frame
            let (_, plaintext) =
                receive_encrypted_message(&mut stream, &mut session_mgr, &info.session_id)
                    .await
                    .unwrap();
            assert_eq!(plaintext, b"hello from client");

            // Send encrypted reply
            send_encrypted_message(
                &mut stream,
                &mut session_mgr,
                &info.session_id,
                MessageType::Data,
                b"hello from server",
            )
            .await
            .unwrap();
        });

        // Client side
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut session_mgr = SessionManager::new();
        let (session_id, remote_hs) = perform_handshake(
            &mut stream,
            &mut session_mgr,
            &secret_a.to_bytes(),
            &payload_a,
        )
        .await
        .unwrap();

        assert_eq!(remote_hs.device_id, "agent-b");
        assert!(!session_id.is_empty());

        // Send encrypted data
        send_encrypted_message(
            &mut stream,
            &mut session_mgr,
            &session_id,
            MessageType::Data,
            b"hello from client",
        )
        .await
        .unwrap();

        // Receive encrypted reply
        let (msg_type, plaintext) =
            receive_encrypted_message(&mut stream, &mut session_mgr, &session_id)
                .await
                .unwrap();
        assert_eq!(msg_type, MessageType::Data);
        assert_eq!(plaintext, b"hello from server");

        server.await.unwrap();
    }
}

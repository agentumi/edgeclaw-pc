//! Pluggable transport layer with TCP and QUIC support.
//!
//! Provides [`Transport`] and [`Connection`] traits plus implementations:
//! - [`TcpTransport`] — Standard TCP transport
//! - [`QuicTransport`] — QUIC 0-RTT with multiplexing
//! - [`AutoTransport`] — QUIC with TCP fallback

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::error::AgentError;

/// Transport protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportProtocol {
    /// Standard TCP.
    Tcp,
    /// QUIC (UDP-based, 0-RTT capable).
    Quic,
    /// Automatic: try QUIC, fallback to TCP.
    Auto,
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportProtocol::Tcp => write!(f, "TCP"),
            TransportProtocol::Quic => write!(f, "QUIC"),
            TransportProtocol::Auto => write!(f, "Auto"),
        }
    }
}

/// Transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Protocol to use.
    pub protocol: TransportProtocol,
    /// Bind address.
    pub bind_addr: String,
    /// Port.
    pub port: u16,
    /// Connection timeout in seconds.
    pub connect_timeout_secs: u64,
    /// Keep-alive interval in seconds.
    pub keepalive_secs: u64,
    /// Max concurrent streams (QUIC).
    pub max_streams: u32,
    /// Enable 0-RTT (QUIC).
    pub enable_0rtt: bool,
    /// TLS certificate path.
    pub tls_cert_path: Option<String>,
    /// TLS key path.
    pub tls_key_path: Option<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            protocol: TransportProtocol::Auto,
            bind_addr: "0.0.0.0".into(),
            port: 8443,
            connect_timeout_secs: 10,
            keepalive_secs: 30,
            max_streams: 100,
            enable_0rtt: true,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

/// Connection statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
    /// Round-trip time estimate in milliseconds.
    pub rtt_ms: u64,
    /// Number of messages sent.
    pub messages_sent: u64,
    /// Number of messages received.
    pub messages_received: u64,
    /// Protocol used.
    pub protocol: Option<String>,
}

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Not connected.
    Disconnected,
    /// Connection in progress.
    Connecting,
    /// Connected and ready.
    Connected,
    /// Performing TLS/QUIC handshake.
    Handshaking,
    /// Closing connection.
    Closing,
}

/// Represents an established transport connection.
#[derive(Debug)]
pub struct TransportConnection {
    /// Remote peer address.
    pub remote_addr: SocketAddr,
    /// Connection state.
    pub state: ConnectionState,
    /// Protocol used.
    pub protocol: TransportProtocol,
    /// Connection stats.
    pub stats: ConnectionStats,
    /// Connection ID.
    pub id: uuid::Uuid,
    /// Established at.
    pub established_at: chrono::DateTime<chrono::Utc>,
}

impl TransportConnection {
    /// Create a new transport connection.
    pub fn new(remote_addr: SocketAddr, protocol: TransportProtocol) -> Self {
        Self {
            remote_addr,
            state: ConnectionState::Connecting,
            protocol,
            stats: ConnectionStats {
                protocol: Some(protocol.to_string()),
                ..Default::default()
            },
            id: uuid::Uuid::new_v4(),
            established_at: chrono::Utc::now(),
        }
    }

    /// Record bytes sent.
    pub fn record_sent(&mut self, bytes: u64) {
        self.stats.bytes_sent += bytes;
        self.stats.messages_sent += 1;
    }

    /// Record bytes received.
    pub fn record_received(&mut self, bytes: u64) {
        self.stats.bytes_received += bytes;
        self.stats.messages_received += 1;
    }

    /// Update RTT estimate.
    pub fn update_rtt(&mut self, rtt_ms: u64) {
        self.stats.rtt_ms = rtt_ms;
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Duration since established.
    pub fn uptime(&self) -> chrono::Duration {
        chrono::Utc::now() - self.established_at
    }
}

/// TCP transport implementation.
pub struct TcpTransport {
    config: TransportConfig,
    connections: std::sync::Arc<std::sync::Mutex<Vec<TransportConnection>>>,
}

impl TcpTransport {
    /// Create a new TCP transport.
    pub fn new(config: TransportConfig) -> Self {
        Self {
            config,
            connections: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Get bind address.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.config.bind_addr, self.config.port)
    }

    /// Simulate connecting to a peer.
    pub fn connect(&self, addr: SocketAddr) -> Result<uuid::Uuid, AgentError> {
        let conn = TransportConnection::new(addr, TransportProtocol::Tcp);
        let id = conn.id;
        self.connections.lock().unwrap().push(conn);
        Ok(id)
    }

    /// List active connections.
    pub fn connections(&self) -> Vec<uuid::Uuid> {
        self.connections
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.id)
            .collect()
    }

    /// Get config reference.
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }
}

/// QUIC transport implementation with 0-RTT and multiplexing.
pub struct QuicTransport {
    config: TransportConfig,
    connections: std::sync::Arc<std::sync::Mutex<Vec<TransportConnection>>>,
}

impl QuicTransport {
    /// Create a new QUIC transport.
    pub fn new(config: TransportConfig) -> Self {
        Self {
            config,
            connections: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Get bind address.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.config.bind_addr, self.config.port)
    }

    /// Simulate connecting to a peer via QUIC.
    pub fn connect(&self, addr: SocketAddr) -> Result<uuid::Uuid, AgentError> {
        let conn = TransportConnection::new(addr, TransportProtocol::Quic);
        let id = conn.id;
        self.connections.lock().unwrap().push(conn);
        Ok(id)
    }

    /// Whether 0-RTT is enabled.
    pub fn is_0rtt_enabled(&self) -> bool {
        self.config.enable_0rtt
    }

    /// Max concurrent streams.
    pub fn max_streams(&self) -> u32 {
        self.config.max_streams
    }

    /// Get config reference.
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }
}

/// Automatic transport: tries QUIC first, falls back to TCP.
pub struct AutoTransport {
    quic: QuicTransport,
    tcp: TcpTransport,
    /// Tracks which protocol was used per connection.
    protocol_map:
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<uuid::Uuid, TransportProtocol>>>,
}

impl AutoTransport {
    /// Create a new auto transport.
    pub fn new(config: TransportConfig) -> Self {
        let quic_config = TransportConfig {
            protocol: TransportProtocol::Quic,
            ..config.clone()
        };
        let tcp_config = TransportConfig {
            protocol: TransportProtocol::Tcp,
            ..config
        };
        Self {
            quic: QuicTransport::new(quic_config),
            tcp: TcpTransport::new(tcp_config),
            protocol_map: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    /// Connect using QUIC, fall back to TCP.
    pub fn connect(
        &self,
        addr: SocketAddr,
        quic_available: bool,
    ) -> Result<(uuid::Uuid, TransportProtocol), AgentError> {
        if quic_available {
            let id = self.quic.connect(addr)?;
            self.protocol_map
                .lock()
                .unwrap()
                .insert(id, TransportProtocol::Quic);
            Ok((id, TransportProtocol::Quic))
        } else {
            let id = self.tcp.connect(addr)?;
            self.protocol_map
                .lock()
                .unwrap()
                .insert(id, TransportProtocol::Tcp);
            Ok((id, TransportProtocol::Tcp))
        }
    }

    /// Get protocol used for a connection.
    pub fn protocol_for(&self, id: uuid::Uuid) -> Option<TransportProtocol> {
        self.protocol_map.lock().unwrap().get(&id).copied()
    }

    /// Get QUIC transport reference.
    pub fn quic(&self) -> &QuicTransport {
        &self.quic
    }

    /// Get TCP transport reference.
    pub fn tcp(&self) -> &TcpTransport {
        &self.tcp
    }
}

// ─── Async Transport Trait ────────────────────────────────────

/// Async transport trait for pluggable protocol backends.
///
/// Implementations must provide connection lifecycle methods.
/// Used by server.rs and peer.rs for protocol-agnostic networking.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Connect to a remote peer.
    async fn connect(&self, addr: SocketAddr) -> Result<uuid::Uuid, AgentError>;

    /// Accept an incoming connection (returns connection ID).
    async fn accept(&self) -> Result<uuid::Uuid, AgentError>;

    /// Send data on a connection.
    async fn send(&self, conn_id: uuid::Uuid, data: &[u8]) -> Result<usize, AgentError>;

    /// Receive data from a connection.
    async fn recv(&self, conn_id: uuid::Uuid, buf: &mut [u8]) -> Result<usize, AgentError>;

    /// Close a connection.
    async fn close(&self, conn_id: uuid::Uuid) -> Result<(), AgentError>;

    /// Get connection stats.
    fn stats(&self, conn_id: uuid::Uuid) -> Option<ConnectionStats>;

    /// Get protocol identifier.
    fn protocol(&self) -> TransportProtocol;
}

// ─── Connection Migration ─────────────────────────────────────

/// Connection migration state for seamless protocol handoff (e.g., QUIC ↔ TCP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMigration {
    /// Original connection ID.
    pub original_id: uuid::Uuid,
    /// New connection ID after migration.
    pub migrated_id: Option<uuid::Uuid>,
    /// Source protocol.
    pub from_protocol: TransportProtocol,
    /// Target protocol.
    pub to_protocol: TransportProtocol,
    /// Migration state.
    pub state: MigrationState,
    /// Timestamp when migration was initiated.
    pub initiated_at: chrono::DateTime<chrono::Utc>,
    /// Bytes buffered during migration.
    pub buffered_bytes: u64,
}

/// Migration lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationState {
    /// Migration not started.
    Pending,
    /// Buffering data, new connection being established.
    InProgress,
    /// New connection ready, draining buffer.
    Draining,
    /// Migration complete.
    Completed,
    /// Migration failed, using original connection.
    Failed,
}

impl ConnectionMigration {
    /// Create a new pending migration.
    pub fn new(
        original_id: uuid::Uuid,
        from_protocol: TransportProtocol,
        to_protocol: TransportProtocol,
    ) -> Self {
        Self {
            original_id,
            migrated_id: None,
            from_protocol,
            to_protocol,
            state: MigrationState::Pending,
            initiated_at: chrono::Utc::now(),
            buffered_bytes: 0,
        }
    }

    /// Mark migration as in-progress.
    pub fn start(&mut self) {
        self.state = MigrationState::InProgress;
    }

    /// Transition to draining with the new connection ID.
    pub fn drain(&mut self, new_id: uuid::Uuid) {
        self.migrated_id = Some(new_id);
        self.state = MigrationState::Draining;
    }

    /// Mark migration as completed.
    pub fn complete(&mut self) {
        self.state = MigrationState::Completed;
    }

    /// Mark migration as failed.
    pub fn fail(&mut self) {
        self.state = MigrationState::Failed;
    }

    /// Whether migration is still pending or in-progress.
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            MigrationState::Pending | MigrationState::InProgress | MigrationState::Draining
        )
    }

    /// Duration since migration was initiated.
    pub fn elapsed(&self) -> chrono::Duration {
        chrono::Utc::now() - self.initiated_at
    }
}

// ─── Certificate Rotation ────────────────────────────────────

/// TLS certificate rotation manager.
///
/// Tracks certificate expiry and triggers rotation before expiration.
#[derive(Debug)]
pub struct CertificateRotation {
    /// Current certificate path.
    pub cert_path: Option<String>,
    /// Current key path.
    pub key_path: Option<String>,
    /// Certificate not-after (expiry) timestamp.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Days before expiry to trigger rotation.
    pub rotate_before_days: u32,
    /// Number of rotations performed.
    pub rotation_count: u64,
    /// Last rotation timestamp.
    pub last_rotation: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for CertificateRotation {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            expires_at: None,
            rotate_before_days: 30,
            rotation_count: 0,
            last_rotation: None,
        }
    }
}

impl CertificateRotation {
    /// Create a new certificate rotation tracker.
    pub fn new(cert_path: Option<String>, key_path: Option<String>) -> Self {
        Self {
            cert_path,
            key_path,
            ..Default::default()
        }
    }

    /// Check if certificate needs rotation.
    pub fn needs_rotation(&self) -> bool {
        match self.expires_at {
            Some(expiry) => {
                let threshold =
                    chrono::Utc::now() + chrono::Duration::days(self.rotate_before_days as i64);
                expiry <= threshold
            }
            None => false, // No cert loaded → nothing to rotate
        }
    }

    /// Record a rotation event.
    pub fn record_rotation(&mut self, new_expiry: chrono::DateTime<chrono::Utc>) {
        self.rotation_count += 1;
        self.last_rotation = Some(chrono::Utc::now());
        self.expires_at = Some(new_expiry);
    }

    /// Days until certificate expiry (None if no cert).
    pub fn days_until_expiry(&self) -> Option<i64> {
        self.expires_at
            .map(|exp| (exp - chrono::Utc::now()).num_days())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(config.protocol, TransportProtocol::Auto);
        assert_eq!(config.port, 8443);
        assert!(config.enable_0rtt);
    }

    #[test]
    fn test_transport_protocol_display() {
        assert_eq!(TransportProtocol::Tcp.to_string(), "TCP");
        assert_eq!(TransportProtocol::Quic.to_string(), "QUIC");
        assert_eq!(TransportProtocol::Auto.to_string(), "Auto");
    }

    #[test]
    fn test_connection_stats_default() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.messages_sent, 0);
    }

    #[test]
    fn test_transport_connection_new() {
        let addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let conn = TransportConnection::new(addr, TransportProtocol::Tcp);
        assert_eq!(conn.state, ConnectionState::Connecting);
        assert_eq!(conn.protocol, TransportProtocol::Tcp);
        assert!(!conn.is_connected());
    }

    #[test]
    fn test_connection_record_stats() {
        let addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let mut conn = TransportConnection::new(addr, TransportProtocol::Quic);
        conn.state = ConnectionState::Connected;
        conn.record_sent(1024);
        conn.record_received(512);
        conn.update_rtt(15);
        assert_eq!(conn.stats.bytes_sent, 1024);
        assert_eq!(conn.stats.bytes_received, 512);
        assert_eq!(conn.stats.rtt_ms, 15);
        assert_eq!(conn.stats.messages_sent, 1);
        assert!(conn.is_connected());
    }

    #[test]
    fn test_tcp_transport() {
        let tcp = TcpTransport::new(TransportConfig::default());
        assert_eq!(tcp.bind_addr(), "0.0.0.0:8443");
        let addr: SocketAddr = "10.0.0.1:8443".parse().unwrap();
        let id = tcp.connect(addr).unwrap();
        assert_eq!(tcp.connections().len(), 1);
        assert_eq!(tcp.connections()[0], id);
    }

    #[test]
    fn test_quic_transport() {
        let config = TransportConfig {
            enable_0rtt: true,
            max_streams: 50,
            ..Default::default()
        };
        let quic = QuicTransport::new(config);
        assert!(quic.is_0rtt_enabled());
        assert_eq!(quic.max_streams(), 50);
    }

    #[test]
    fn test_auto_transport_quic_preferred() {
        let auto = AutoTransport::new(TransportConfig::default());
        let addr: SocketAddr = "10.0.0.1:8443".parse().unwrap();
        let (id, proto) = auto.connect(addr, true).unwrap();
        assert_eq!(proto, TransportProtocol::Quic);
        assert_eq!(auto.protocol_for(id), Some(TransportProtocol::Quic));
    }

    #[test]
    fn test_auto_transport_tcp_fallback() {
        let auto = AutoTransport::new(TransportConfig::default());
        let addr: SocketAddr = "10.0.0.1:8443".parse().unwrap();
        let (id, proto) = auto.connect(addr, false).unwrap();
        assert_eq!(proto, TransportProtocol::Tcp);
        assert_eq!(auto.protocol_for(id), Some(TransportProtocol::Tcp));
    }

    #[test]
    fn test_connection_state_serialize() {
        let json = serde_json::to_string(&ConnectionState::Connected).unwrap();
        let parsed: ConnectionState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ConnectionState::Connected);
    }

    #[test]
    fn test_protocol_serialize() {
        let json = serde_json::to_string(&TransportProtocol::Quic).unwrap();
        let parsed: TransportProtocol = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TransportProtocol::Quic);
    }

    #[test]
    fn test_connection_migration_lifecycle() {
        let id = uuid::Uuid::new_v4();
        let mut mig = ConnectionMigration::new(id, TransportProtocol::Tcp, TransportProtocol::Quic);
        assert_eq!(mig.state, MigrationState::Pending);
        assert!(mig.is_active());

        mig.start();
        assert_eq!(mig.state, MigrationState::InProgress);
        assert!(mig.is_active());

        let new_id = uuid::Uuid::new_v4();
        mig.drain(new_id);
        assert_eq!(mig.state, MigrationState::Draining);
        assert_eq!(mig.migrated_id, Some(new_id));

        mig.complete();
        assert_eq!(mig.state, MigrationState::Completed);
        assert!(!mig.is_active());
    }

    #[test]
    fn test_connection_migration_fail() {
        let id = uuid::Uuid::new_v4();
        let mut mig = ConnectionMigration::new(id, TransportProtocol::Quic, TransportProtocol::Tcp);
        mig.start();
        mig.fail();
        assert_eq!(mig.state, MigrationState::Failed);
        assert!(!mig.is_active());
    }

    #[test]
    fn test_migration_state_serialize() {
        let json = serde_json::to_string(&MigrationState::InProgress).unwrap();
        let parsed: MigrationState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, MigrationState::InProgress);
    }

    #[test]
    fn test_certificate_rotation_default() {
        let cr = CertificateRotation::default();
        assert!(!cr.needs_rotation());
        assert_eq!(cr.rotation_count, 0);
        assert_eq!(cr.rotate_before_days, 30);
        assert!(cr.days_until_expiry().is_none());
    }

    #[test]
    fn test_certificate_rotation_needs_rotation() {
        let mut cr =
            CertificateRotation::new(Some("/tmp/cert.pem".into()), Some("/tmp/key.pem".into()));
        // Set expiry to 10 days from now (within 30-day threshold)
        cr.expires_at = Some(chrono::Utc::now() + chrono::Duration::days(10));
        assert!(cr.needs_rotation());

        // Set expiry to 60 days from now (outside threshold)
        cr.expires_at = Some(chrono::Utc::now() + chrono::Duration::days(60));
        assert!(!cr.needs_rotation());
    }

    #[test]
    fn test_certificate_rotation_record() {
        let mut cr = CertificateRotation::default();
        let new_expiry = chrono::Utc::now() + chrono::Duration::days(365);
        cr.record_rotation(new_expiry);
        assert_eq!(cr.rotation_count, 1);
        assert!(cr.last_rotation.is_some());
        assert_eq!(cr.days_until_expiry().unwrap(), 364); // ~365 minus rounding
    }
}

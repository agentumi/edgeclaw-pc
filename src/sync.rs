//! Mobile-Desktop synchronization server.
//!
//! Provides [`SyncServer`] for accepting mobile connections and handling
//! configuration sync, status push, and remote execution requests.

use serde::{Deserialize, Serialize};

use crate::error::AgentError;

// ─── Sync Message Types ────────────────────────────────────

/// Synchronization message exchanged between mobile and desktop.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SyncMessage {
    /// Configuration synchronization (desktop → mobile or vice versa).
    ConfigSync {
        config_hash: String,
        config_data: String,
    },
    /// Remote command execution request (mobile → desktop).
    RemoteExec { command: String, args: Vec<String> },
    /// Remote execution result (desktop → mobile).
    ExecResult {
        success: bool,
        output: String,
        exit_code: i32,
    },
    /// Periodic status push (desktop → mobile).
    StatusPush {
        cpu_percent: f64,
        memory_percent: f64,
        disk_percent: f64,
        uptime_secs: u64,
        active_peers: usize,
        active_sessions: usize,
    },
    /// Heartbeat / keep-alive.
    Ping { timestamp: u64 },
    /// Heartbeat response.
    Pong { timestamp: u64 },
}

/// Sync server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// TCP port for sync connections (default 9446).
    pub port: u16,
    /// Status push interval in seconds.
    pub push_interval_secs: u64,
    /// Maximum connected mobile clients.
    pub max_clients: usize,
    /// Require authentication for sync connections.
    pub require_auth: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            port: 9446,
            push_interval_secs: 30,
            max_clients: 8,
            require_auth: true,
        }
    }
}

/// Connected mobile client info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncClient {
    /// Client identifier (device fingerprint).
    pub client_id: String,
    /// Remote address.
    pub address: String,
    /// Connection time.
    pub connected_at: String,
    /// Last message time.
    pub last_seen: String,
    /// Device name (if provided).
    pub device_name: Option<String>,
}

/// Sync server that accepts mobile connections.
pub struct SyncServer {
    config: SyncConfig,
    clients: std::sync::Arc<std::sync::Mutex<Vec<SyncClient>>>,
}

impl SyncServer {
    /// Create a new sync server with the given configuration.
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            clients: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Get the listening port.
    pub fn port(&self) -> u16 {
        self.config.port
    }

    /// Get the push interval.
    pub fn push_interval_secs(&self) -> u64 {
        self.config.push_interval_secs
    }

    /// Check if authentication is required.
    pub fn require_auth(&self) -> bool {
        self.config.require_auth
    }

    /// Get the number of connected clients.
    pub fn client_count(&self) -> usize {
        self.clients.lock().unwrap().len()
    }

    /// Register a new client connection.
    pub fn add_client(&self, client: SyncClient) -> Result<(), AgentError> {
        let mut clients = self.clients.lock().unwrap();
        if clients.len() >= self.config.max_clients {
            return Err(AgentError::ExecutionError(format!(
                "Max sync clients ({}) reached",
                self.config.max_clients
            )));
        }
        clients.push(client);
        Ok(())
    }

    /// Remove a client by ID.
    pub fn remove_client(&self, client_id: &str) -> bool {
        let mut clients = self.clients.lock().unwrap();
        let before = clients.len();
        clients.retain(|c| c.client_id != client_id);
        clients.len() < before
    }

    /// List all connected clients.
    pub fn list_clients(&self) -> Vec<SyncClient> {
        self.clients.lock().unwrap().clone()
    }

    /// Build a StatusPush message from current system state.
    pub fn build_status_push(
        cpu: f64,
        memory: f64,
        disk: f64,
        uptime: u64,
        peers: usize,
        sessions: usize,
    ) -> SyncMessage {
        SyncMessage::StatusPush {
            cpu_percent: cpu,
            memory_percent: memory,
            disk_percent: disk,
            uptime_secs: uptime,
            active_peers: peers,
            active_sessions: sessions,
        }
    }

    /// Serialize a SyncMessage for wire transfer.
    pub fn encode_message(msg: &SyncMessage) -> Result<Vec<u8>, AgentError> {
        serde_json::to_vec(msg).map_err(|e| AgentError::ExecutionError(format!("Sync encode: {e}")))
    }

    /// Deserialize a SyncMessage from bytes.
    pub fn decode_message(data: &[u8]) -> Result<SyncMessage, AgentError> {
        serde_json::from_slice(data)
            .map_err(|e| AgentError::ExecutionError(format!("Sync decode: {e}")))
    }

    /// Process an incoming sync message and return a response if needed.
    pub fn handle_message(&self, msg: &SyncMessage) -> Result<Option<SyncMessage>, AgentError> {
        match msg {
            SyncMessage::Ping { timestamp } => Ok(Some(SyncMessage::Pong {
                timestamp: *timestamp,
            })),
            SyncMessage::ConfigSync { config_hash, .. } => {
                tracing::info!(hash = %config_hash, "Received config sync");
                Ok(None)
            }
            SyncMessage::RemoteExec { command, args } => {
                tracing::info!(cmd = %command, "Remote exec request");
                // In production, this would call executor
                Ok(Some(SyncMessage::ExecResult {
                    success: true,
                    output: format!("Executed: {command} {}", args.join(" ")),
                    exit_code: 0,
                }))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_config_default() {
        let cfg = SyncConfig::default();
        assert_eq!(cfg.port, 9446);
        assert_eq!(cfg.push_interval_secs, 30);
        assert_eq!(cfg.max_clients, 8);
        assert!(cfg.require_auth);
    }

    #[test]
    fn test_sync_server_creation() {
        let server = SyncServer::new(SyncConfig::default());
        assert_eq!(server.port(), 9446);
        assert_eq!(server.client_count(), 0);
        assert!(server.require_auth());
    }

    #[test]
    fn test_add_and_remove_client() {
        let server = SyncServer::new(SyncConfig::default());
        let client = SyncClient {
            client_id: "mobile-1".into(),
            address: "192.168.1.10:12345".into(),
            connected_at: "2026-03-01T10:00:00Z".into(),
            last_seen: "2026-03-01T10:00:00Z".into(),
            device_name: Some("Pixel 9".into()),
        };
        server.add_client(client).unwrap();
        assert_eq!(server.client_count(), 1);

        let clients = server.list_clients();
        assert_eq!(clients[0].client_id, "mobile-1");

        assert!(server.remove_client("mobile-1"));
        assert_eq!(server.client_count(), 0);
    }

    #[test]
    fn test_max_clients_limit() {
        let cfg = SyncConfig {
            max_clients: 2,
            ..Default::default()
        };
        let server = SyncServer::new(cfg);
        for i in 0..2 {
            server
                .add_client(SyncClient {
                    client_id: format!("c{i}"),
                    address: "127.0.0.1:0".into(),
                    connected_at: String::new(),
                    last_seen: String::new(),
                    device_name: None,
                })
                .unwrap();
        }
        let result = server.add_client(SyncClient {
            client_id: "c2".into(),
            address: "127.0.0.1:0".into(),
            connected_at: String::new(),
            last_seen: String::new(),
            device_name: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_config_sync_roundtrip() {
        let msg = SyncMessage::ConfigSync {
            config_hash: "abc123".into(),
            config_data: "[agent]\nname = \"test\"".into(),
        };
        let bytes = SyncServer::encode_message(&msg).unwrap();
        let decoded = SyncServer::decode_message(&bytes).unwrap();
        if let SyncMessage::ConfigSync {
            config_hash,
            config_data,
        } = decoded
        {
            assert_eq!(config_hash, "abc123");
            assert!(config_data.contains("test"));
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_remote_exec_roundtrip() {
        let msg = SyncMessage::RemoteExec {
            command: "ls".into(),
            args: vec!["-la".into()],
        };
        let bytes = SyncServer::encode_message(&msg).unwrap();
        let decoded = SyncServer::decode_message(&bytes).unwrap();
        if let SyncMessage::RemoteExec { command, args } = decoded {
            assert_eq!(command, "ls");
            assert_eq!(args, vec!["-la"]);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_status_push() {
        let msg = SyncServer::build_status_push(45.0, 72.0, 55.0, 3600, 3, 2);
        if let SyncMessage::StatusPush {
            cpu_percent,
            active_peers,
            ..
        } = msg
        {
            assert!((cpu_percent - 45.0).abs() < f64::EPSILON);
            assert_eq!(active_peers, 3);
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_ping_pong() {
        let server = SyncServer::new(SyncConfig::default());
        let ping = SyncMessage::Ping { timestamp: 12345 };
        let response = server.handle_message(&ping).unwrap();
        assert!(response.is_some());
        if let Some(SyncMessage::Pong { timestamp }) = response {
            assert_eq!(timestamp, 12345);
        } else {
            panic!("Expected Pong");
        }
    }

    #[test]
    fn test_handle_remote_exec() {
        let server = SyncServer::new(SyncConfig::default());
        let msg = SyncMessage::RemoteExec {
            command: "echo".into(),
            args: vec!["hello".into()],
        };
        let response = server.handle_message(&msg).unwrap();
        assert!(response.is_some());
        if let Some(SyncMessage::ExecResult {
            success, output, ..
        }) = response
        {
            assert!(success);
            assert!(output.contains("echo"));
        } else {
            panic!("Expected ExecResult");
        }
    }

    #[test]
    fn test_sync_message_serialization() {
        let messages = vec![
            SyncMessage::Ping { timestamp: 1 },
            SyncMessage::Pong { timestamp: 1 },
            SyncMessage::ConfigSync {
                config_hash: "h".into(),
                config_data: "d".into(),
            },
            SyncMessage::RemoteExec {
                command: "c".into(),
                args: vec![],
            },
            SyncMessage::ExecResult {
                success: true,
                output: "ok".into(),
                exit_code: 0,
            },
            SyncMessage::StatusPush {
                cpu_percent: 10.0,
                memory_percent: 20.0,
                disk_percent: 30.0,
                uptime_secs: 100,
                active_peers: 1,
                active_sessions: 1,
            },
        ];
        for msg in &messages {
            let json = serde_json::to_string(msg).unwrap();
            assert!(!json.is_empty());
            let _: SyncMessage = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_handle_config_sync() {
        let server = SyncServer::new(SyncConfig::default());
        let msg = SyncMessage::ConfigSync {
            config_hash: "abc123".into(),
            config_data: "[agent]\nname = \"test\"".into(),
        };
        let response = server.handle_message(&msg).unwrap();
        assert!(response.is_none()); // ConfigSync returns None
    }

    #[test]
    fn test_handle_status_push() {
        let server = SyncServer::new(SyncConfig::default());
        let msg = SyncMessage::StatusPush {
            cpu_percent: 50.0,
            memory_percent: 60.0,
            disk_percent: 70.0,
            uptime_secs: 1000,
            active_peers: 2,
            active_sessions: 1,
        };
        let response = server.handle_message(&msg).unwrap();
        assert!(response.is_none()); // StatusPush returns None
    }

    #[test]
    fn test_push_interval() {
        let server = SyncServer::new(SyncConfig::default());
        assert_eq!(server.push_interval_secs(), 30);
    }
}

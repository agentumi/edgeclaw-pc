//! TCP / Transport-agnostic server for ECNP connections.
//!
//! Accepts and manages connections with handshake timeout,
//! connection tracking, and ECNP frame dispatch to message handlers.
//! Supports pluggable transport backends via the `Transport` trait
//! from `transport.rs`.

use crate::ecnp::{EcnpCodec, EcnpMessage};
use crate::error::AgentError;
use crate::protocol::MessageType;
use crate::security::ConnectionTracker;
use crate::transport::{Transport, TransportProtocol};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

/// TCP server configuration
pub struct TcpServerConfig {
    pub bind_addr: String,
    pub max_connections: usize,
    /// Handshake timeout in seconds (default: 5)
    pub handshake_timeout_secs: u64,
}

/// Message received from a client
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    pub peer_addr: String,
    pub message: EcnpMessage,
}

/// TCP server for receiving ECNP connections
pub struct TcpServer {
    config: TcpServerConfig,
    shutdown_tx: Option<broadcast::Sender<()>>,
    conn_tracker: Arc<ConnectionTracker>,
}

impl TcpServer {
    pub fn new(config: TcpServerConfig) -> Self {
        Self {
            config,
            shutdown_tx: None,
            conn_tracker: Arc::new(ConnectionTracker::new()),
        }
    }

    /// Start listening for connections
    pub async fn start(
        &mut self,
        message_tx: tokio::sync::mpsc::Sender<IncomingMessage>,
    ) -> Result<(), AgentError> {
        let listener = TcpListener::bind(&self.config.bind_addr)
            .await
            .map_err(|e| {
                AgentError::ConnectionError(format!(
                    "failed to bind {}: {}",
                    self.config.bind_addr, e
                ))
            })?;

        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        let max_conn = self.config.max_connections;
        let conn_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        info!(addr = %self.config.bind_addr, "TCP server listening");

        loop {
            let mut shutdown_rx = shutdown_tx.subscribe();

            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            // Check if this IP is locked out
                            let ip = addr.ip().to_string();
                            if self.conn_tracker.is_locked_out(&ip) {
                                warn!(addr = %addr, "rejecting locked-out peer");
                                drop(stream);
                                continue;
                            }

                            let current = conn_count.load(std::sync::atomic::Ordering::SeqCst);
                            if current >= max_conn {
                                warn!(addr = %addr, "max connections reached, rejecting");
                                drop(stream);
                                continue;
                            }

                            conn_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let tx = message_tx.clone();
                            let count = conn_count.clone();
                            let mut shutdown = shutdown_tx.subscribe();
                            let hs_timeout = self.config.handshake_timeout_secs;

                            tokio::spawn(async move {
                                info!(peer = %addr, "client connected");
                                if let Err(e) = handle_connection(stream, addr.to_string(), tx, &mut shutdown, hs_timeout).await {
                                    error!(peer = %addr, error = %e, "connection error");
                                }
                                count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                                info!(peer = %addr, "client disconnected");
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "accept error");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("TCP server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Signal the server to shut down
    pub fn shutdown(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(());
        }
    }
}

/// Handle a single TCP connection with handshake timeout
async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: String,
    message_tx: tokio::sync::mpsc::Sender<IncomingMessage>,
    shutdown: &mut broadcast::Receiver<()>,
    handshake_timeout_secs: u64,
) -> Result<(), AgentError> {
    let mut buf = vec![0u8; 65536]; // 64KB read buffer

    // Wait for initial handshake frame with timeout
    let first_read = tokio::time::timeout(
        std::time::Duration::from_secs(handshake_timeout_secs),
        stream.read(&mut buf),
    )
    .await;

    match first_read {
        Err(_) => {
            warn!(peer = %peer_addr, "handshake timeout ({}s)", handshake_timeout_secs);
            return Err(AgentError::ConnectionError("handshake timeout".into()));
        }
        Ok(Err(e)) => {
            return Err(AgentError::ConnectionError(e.to_string()));
        }
        Ok(Ok(0)) => {
            return Ok(()); // closed before handshake
        }
        Ok(Ok(n)) => match EcnpCodec::decode(&buf[..n]) {
            Ok(msg) => {
                let _ = message_tx
                    .send(IncomingMessage {
                        peer_addr: peer_addr.clone(),
                        message: msg,
                    })
                    .await;
            }
            Err(e) => {
                warn!(peer = %peer_addr, error = %e, "invalid handshake frame");
                let err_frame =
                    EcnpCodec::encode(MessageType::Error, b"invalid frame").unwrap_or_default();
                let _ = stream.write_all(&err_frame).await;
                return Err(AgentError::ConnectionError("invalid handshake".into()));
            }
        },
    }

    // Continue reading subsequent frames
    loop {
        tokio::select! {
            result = stream.read(&mut buf) => {
                match result {
                    Ok(0) => break, // connection closed
                    Ok(n) => {
                        match EcnpCodec::decode(&buf[..n]) {
                            Ok(msg) => {
                                let _ = message_tx.send(IncomingMessage {
                                    peer_addr: peer_addr.clone(),
                                    message: msg,
                                }).await;
                            }
                            Err(e) => {
                                warn!(peer = %peer_addr, error = %e, "invalid ECNP frame");
                                // Send error response
                                let err_frame = EcnpCodec::encode(
                                    MessageType::Error,
                                    b"invalid frame",
                                ).unwrap_or_default();
                                let _ = stream.write_all(&err_frame).await;
                            }
                        }
                    }
                    Err(e) => {
                        return Err(AgentError::ConnectionError(e.to_string()));
                    }
                }
            }
            _ = shutdown.recv() => {
                break;
            }
        }
    }

    Ok(())
}

/// Send an ECNP frame over a TCP stream
pub async fn send_frame(
    stream: &mut TcpStream,
    msg_type: MessageType,
    payload: &[u8],
) -> Result<(), AgentError> {
    let frame = EcnpCodec::encode(msg_type, payload)?;
    stream
        .write_all(&frame)
        .await
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;
    Ok(())
}

// ─── Transport-Agnostic Server ────────────────────────────────

/// Configuration for the transport-agnostic server
pub struct TransportServerConfig {
    pub bind_addr: String,
    pub max_connections: usize,
    pub handshake_timeout_secs: u64,
    pub protocol: TransportProtocol,
}

/// Transport-agnostic ECNP server that wraps any `Transport` implementation.
///
/// This supports both TCP and QUIC backends via the `Transport` trait.
/// For direct TCP usage, `TcpServer` remains available for backward compatibility.
pub struct TransportServer<T: Transport> {
    config: TransportServerConfig,
    transport: T,
    shutdown_tx: Option<broadcast::Sender<()>>,
    #[allow(dead_code)]
    conn_tracker: Arc<ConnectionTracker>,
}

impl<T: Transport + 'static> TransportServer<T> {
    /// Create a new transport server with the given backend.
    pub fn new(config: TransportServerConfig, transport: T) -> Self {
        Self {
            config,
            transport,
            shutdown_tx: None,
            conn_tracker: Arc::new(ConnectionTracker::new()),
        }
    }

    /// Start accepting connections via the Transport trait.
    ///
    /// Incoming data is dispatched as `IncomingMessage` to the provided channel.
    pub async fn start(
        &mut self,
        message_tx: tokio::sync::mpsc::Sender<IncomingMessage>,
    ) -> Result<(), AgentError> {
        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        let conn_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        info!(
            addr = %self.config.bind_addr,
            protocol = %self.config.protocol,
            "Transport server listening"
        );

        loop {
            let mut shutdown_rx = shutdown_tx.subscribe();

            tokio::select! {
                result = self.transport.accept() => {
                    match result {
                        Ok(conn_id) => {
                            let current = conn_count.load(std::sync::atomic::Ordering::SeqCst);
                            if current >= self.config.max_connections {
                                warn!(conn = %conn_id, "max connections reached, closing");
                                let _ = self.transport.close(conn_id).await;
                                continue;
                            }

                            conn_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            info!(conn = %conn_id, "transport connection accepted");

                            // Read initial handshake frame via transport
                            let mut buf = vec![0u8; 65536];
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(self.config.handshake_timeout_secs),
                                self.transport.recv(conn_id, &mut buf),
                            )
                            .await
                            {
                                Ok(Ok(n)) if n > 0 => {
                                    match EcnpCodec::decode(&buf[..n]) {
                                        Ok(msg) => {
                                            let _ = message_tx.send(IncomingMessage {
                                                peer_addr: conn_id.to_string(),
                                                message: msg,
                                            }).await;
                                        }
                                        Err(e) => {
                                            warn!(conn = %conn_id, error = %e, "invalid frame");
                                            let _ = self.transport.close(conn_id).await;
                                        }
                                    }
                                }
                                _ => {
                                    warn!(conn = %conn_id, "handshake timeout or empty read");
                                    let _ = self.transport.close(conn_id).await;
                                }
                            }

                            conn_count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                        }
                        Err(e) => {
                            error!(error = %e, "transport accept error");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Transport server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Signal the transport server to shut down.
    pub fn shutdown(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(());
        }
    }

    /// Get current protocol.
    pub fn protocol(&self) -> TransportProtocol {
        self.config.protocol
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_server_config() {
        let config = TcpServerConfig {
            bind_addr: "0.0.0.0:8443".to_string(),
            max_connections: 50,
            handshake_timeout_secs: 5,
        };
        assert_eq!(config.bind_addr, "0.0.0.0:8443");
        assert_eq!(config.max_connections, 50);
        assert_eq!(config.handshake_timeout_secs, 5);
    }

    #[tokio::test]
    async fn test_server_creation() {
        let config = TcpServerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            max_connections: 10,
            handshake_timeout_secs: 5,
        };
        let server = TcpServer::new(config);
        assert!(server.shutdown_tx.is_none());
    }

    #[test]
    fn test_transport_server_config() {
        let config = TransportServerConfig {
            bind_addr: "0.0.0.0:8443".to_string(),
            max_connections: 100,
            handshake_timeout_secs: 10,
            protocol: TransportProtocol::Tcp,
        };
        assert_eq!(config.bind_addr, "0.0.0.0:8443");
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.protocol, TransportProtocol::Tcp);
    }

    #[test]
    fn test_incoming_message_debug() {
        let msg = EcnpCodec::encode(MessageType::Heartbeat, b"ping").unwrap();
        let decoded = EcnpCodec::decode(&msg).unwrap();
        let incoming = IncomingMessage {
            peer_addr: "127.0.0.1:9443".to_string(),
            message: decoded,
        };
        let debug = format!("{:?}", incoming);
        assert!(debug.contains("127.0.0.1:9443"));
    }

    // ── New coverage tests ─────────────────────────────────

    #[tokio::test]
    async fn test_tcp_server_shutdown_noop_before_start() {
        let config = TcpServerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            max_connections: 10,
            handshake_timeout_secs: 5,
        };
        let server = TcpServer::new(config);
        // shutdown before start should be a no-op (no panic)
        server.shutdown();
    }

    #[tokio::test]
    async fn test_send_frame_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Connect a client
        let client_handle = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = client.read(&mut buf).await.unwrap();
            let msg = EcnpCodec::decode(&buf[..n]).unwrap();
            assert_eq!(msg.msg_type, MessageType::Heartbeat as u8);
        });

        let (stream, _) = listener.accept().await.unwrap();
        let mut server_stream = stream;
        send_frame(&mut server_stream, MessageType::Heartbeat, b"hello")
            .await
            .unwrap();

        client_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_server_start_and_connect() {
        let config = TcpServerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            max_connections: 10,
            handshake_timeout_secs: 5,
        };

        // Bind listener manually to get port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let mut server = TcpServer::new(TcpServerConfig {
            bind_addr: addr.to_string(),
            ..config
        });

        let (msg_tx, mut msg_rx) = tokio::sync::mpsc::channel(32);

        let server_handle = tokio::spawn(async move { server.start(msg_tx).await });

        // Wait for server to bind
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send a valid ECNP frame from client
        let handshake = EcnpCodec::encode(MessageType::Handshake, b"hello").unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&handshake).await.unwrap();

        // Receive the message
        let incoming = tokio::time::timeout(std::time::Duration::from_secs(2), msg_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert!(incoming.peer_addr.contains("127.0.0.1"));
        assert_eq!(incoming.message.msg_type, MessageType::Handshake as u8);

        server_handle.abort();
    }
}

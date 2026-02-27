//! TCP server for ECNP connections.
//!
//! Accepts and manages TCP connections with handshake timeout,
//! connection tracking, and ECNP frame dispatch to message handlers.

use crate::ecnp::{EcnpCodec, EcnpMessage};
use crate::error::AgentError;
use crate::protocol::MessageType;
use crate::security::ConnectionTracker;
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
}

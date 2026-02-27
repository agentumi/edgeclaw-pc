//! WebSocket server for real-time event streaming.
//!
//! Provides a [`WebSocketServer`] that upgrades HTTP connections to WebSocket,
//! authenticates clients, and bridges them to the [`EventBus`].
//! Supports up to 50 concurrent clients with 30-second heartbeat ping/pong.

use crate::error::AgentError;
use crate::events::{AgentEvent, EventBus};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, warn};

/// Maximum concurrent WebSocket clients
const MAX_WS_CLIENTS: usize = 50;

/// Heartbeat ping interval
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Pong timeout — disconnect if no pong received within this window
const PONG_TIMEOUT: Duration = Duration::from_secs(10);

/// WebSocket server configuration
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Bind address (e.g. "127.0.0.1:9445")
    pub bind_addr: String,
    /// Authentication token required for connection (empty = no auth)
    pub auth_token: String,
    /// Maximum clients
    pub max_clients: usize,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:9445".to_string(),
            auth_token: String::new(),
            max_clients: MAX_WS_CLIENTS,
        }
    }
}

/// Connected WebSocket client info
#[derive(Debug, Clone)]
pub struct WsClientInfo {
    pub peer_addr: String,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub authenticated: bool,
}

/// WebSocket server for real-time event distribution
pub struct WebSocketServer {
    config: WebSocketConfig,
    event_bus: Arc<EventBus>,
    clients: Arc<RwLock<HashMap<String, WsClientInfo>>>,
    shutdown_tx: Option<broadcast::Sender<()>>,
}

impl WebSocketServer {
    /// Create a new WebSocket server
    pub fn new(config: WebSocketConfig, event_bus: Arc<EventBus>) -> Self {
        Self {
            config,
            event_bus,
            clients: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx: None,
        }
    }

    /// Get the number of connected clients
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }

    /// Start the WebSocket server
    pub async fn start(&mut self) -> Result<(), AgentError> {
        let listener = TcpListener::bind(&self.config.bind_addr)
            .await
            .map_err(|e| {
                AgentError::ConnectionError(format!(
                    "WebSocket failed to bind {}: {}",
                    self.config.bind_addr, e
                ))
            })?;

        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        let auth_required = !self.config.auth_token.is_empty();
        let auth_token = self.config.auth_token.clone();
        let max_clients = self.config.max_clients;

        info!(
            addr = %self.config.bind_addr,
            auth = auth_required,
            max_clients = max_clients,
            "WebSocket server listening"
        );

        loop {
            let mut shutdown_rx = shutdown_tx.subscribe();

            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let peer_addr = addr.to_string();

                            // Check client limit
                            {
                                let clients = self.clients.read().await;
                                if clients.len() >= max_clients {
                                    warn!(peer = %peer_addr, "max WS clients reached, rejecting");
                                    drop(stream);
                                    continue;
                                }
                            }

                            let event_bus = self.event_bus.clone();
                            let clients = self.clients.clone();
                            let token = auth_token.clone();
                            let need_auth = auth_required;
                            let mut shutdown = shutdown_tx.subscribe();

                            tokio::spawn(async move {
                                if let Err(e) = handle_ws_client(
                                    stream,
                                    peer_addr.clone(),
                                    event_bus,
                                    clients,
                                    &token,
                                    need_auth,
                                    &mut shutdown,
                                ).await {
                                    warn!(peer = %peer_addr, error = %e, "WS client error");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "WebSocket accept error");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("WebSocket server shutting down");
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

/// Handle a single WebSocket client connection
async fn handle_ws_client(
    stream: tokio::net::TcpStream,
    peer_addr: String,
    event_bus: Arc<EventBus>,
    clients: Arc<RwLock<HashMap<String, WsClientInfo>>>,
    auth_token: &str,
    auth_required: bool,
    shutdown: &mut broadcast::Receiver<()>,
) -> Result<(), AgentError> {
    // Perform WebSocket upgrade
    let ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| AgentError::ConnectionError(format!("WS upgrade failed: {e}")))?;

    let (ws_sink, mut ws_stream_rx) = ws_stream.split();
    let ws_sink = Arc::new(Mutex::new(ws_sink));

    // Register client (unauthenticated initially)
    let client_id = peer_addr.clone();
    {
        let mut cl = clients.write().await;
        cl.insert(
            client_id.clone(),
            WsClientInfo {
                peer_addr: peer_addr.clone(),
                connected_at: chrono::Utc::now(),
                authenticated: !auth_required,
            },
        );
    }

    info!(peer = %peer_addr, "WebSocket client connected");

    // If auth required, wait for auth message first
    if auth_required {
        let authenticated = wait_for_auth(&mut ws_stream_rx, auth_token).await;
        if !authenticated {
            warn!(peer = %peer_addr, "WS authentication failed");
            // Remove client and close
            clients.write().await.remove(&client_id);
            let mut sink = ws_sink.lock().await;
            let _ = sink
                .send(Message::Text(
                    serde_json::json!({"error": "authentication failed"}).to_string(),
                ))
                .await;
            let _ = sink.close().await;
            return Ok(());
        }
        // Mark authenticated
        {
            let mut cl = clients.write().await;
            if let Some(info) = cl.get_mut(&client_id) {
                info.authenticated = true;
            }
        }
        // Send auth success
        let mut sink = ws_sink.lock().await;
        let _ = sink
            .send(Message::Text(
                serde_json::json!({"status": "authenticated"}).to_string(),
            ))
            .await;
        info!(peer = %peer_addr, "WS client authenticated");
    }

    // Subscribe to event bus
    let mut event_rx = event_bus.subscribe();

    // Heartbeat ping/pong tracking
    let last_pong = Arc::new(Mutex::new(std::time::Instant::now()));

    // Spawn event forwarder (EventBus → WebSocket)
    let sink_clone = ws_sink.clone();
    let pong_clone = last_pong.clone();
    let peer_clone = peer_addr.clone();
    let forward_handle = tokio::spawn(async move {
        let mut heartbeat_interval = tokio::time::interval(HEARTBEAT_INTERVAL);

        loop {
            tokio::select! {
                event = event_rx.recv() => {
                    match event {
                        Ok(evt) => {
                            if let Ok(json) = serde_json::to_string(&evt) {
                                let mut sink = sink_clone.lock().await;
                                if sink.send(Message::Text(json)).await.is_err() {
                                    break; // Client disconnected
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!(peer = %peer_clone, skipped = n, "WS client lagged, skipped events");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = heartbeat_interval.tick() => {
                    // Check pong timeout
                    let elapsed = pong_clone.lock().await.elapsed();
                    if elapsed > HEARTBEAT_INTERVAL + PONG_TIMEOUT {
                        warn!(peer = %peer_clone, "WS pong timeout, disconnecting");
                        break;
                    }
                    // Send ping
                    let mut sink = sink_clone.lock().await;
                    if sink.send(Message::Ping(vec![1, 2, 3, 4])).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Main message receiver (WebSocket → Agent)
    loop {
        tokio::select! {
            msg = ws_stream_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        handle_ws_message(&text, &event_bus, &peer_addr);
                    }
                    Some(Ok(Message::Pong(_))) => {
                        *last_pong.lock().await = std::time::Instant::now();
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    Some(Err(e)) => {
                        warn!(peer = %peer_addr, error = %e, "WS receive error");
                        break;
                    }
                    _ => {} // Ignore Binary, Ping (auto-responded by tungstenite)
                }
            }
            _ = shutdown.recv() => {
                break;
            }
        }
    }

    // Cleanup
    forward_handle.abort();
    clients.write().await.remove(&client_id);
    info!(peer = %peer_addr, "WebSocket client disconnected");

    Ok(())
}

/// Wait for an authentication message from the client
async fn wait_for_auth(
    ws_stream: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    >,
    expected_token: &str,
) -> bool {
    // Wait up to 10 seconds for auth message
    match tokio::time::timeout(Duration::from_secs(10), ws_stream.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            // Expected: {"auth": "<token>"}
            #[derive(serde::Deserialize)]
            struct AuthMsg {
                auth: String,
            }
            match serde_json::from_str::<AuthMsg>(&text) {
                Ok(msg) => msg.auth == expected_token,
                Err(_) => false,
            }
        }
        _ => false,
    }
}

/// Handle an incoming WebSocket text message from the client
fn handle_ws_message(text: &str, event_bus: &EventBus, peer_addr: &str) {
    // Parse incoming JSON message
    #[derive(serde::Deserialize)]
    struct WsCommand {
        #[serde(default)]
        action: String,
    }

    if let Ok(cmd) = serde_json::from_str::<WsCommand>(text) {
        match cmd.action.as_str() {
            "ping" => {
                event_bus.publish(AgentEvent::Heartbeat { uptime_secs: 0 });
            }
            _ => {
                warn!(peer = %peer_addr, action = %cmd.action, "unknown WS action");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_config_default() {
        let config = WebSocketConfig::default();
        assert_eq!(config.bind_addr, "127.0.0.1:9445");
        assert!(config.auth_token.is_empty());
        assert_eq!(config.max_clients, MAX_WS_CLIENTS);
    }

    #[test]
    fn test_ws_client_info() {
        let info = WsClientInfo {
            peer_addr: "127.0.0.1:12345".to_string(),
            connected_at: chrono::Utc::now(),
            authenticated: true,
        };
        assert!(info.authenticated);
        assert_eq!(info.peer_addr, "127.0.0.1:12345");
    }

    #[tokio::test]
    async fn test_websocket_server_creation() {
        let event_bus = Arc::new(EventBus::new(64));
        let config = WebSocketConfig::default();
        let server = WebSocketServer::new(config, event_bus);
        assert_eq!(server.client_count().await, 0);
        assert!(server.shutdown_tx.is_none());
    }

    #[test]
    fn test_handle_ws_message_ping() {
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        handle_ws_message(r#"{"action":"ping"}"#, &bus, "test");
        // Should have published a heartbeat
        let event = rx.try_recv();
        assert!(event.is_ok());
        assert!(matches!(event.unwrap(), AgentEvent::Heartbeat { .. }));
    }

    #[test]
    fn test_handle_ws_message_unknown() {
        let bus = EventBus::new(64);
        // Should not panic on unknown action
        handle_ws_message(r#"{"action":"unknown"}"#, &bus, "test");
    }

    #[test]
    fn test_handle_ws_message_invalid_json() {
        let bus = EventBus::new(64);
        // Should not panic on invalid JSON
        handle_ws_message("not json", &bus, "test");
    }

    #[tokio::test]
    async fn test_websocket_server_start_stop() {
        let event_bus = Arc::new(EventBus::new(64));
        let config = WebSocketConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            auth_token: String::new(),
            max_clients: 10,
        };
        let mut server = WebSocketServer::new(config, event_bus);

        // Start in background
        let handle = tokio::spawn(async move { server.start().await });

        // Give it a moment to bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Server is running. We can't easily shutdown from here since we moved it,
        // so we'll abort the task
        handle.abort();
    }

    #[tokio::test]
    async fn test_ws_connect_and_receive_event() {
        use tokio_tungstenite::connect_async;

        let _event_bus = Arc::new(EventBus::new(64));

        // Start server on random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let _ws_config = WebSocketConfig {
            bind_addr: addr.to_string(),
            auth_token: String::new(),
            max_clients: 10,
        };

        // We'll manually accept one connection for a focused test
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let (mut sink, _) = ws.split();

            // Send an event as JSON
            let event = AgentEvent::Heartbeat { uptime_secs: 99 };
            let json = serde_json::to_string(&event).unwrap();
            sink.send(Message::Text(json)).await.unwrap();
        });

        // Connect as client
        let url = format!("ws://{}", addr);
        let (ws, _) = connect_async(&url).await.unwrap();
        let (_, mut read) = ws.split();

        // Receive the event
        if let Some(Ok(Message::Text(text))) = read.next().await {
            let event: AgentEvent = serde_json::from_str(&text).unwrap();
            assert!(matches!(event, AgentEvent::Heartbeat { uptime_secs: 99 }));
        } else {
            panic!("expected text message");
        }

        server_handle.await.unwrap();
    }
}

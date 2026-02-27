//! Web UI HTTP server for the EdgeClaw Agent chat interface.
//!
//! Serves an embedded single-page chat application and exposes JSON API endpoints
//! for chat, quick actions, and status queries. Uses raw tokio TCP — no HTTP framework
//! dependency needed.

use crate::ai::QuickAction;
use crate::error::AgentError;
use crate::security::{RateLimitConfig, RateLimiter};
use crate::AgentEngine;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

/// Embedded HTML chat page (compiled into the binary)
const CHAT_HTML: &str = include_str!("../static/chat.html");

/// Web UI server configuration
#[derive(Debug, Clone)]
pub struct WebUiConfig {
    /// Address to bind (e.g. "127.0.0.1:9444")
    pub bind_addr: String,
}

/// Lightweight HTTP server for the chat web UI
pub struct WebUiServer {
    config: WebUiConfig,
    engine: Arc<AgentEngine>,
    shutdown_tx: Option<broadcast::Sender<()>>,
    rate_limiter: Arc<RateLimiter>,
}

impl WebUiServer {
    /// Create a new Web UI server
    pub fn new(config: WebUiConfig, engine: Arc<AgentEngine>) -> Self {
        Self {
            config,
            engine,
            shutdown_tx: None,
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
        }
    }

    /// Start serving HTTP requests
    pub async fn start(&mut self) -> Result<(), AgentError> {
        let listener = TcpListener::bind(&self.config.bind_addr)
            .await
            .map_err(|e| {
                AgentError::ConnectionError(format!(
                    "WebUI failed to bind {}: {}",
                    self.config.bind_addr, e
                ))
            })?;

        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        info!(addr = %self.config.bind_addr, "Web UI server listening");

        loop {
            let mut shutdown_rx = shutdown_tx.subscribe();
            let engine = self.engine.clone();

            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let eng = engine.clone();
                            let limiter = self.rate_limiter.clone();
                            let mut shutdown = shutdown_tx.subscribe();
                            tokio::spawn(async move {
                                if let Err(e) = handle_http(stream, eng, &limiter, &mut shutdown).await {
                                    warn!(peer = %addr, error = %e, "HTTP handler error");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "WebUI accept error");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Web UI server shutting down");
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

/// Handle a single HTTP connection (request/response cycle)
async fn handle_http(
    mut stream: TcpStream,
    engine: Arc<AgentEngine>,
    rate_limiter: &RateLimiter,
    shutdown: &mut broadcast::Receiver<()>,
) -> Result<(), AgentError> {
    // Rate-limit by peer IP
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let rate_result = rate_limiter.check(&peer_ip);
    if !rate_result.is_allowed() {
        send_response(
            &mut stream,
            429,
            "application/json",
            b"{\"error\":\"too many requests\"}",
        )
        .await?;
        return Ok(());
    }

    let mut buf = Vec::with_capacity(65536);
    let mut tmp = [0u8; 8192];

    // Read HTTP headers (loop until we see the header/body delimiter)
    loop {
        let n = tokio::select! {
            result = stream.read(&mut tmp) => {
                match result {
                    Ok(0) => return Ok(()),
                    Ok(n) => n,
                    Err(e) => return Err(AgentError::ConnectionError(e.to_string())),
                }
            }
            _ = shutdown.recv() => return Ok(()),
        };
        buf.extend_from_slice(&tmp[..n]);

        // Check if we have the complete headers
        let s = String::from_utf8_lossy(&buf);
        if s.contains("\r\n\r\n") || s.contains("\n\n") {
            // Check Content-Length and read remaining body if needed
            let content_length = parse_content_length(&s);
            let header_end = if let Some(idx) = s.find("\r\n\r\n") {
                idx + 4
            } else if let Some(idx) = s.find("\n\n") {
                idx + 2
            } else {
                buf.len()
            };

            let body_received = buf.len() - header_end;
            let body_remaining = content_length.saturating_sub(body_received);

            if body_remaining > 0 {
                let mut remaining = body_remaining;
                while remaining > 0 {
                    let n = tokio::select! {
                        result = stream.read(&mut tmp) => {
                            match result {
                                Ok(0) => break,
                                Ok(n) => n,
                                Err(e) => return Err(AgentError::ConnectionError(e.to_string())),
                            }
                        }
                        _ = shutdown.recv() => return Ok(()),
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    remaining = remaining.saturating_sub(n);
                }
            }
            break;
        }

        if buf.len() > 65536 {
            send_response(&mut stream, 413, "text/plain", b"Request too large").await?;
            return Ok(());
        }
    }

    let request = String::from_utf8_lossy(&buf).to_string();

    // Parse the HTTP request line
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        send_response(&mut stream, 400, "text/plain", b"Bad Request").await?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    // Route the request
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            send_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                CHAT_HTML.as_bytes(),
            )
            .await
        }
        ("GET", "/health") | ("GET", "/api/health") => handle_health(&mut stream, &engine).await,
        ("GET", "/api/status") => handle_status(&mut stream, &engine).await,
        ("GET", "/api/quick-actions") => handle_quick_actions(&mut stream, &engine).await,
        ("GET", "/api/agents") => handle_agents_info(&mut stream, &engine).await,
        ("POST", "/api/chat") => {
            let body = extract_body(&request);
            handle_chat(&mut stream, &engine, &body).await
        }
        ("OPTIONS", _) => send_cors_preflight(&mut stream).await,
        _ => {
            send_response(
                &mut stream,
                404,
                "application/json",
                b"{\"error\":\"not found\"}",
            )
            .await
        }
    }
}

/// GET /health, /api/health — Lightweight health check for Docker/load balancers
async fn handle_health(stream: &mut TcpStream, engine: &AgentEngine) -> Result<(), AgentError> {
    let body = serde_json::json!({
        "status": "ok",
        "version": "1.0.0",
        "uptime_secs": engine.uptime_secs(),
        "components": {
            "identity": "ok",
            "ai": engine.ai_status()["provider"],
            "webui": "ok",
            "executor": "ok",
        }
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json).await
}

/// GET /api/status
async fn handle_status(stream: &mut TcpStream, engine: &AgentEngine) -> Result<(), AgentError> {
    let ai = engine.ai_status();
    let sys = engine.get_system_info();
    let caps = engine.get_capabilities();

    let body = serde_json::json!({
        "version": "1.0.0",
        "provider": ai["provider"],
        "ai_available": ai["available"],
        "ai_local": ai["local"],
        "port": engine.config().agent.listen_port,
        "capabilities": caps.len(),
        "cpu_usage": sys.cpu_usage,
        "memory_percent": sys.memory_usage_percent,
        "hostname": sys.hostname,
        "uptime_secs": engine.uptime_secs(),
    });

    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json).await
}

/// GET /api/quick-actions
async fn handle_quick_actions(
    stream: &mut TcpStream,
    engine: &AgentEngine,
) -> Result<(), AgentError> {
    let actions: Vec<QuickAction> = engine.get_quick_actions("owner");
    let json = serde_json::to_vec(&actions).unwrap_or_default();
    send_response(stream, 200, "application/json", &json).await
}

/// GET /api/agents — Multi-agent instance info
async fn handle_agents_info(
    stream: &mut TcpStream,
    engine: &AgentEngine,
) -> Result<(), AgentError> {
    let config = engine.config();
    let max = config.webui.effective_max_agents();
    let mut instances = Vec::new();
    for i in 0..max {
        let port = config.webui.agent_port(i);
        instances.push(serde_json::json!({
            "index": i,
            "port": port,
            "url": format!("http://{}:{}", config.webui.bind, port),
            "peer_id": if i == 0 { "web-client".to_string() } else { format!("web-client-{}", i) },
        }));
    }
    let body = serde_json::json!({
        "license_tier": config.webui.license_tier,
        "max_agents": max,
        "max_agents_for_tier": config.webui.max_agents_for_tier(),
        "work_profile": config.webui.work_profile,
        "base_port": config.webui.port,
        "instances": instances,
        "pricing": {
            "free": { "agents": 1, "price": "$0/mo" },
            "pro": { "agents": 5, "price": "$29/mo" },
            "enterprise": { "agents": 10, "price": "$99/mo" },
        }
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json).await
}

/// POST /api/chat
async fn handle_chat(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
) -> Result<(), AgentError> {
    // Parse request JSON
    #[derive(serde::Deserialize)]
    struct ChatReq {
        message: String,
    }

    let req: ChatReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json).await;
        }
    };

    if req.message.trim().is_empty() {
        let err = serde_json::json!({"error": "empty message"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json).await;
    }

    // Process chat through AI engine AND execute the intent
    match engine.chat_execute("web-client", req.message.trim()).await {
        Ok((ai_resp, exec_result)) => {
            let mut resp = serde_json::to_value(&ai_resp).unwrap_or_default();
            if let Some(exec) = exec_result {
                resp["exec_result"] = serde_json::json!({
                    "success": exec.success,
                    "exit_code": exec.exit_code,
                    "stdout": exec.stdout,
                    "stderr": exec.stderr,
                    "duration_ms": exec.duration_ms,
                    "action": exec.action,
                });
            }
            let json = serde_json::to_vec(&resp).unwrap_or_default();
            send_response(stream, 200, "application/json", &json).await
        }
        Err(e) => {
            let err = serde_json::json!({"error": e.to_string()});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 500, "application/json", &json).await
        }
    }
}

/// Extract the HTTP body from a raw request string
fn extract_body(request: &str) -> String {
    // HTTP body comes after the double CRLF
    if let Some(idx) = request.find("\r\n\r\n") {
        request[idx + 4..].to_string()
    } else if let Some(idx) = request.find("\n\n") {
        request[idx + 2..].to_string()
    } else {
        String::new()
    }
}

/// Parse Content-Length header from raw HTTP request
fn parse_content_length(request: &str) -> usize {
    for line in request.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            if let Some(val) = lower.strip_prefix("content-length:") {
                return val.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Send an HTTP response
async fn send_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), AgentError> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    };

    let header = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: http://127.0.0.1:9444\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Connection: close\r\n\
         \r\n",
        status,
        status_text,
        content_type,
        body.len()
    );

    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;
    stream
        .write_all(body)
        .await
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;

    Ok(())
}

/// Handle CORS preflight OPTIONS request
async fn send_cors_preflight(stream: &mut TcpStream) -> Result<(), AgentError> {
    send_response(stream, 200, "text/plain", b"").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_html_embedded() {
        assert!(!CHAT_HTML.is_empty());
        assert!(CHAT_HTML.contains("EdgeClaw"));
        assert!(CHAT_HTML.contains("/api/chat"));
    }

    #[test]
    fn test_extract_body_crlf() {
        let req = "POST /api/chat HTTP/1.1\r\nHost: localhost\r\n\r\n{\"message\":\"hello\"}";
        assert_eq!(extract_body(req), "{\"message\":\"hello\"}");
    }

    #[test]
    fn test_extract_body_lf() {
        let req = "POST /api/chat HTTP/1.1\nHost: localhost\n\n{\"message\":\"hi\"}";
        assert_eq!(extract_body(req), "{\"message\":\"hi\"}");
    }

    #[test]
    fn test_extract_body_empty() {
        let req = "GET / HTTP/1.1";
        assert_eq!(extract_body(req), "");
    }

    #[test]
    fn test_webui_config() {
        let config = WebUiConfig {
            bind_addr: "127.0.0.1:9444".to_string(),
        };
        assert_eq!(config.bind_addr, "127.0.0.1:9444");
    }

    #[test]
    fn test_parse_content_length() {
        let req = "POST /api/chat HTTP/1.1\r\nContent-Length: 42\r\nHost: localhost\r\n\r\n";
        assert_eq!(parse_content_length(req), 42);

        let req2 = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(parse_content_length(req2), 0);
    }

    #[tokio::test]
    async fn test_webui_server_creation() {
        let engine = Arc::new(AgentEngine::new(crate::config::AgentConfig::default()));
        let config = WebUiConfig {
            bind_addr: "127.0.0.1:0".to_string(),
        };
        let server = WebUiServer::new(config, engine);
        assert!(server.shutdown_tx.is_none());
        assert_eq!(server.rate_limiter.tracked_clients(), 0);
    }
}

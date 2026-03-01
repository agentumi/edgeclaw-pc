//! Web UI HTTP server for the EdgeClaw Agent chat interface.
//!
//! Serves an embedded single-page chat application and exposes JSON API endpoints
//! for chat, quick actions, and status queries. Uses raw tokio TCP — no HTTP framework
//! dependency needed. Includes session-based authentication and rate limiting.

use crate::ai::QuickAction;
use crate::error::AgentError;
use crate::metrics::MetricsRegistry;
use crate::security::{RateLimitConfig, RateLimiter};
use crate::AgentEngine;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};

/// Embedded HTML chat page (compiled into the binary)
const CHAT_HTML: &str = include_str!("../static/chat.html");

/// Embedded HTML dashboard page (compiled into the binary)
const DASHBOARD_HTML: &str = include_str!("../static/dashboard.html");

/// Session token validity duration (1 hour)
const SESSION_TTL: Duration = Duration::from_secs(3600);

/// Web UI server configuration
#[derive(Debug, Clone)]
pub struct WebUiConfig {
    /// Address to bind (e.g. "127.0.0.1:9444")
    pub bind_addr: String,
    /// Authentication password (empty = no auth required)
    pub auth_password: String,
    /// CORS allowed origin (empty = derive from bind_addr)
    pub cors_origin: String,
}

/// Active session entry
struct SessionEntry {
    created_at: Instant,
    peer_ip: String,
}

/// Session manager for web UI authentication
struct SessionManager {
    sessions: Mutex<HashMap<String, SessionEntry>>,
}

impl SessionManager {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new session, returning the token
    async fn create_session(&self, peer_ip: &str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        let mut sessions = self.sessions.lock().await;
        // Cleanup expired sessions
        sessions.retain(|_, entry| entry.created_at.elapsed() < SESSION_TTL);
        sessions.insert(
            token.clone(),
            SessionEntry {
                created_at: Instant::now(),
                peer_ip: peer_ip.to_string(),
            },
        );
        token
    }

    /// Validate a session token
    async fn validate(&self, token: &str, peer_ip: &str) -> bool {
        let sessions = self.sessions.lock().await;
        if let Some(entry) = sessions.get(token) {
            entry.created_at.elapsed() < SESSION_TTL && entry.peer_ip == peer_ip
        } else {
            false
        }
    }

    /// Number of active sessions (for tests)
    #[cfg(test)]
    async fn count(&self) -> usize {
        let sessions = self.sessions.lock().await;
        sessions
            .iter()
            .filter(|(_, e)| e.created_at.elapsed() < SESSION_TTL)
            .count()
    }
}

/// Lightweight HTTP server for the chat web UI
pub struct WebUiServer {
    config: WebUiConfig,
    engine: Arc<AgentEngine>,
    shutdown_tx: Option<broadcast::Sender<()>>,
    rate_limiter: Arc<RateLimiter>,
    sessions: Arc<SessionManager>,
    metrics: Arc<MetricsRegistry>,
}

impl WebUiServer {
    /// Create a new Web UI server
    pub fn new(config: WebUiConfig, engine: Arc<AgentEngine>) -> Self {
        Self {
            config,
            engine,
            shutdown_tx: None,
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
            sessions: Arc::new(SessionManager::new()),
            metrics: Arc::new(MetricsRegistry::with_defaults()),
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

        // Compute effective CORS origin
        let cors_origin = if self.config.cors_origin.is_empty() {
            format!("http://{}", self.config.bind_addr)
        } else {
            self.config.cors_origin.clone()
        };

        let auth_password = self.config.auth_password.clone();
        let auth_required = !auth_password.is_empty();

        info!(
            addr = %self.config.bind_addr,
            auth = auth_required,
            "Web UI server listening"
        );

        loop {
            let mut shutdown_rx = shutdown_tx.subscribe();
            let engine = self.engine.clone();

            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let eng = engine.clone();
                            let limiter = self.rate_limiter.clone();
                            let sessions = self.sessions.clone();
                            let cors = cors_origin.clone();
                            let password = auth_password.clone();
                            let need_auth = auth_required;
                            let metrics = self.metrics.clone();
                            let mut shutdown = shutdown_tx.subscribe();
                            tokio::spawn(async move {
                                if let Err(e) = handle_http(
                                    stream, eng, &limiter, &sessions,
                                    &cors, &password, need_auth,
                                    &metrics,
                                    &mut shutdown
                                ).await {
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
#[allow(clippy::too_many_arguments)]
async fn handle_http(
    mut stream: TcpStream,
    engine: Arc<AgentEngine>,
    rate_limiter: &RateLimiter,
    sessions: &SessionManager,
    cors_origin: &str,
    auth_password: &str,
    auth_required: bool,
    metrics: &MetricsRegistry,
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
            cors_origin,
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
            send_response(
                &mut stream,
                413,
                "text/plain",
                b"Request too large",
                cors_origin,
            )
            .await?;
            return Ok(());
        }
    }

    let request = String::from_utf8_lossy(&buf).to_string();

    // Parse the HTTP request line
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        send_response(&mut stream, 400, "text/plain", b"Bad Request", cors_origin).await?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    // Public endpoints (no auth needed)
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            return send_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                CHAT_HTML.as_bytes(),
                cors_origin,
            )
            .await;
        }
        ("GET", "/dashboard") | ("GET", "/dashboard.html") => {
            return send_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                DASHBOARD_HTML.as_bytes(),
                cors_origin,
            )
            .await;
        }
        ("GET", "/metrics") => {
            return handle_metrics_prometheus(&mut stream, metrics, &engine, cors_origin).await;
        }
        ("GET", "/health") | ("GET", "/api/health") => {
            return handle_health(&mut stream, &engine, cors_origin).await;
        }
        ("POST", "/api/login") => {
            let body = extract_body(&request);
            return handle_login(
                &mut stream,
                sessions,
                &peer_ip,
                auth_password,
                auth_required,
                &body,
                cors_origin,
            )
            .await;
        }
        ("OPTIONS", _) => {
            return send_cors_preflight(&mut stream, cors_origin).await;
        }
        _ => {}
    }

    // Protected endpoints — require auth if configured
    if auth_required {
        let token = extract_bearer_token(&request);
        match token {
            Some(t) if sessions.validate(t, &peer_ip).await => {}
            _ => {
                let err = serde_json::json!({"error": "unauthorized", "login_required": true});
                let json = serde_json::to_vec(&err).unwrap_or_default();
                return send_response(&mut stream, 401, "application/json", &json, cors_origin)
                    .await;
            }
        }
    }

    // Route protected endpoints
    match (method, path) {
        ("GET", "/api/status") => handle_status(&mut stream, &engine, cors_origin).await,
        ("GET", "/api/quick-actions") => {
            handle_quick_actions(&mut stream, &engine, cors_origin).await
        }
        ("GET", "/api/agents") => handle_agents_info(&mut stream, &engine, cors_origin).await,
        ("GET", "/api/metrics/history") => {
            handle_metrics_history(&mut stream, metrics, &engine, cors_origin).await
        }
        ("GET", "/api/audit/entries") => {
            handle_audit_entries(&mut stream, &engine, &request, cors_origin).await
        }
        ("GET", "/api/audit/verify") => {
            handle_audit_verify(&mut stream, &engine, cors_origin).await
        }
        ("PUT", "/api/config") => {
            let body = extract_body(&request);
            handle_config_update(&mut stream, &engine, &body, cors_origin).await
        }
        ("POST", "/api/chat") => {
            let body = extract_body(&request);
            handle_chat(&mut stream, &engine, &body, cors_origin).await
        }
        _ if method == "POST" && path.starts_with("/api/agents/") && path.ends_with("/execute") => {
            let agent_id = path
                .strip_prefix("/api/agents/")
                .and_then(|s| s.strip_suffix("/execute"))
                .unwrap_or("");
            let body = extract_body(&request);
            handle_agent_execute(&mut stream, agent_id, &body, cors_origin).await
        }
        _ if method == "DELETE" && path.starts_with("/api/agents/") => {
            let agent_id = path.strip_prefix("/api/agents/").unwrap_or("");
            handle_agent_delete(&mut stream, agent_id, cors_origin).await
        }
        _ => {
            send_response(
                &mut stream,
                404,
                "application/json",
                b"{\"error\":\"not found\"}",
                cors_origin,
            )
            .await
        }
    }
}

/// POST /api/login — Authenticate and get session token
async fn handle_login(
    stream: &mut TcpStream,
    sessions: &SessionManager,
    peer_ip: &str,
    auth_password: &str,
    auth_required: bool,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    // If no auth required, always succeed
    if !auth_required {
        let token = sessions.create_session(peer_ip).await;
        let resp = serde_json::json!({
            "token": token,
            "expires_in": SESSION_TTL.as_secs(),
            "auth_required": false,
        });
        let json = serde_json::to_vec(&resp).unwrap_or_default();
        return send_response(stream, 200, "application/json", &json, cors_origin).await;
    }

    #[derive(serde::Deserialize)]
    struct LoginReq {
        password: String,
    }

    let req: LoginReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    if req.password == auth_password {
        let token = sessions.create_session(peer_ip).await;
        info!(peer = %peer_ip, "WebUI login successful");
        let resp = serde_json::json!({
            "token": token,
            "expires_in": SESSION_TTL.as_secs(),
        });
        let json = serde_json::to_vec(&resp).unwrap_or_default();
        send_response(stream, 200, "application/json", &json, cors_origin).await
    } else {
        warn!(peer = %peer_ip, "WebUI login failed — bad password");
        let err = serde_json::json!({"error": "invalid password"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        send_response(stream, 401, "application/json", &json, cors_origin).await
    }
}

/// GET /health, /api/health — Lightweight health check for Docker/load balancers
async fn handle_health(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
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
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/status
async fn handle_status(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
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
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/quick-actions
async fn handle_quick_actions(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let actions: Vec<QuickAction> = engine.get_quick_actions("owner");
    let json = serde_json::to_vec(&actions).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/agents — Multi-agent instance info + remote agent registry
async fn handle_agents_info(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
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

    // Include agents from the registry
    let registry = crate::registry::AgentRegistry::new();
    let registered: Vec<serde_json::Value> = registry
        .list_all()
        .iter()
        .map(|a| {
            serde_json::json!({
                "id": a.id,
                "name": a.name,
                "profile": a.profile,
                "address": a.address,
                "port": a.port,
                "status": a.status.to_string(),
                "version": a.version,
                "capabilities": a.capabilities,
            })
        })
        .collect();

    let body = serde_json::json!({
        "license_tier": config.webui.license_tier,
        "max_agents": max,
        "max_agents_for_tier": config.webui.max_agents_for_tier(),
        "work_profile": config.webui.work_profile,
        "base_port": config.webui.port,
        "instances": instances,
        "registered_agents": registered,
        "registered_count": registered.len(),
        "pricing": {
            "free": { "agents": 1, "price": "$0/mo" },
            "pro": { "agents": 5, "price": "$29/mo" },
            "enterprise": { "agents": 10, "price": "$99/mo" },
        }
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// POST /api/agents/{id}/execute — Forward command to a remote agent (stub)
async fn handle_agent_execute(
    stream: &mut TcpStream,
    agent_id: &str,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let registry = crate::registry::AgentRegistry::new();
    let agent = registry.get(agent_id);

    match agent {
        Some(a) => {
            let resp = serde_json::json!({
                "agent_id": a.id,
                "agent_name": a.name,
                "status": "queued",
                "message": format!("command forwarded to {} ({}:{})", a.name, a.address, a.port),
                "body": body,
            });
            let json = serde_json::to_vec(&resp).unwrap_or_default();
            send_response(stream, 202, "application/json", &json, cors_origin).await
        }
        None => {
            let err = serde_json::json!({"error": format!("agent '{}' not found", agent_id)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 404, "application/json", &json, cors_origin).await
        }
    }
}

/// DELETE /api/agents/{id} — Remove agent from registry
async fn handle_agent_delete(
    stream: &mut TcpStream,
    agent_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let registry = crate::registry::AgentRegistry::new();
    if registry.remove(agent_id) {
        let _ = registry.save();
        let resp = serde_json::json!({"removed": agent_id});
        let json = serde_json::to_vec(&resp).unwrap_or_default();
        send_response(stream, 200, "application/json", &json, cors_origin).await
    } else {
        let err = serde_json::json!({"error": format!("agent '{}' not found", agent_id)});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        send_response(stream, 404, "application/json", &json, cors_origin).await
    }
}

/// POST /api/chat
async fn handle_chat(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
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
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    if req.message.trim().is_empty() {
        let err = serde_json::json!({"error": "empty message"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
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
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        Err(e) => {
            let err = serde_json::json!({"error": e.to_string()});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 500, "application/json", &json, cors_origin).await
        }
    }
}

/// GET /metrics — Prometheus text exposition format.
/// Updates system gauges from AgentEngine before rendering.
async fn handle_metrics_prometheus(
    stream: &mut TcpStream,
    metrics: &MetricsRegistry,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    // Refresh system gauges
    let sys = engine.get_system_info();
    metrics.set_gauge("edgeclaw_cpu_usage_percent", sys.cpu_usage as f64);
    metrics.set_gauge(
        "edgeclaw_memory_usage_bytes",
        (sys.used_memory_mb * 1024 * 1024) as f64,
    );
    metrics.set_gauge("edgeclaw_active_peers", engine.connected_count() as f64);

    let text = metrics.render_prometheus();
    send_response(
        stream,
        200,
        "text/plain; version=0.0.4; charset=utf-8",
        text.as_bytes(),
        cors_origin,
    )
    .await
}

/// GET /api/metrics/history — Recent 1h snapshot of key metrics.
async fn handle_metrics_history(
    stream: &mut TcpStream,
    metrics: &MetricsRegistry,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let sys = engine.get_system_info();
    metrics.set_gauge("edgeclaw_cpu_usage_percent", sys.cpu_usage as f64);
    metrics.set_gauge(
        "edgeclaw_memory_usage_bytes",
        (sys.used_memory_mb * 1024 * 1024) as f64,
    );

    let body = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "uptime_secs": engine.uptime_secs(),
        "cpu_usage_percent": sys.cpu_usage,
        "memory_usage_percent": sys.memory_usage_percent,
        "memory_usage_bytes": sys.used_memory_mb * 1024 * 1024,
        "total_memory_mb": sys.total_memory_mb,
        "active_peers": engine.connected_count(),
        "commands_total": metrics.get("edgeclaw_commands_total")
            .map(|v| match v { crate::metrics::MetricValue::Counter(c) => c, _ => 0.0 })
            .unwrap_or(0.0),
        "messages_total": metrics.get("edgeclaw_messages_total")
            .map(|v| match v { crate::metrics::MetricValue::Counter(c) => c, _ => 0.0 })
            .unwrap_or(0.0),
        "errors_total": metrics.get("edgeclaw_errors_total")
            .map(|v| match v { crate::metrics::MetricValue::Counter(c) => c, _ => 0.0 })
            .unwrap_or(0.0),
        "audit_entry_count": engine.audit_count(),
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/audit/entries — Paginated audit log entries.
/// Query params: ?limit=N (default 50, max 500)
async fn handle_audit_entries(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    raw_request: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    // Parse query parameters from request path
    let limit = parse_query_param(raw_request, "limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(500);

    let entries = engine.get_audit_log(limit);
    let body = serde_json::json!({
        "count": entries.len(),
        "total": engine.audit_count(),
        "entries": entries,
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/audit/verify — Verify hash-chain integrity of audit log.
async fn handle_audit_verify(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let (valid, detail) = match engine.verify_audit_chain() {
        Ok(true) => (true, "Hash chain is intact".to_string()),
        Ok(false) => (false, "Verification returned false".to_string()),
        Err(e) => (false, e),
    };
    let body = serde_json::json!({
        "valid": valid,
        "detail": detail,
        "entry_count": engine.audit_count(),
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// PUT /api/config — Update agent config (TOML body).
async fn handle_config_update(
    stream: &mut TcpStream,
    _engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    // Validate TOML syntax
    match toml::from_str::<crate::config::AgentConfig>(body) {
        Ok(new_config) => {
            let config_path = crate::config::AgentConfig::default_path();
            match new_config.save(&config_path) {
                Ok(()) => {
                    let resp = serde_json::json!({
                        "status": "saved",
                        "path": config_path.to_string_lossy(),
                        "message": "Config saved. Restart agent to apply changes."
                    });
                    let json = serde_json::to_vec(&resp).unwrap_or_default();
                    send_response(stream, 200, "application/json", &json, cors_origin).await
                }
                Err(e) => {
                    let err = serde_json::json!({"error": format!("save failed: {}", e)});
                    let json = serde_json::to_vec(&err).unwrap_or_default();
                    send_response(stream, 500, "application/json", &json, cors_origin).await
                }
            }
        }
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid TOML: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 400, "application/json", &json, cors_origin).await
        }
    }
}

/// Parse a query parameter from the raw HTTP request path.
fn parse_query_param<'a>(request: &'a str, key: &str) -> Option<&'a str> {
    let first_line = request.lines().next()?;
    let path = first_line.split_whitespace().nth(1)?;
    let query = path.split('?').nth(1)?;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
            if k == key {
                return Some(v);
            }
        }
    }
    None
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

/// Extract Bearer token from Authorization header
fn extract_bearer_token(request: &str) -> Option<&str> {
    for line in request.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("authorization: bearer ") {
            // Return the token part from the ORIGINAL line (preserving case)
            return Some(line["authorization: bearer ".len()..].trim());
        }
    }
    None
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

/// Send an HTTP response with dynamic CORS origin
async fn send_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    cors_origin: &str,
) -> Result<(), AgentError> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
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
         Access-Control-Allow-Origin: {}\r\n\
         Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
         Connection: close\r\n\
         \r\n",
        status,
        status_text,
        content_type,
        body.len(),
        cors_origin
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
async fn send_cors_preflight(stream: &mut TcpStream, cors_origin: &str) -> Result<(), AgentError> {
    send_response(stream, 200, "text/plain", b"", cors_origin).await
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
            auth_password: String::new(),
            cors_origin: String::new(),
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

    #[test]
    fn test_extract_bearer_token() {
        let req = "GET /api/status HTTP/1.1\r\nAuthorization: Bearer abc-123-def\r\nHost: localhost\r\n\r\n";
        assert_eq!(extract_bearer_token(req), Some("abc-123-def"));

        let req2 = "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(extract_bearer_token(req2), None);
    }

    #[tokio::test]
    async fn test_session_manager_create_and_validate() {
        let mgr = SessionManager::new();
        let token = mgr.create_session("127.0.0.1").await;
        assert!(!token.is_empty());
        assert!(mgr.validate(&token, "127.0.0.1").await);
        assert!(!mgr.validate(&token, "192.168.1.1").await); // wrong IP
        assert!(!mgr.validate("bad-token", "127.0.0.1").await);
        assert_eq!(mgr.count().await, 1);
    }

    #[tokio::test]
    async fn test_webui_server_creation() {
        let engine = Arc::new(AgentEngine::new(crate::config::AgentConfig::default()));
        let config = WebUiConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            auth_password: String::new(),
            cors_origin: String::new(),
        };
        let server = WebUiServer::new(config, engine);
        assert!(server.shutdown_tx.is_none());
        assert_eq!(server.rate_limiter.tracked_clients(), 0);
    }

    #[test]
    fn test_dashboard_html_embedded() {
        assert!(!DASHBOARD_HTML.is_empty());
        assert!(DASHBOARD_HTML.contains("EdgeClaw"));
        assert!(DASHBOARD_HTML.contains("Dashboard"));
    }

    #[test]
    fn test_parse_query_param() {
        let req =
            "GET /api/audit/entries?limit=20&filter=admin HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(parse_query_param(req, "limit"), Some("20"));
        assert_eq!(parse_query_param(req, "filter"), Some("admin"));
        assert_eq!(parse_query_param(req, "page"), None);
    }

    #[test]
    fn test_parse_query_param_no_query() {
        let req = "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(parse_query_param(req, "limit"), None);
    }

    #[test]
    fn test_metrics_registry_with_defaults() {
        let reg = MetricsRegistry::with_defaults();
        assert!(reg.get("edgeclaw_active_peers").is_some());
        assert!(reg.get("edgeclaw_commands_total").is_some());
        let text = reg.render_prometheus();
        assert!(text.contains("edgeclaw_cpu_usage_percent"));
    }

    // ── New coverage tests ─────────────────────────────────

    #[tokio::test]
    async fn test_session_manager_multiple_sessions() {
        let mgr = SessionManager::new();
        let tok1 = mgr.create_session("10.0.0.1").await;
        let tok2 = mgr.create_session("10.0.0.2").await;
        let tok3 = mgr.create_session("10.0.0.3").await;
        assert_ne!(tok1, tok2);
        assert_ne!(tok2, tok3);
        assert!(mgr.validate(&tok1, "10.0.0.1").await);
        assert!(mgr.validate(&tok2, "10.0.0.2").await);
        assert!(mgr.validate(&tok3, "10.0.0.3").await);
        // Cross-IP should fail
        assert!(!mgr.validate(&tok1, "10.0.0.2").await);
        assert_eq!(mgr.count().await, 3);
    }

    // Helper: start a WebUI server on port 0, return the bound address
    async fn start_test_server(
        auth_password: &str,
    ) -> (String, Arc<AgentEngine>, broadcast::Sender<()>) {
        let engine = Arc::new(AgentEngine::new(crate::config::AgentConfig::default()));
        let config = WebUiConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            auth_password: auth_password.to_string(),
            cors_origin: String::new(),
        };
        let mut server = WebUiServer::new(config, engine.clone());

        // Bind manually to get the port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let rate_limiter = server.rate_limiter.clone();
        let sessions = server.sessions.clone();
        let metrics = server.metrics.clone();
        let (shutdown_tx, _) = broadcast::channel::<()>(1);
        server.shutdown_tx = Some(shutdown_tx.clone());

        let password = auth_password.to_string();
        let auth_required = !password.is_empty();
        let cors_origin = format!("http://{}", addr);
        let eng = engine.clone();

        tokio::spawn(async move {
            loop {
                let mut shutdown_rx = shutdown_tx.subscribe();
                let eng = eng.clone();
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let eng = eng.clone();
                                let limiter = rate_limiter.clone();
                                let sessions = sessions.clone();
                                let cors = cors_origin.clone();
                                let password = password.clone();
                                let metrics = metrics.clone();
                                let mut shutdown = shutdown_tx.subscribe();
                                tokio::spawn(async move {
                                    let _ = handle_http(
                                        stream, eng, &limiter, &sessions,
                                        &cors, &password, auth_required,
                                        &metrics, &mut shutdown,
                                    ).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                    _ = shutdown_rx.recv() => break,
                }
            }
        });

        // Return the shutdown sender from the server
        let tx = server.shutdown_tx.take().unwrap();
        (addr, engine, tx)
    }

    // Helper: raw HTTP request and read response
    async fn http_request(addr: &str, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        // Read response
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        loop {
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
                Ok(Err(_)) => break,
                Err(_) => break, // timeout
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    #[tokio::test]
    async fn test_webui_serve_index_html() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("EdgeClaw"));
    }

    #[tokio::test]
    async fn test_webui_serve_dashboard() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /dashboard HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("Dashboard"));
    }

    #[tokio::test]
    async fn test_webui_health_endpoint() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"status\":\"ok\""));
    }

    #[tokio::test]
    async fn test_webui_options_cors() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "OPTIONS /api/chat HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("Access-Control-Allow-Methods"));
    }

    #[tokio::test]
    async fn test_webui_login_no_auth() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let body = r#"{"password":""}"#;
        let req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"token\""));
    }

    #[tokio::test]
    async fn test_webui_login_bad_password() {
        let (addr, _engine, _tx) = start_test_server("secret123").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let body = r#"{"password":"wrong"}"#;
        let req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 401"));
        assert!(resp.contains("invalid password"));
    }

    #[tokio::test]
    async fn test_webui_login_good_password() {
        let (addr, _engine, _tx) = start_test_server("secret123").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let body = r#"{"password":"secret123"}"#;
        let req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"token\""));
    }

    #[tokio::test]
    async fn test_webui_not_found() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /api/nonexistent HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 404"));
        assert!(resp.contains("not found"));
    }

    #[tokio::test]
    async fn test_webui_status_no_auth() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"version\""));
    }

    #[tokio::test]
    async fn test_webui_protected_no_token() {
        let (addr, _engine, _tx) = start_test_server("secret").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 401"));
        assert!(resp.contains("unauthorized"));
    }

    #[tokio::test]
    async fn test_webui_metrics_endpoint() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("edgeclaw_"));
    }

    #[tokio::test]
    async fn test_webui_quick_actions() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /api/quick-actions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn test_webui_agents_info() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /api/agents HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"max_agents\""));
    }

    #[tokio::test]
    async fn test_webui_audit_entries() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /api/audit/entries HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"count\""));
    }

    #[tokio::test]
    async fn test_webui_audit_verify() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /api/audit/verify HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"valid\""));
    }

    #[tokio::test]
    async fn test_webui_metrics_history() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /api/metrics/history HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"uptime_secs\""));
    }

    #[tokio::test]
    async fn test_webui_chat_empty_message() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let body = r#"{"message":""}"#;
        let req = format!(
            "POST /api/chat HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 400"));
        assert!(resp.contains("empty message"));
    }

    #[tokio::test]
    async fn test_webui_chat_invalid_json() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let body = "not json at all";
        let req = format!(
            "POST /api/chat HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 400"));
        assert!(resp.contains("invalid JSON"));
    }

    #[tokio::test]
    async fn test_webui_delete_nonexistent_agent() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "DELETE /api/agents/nonexistent HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 404"));
    }

    #[tokio::test]
    async fn test_webui_execute_nonexistent_agent() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let body = r#"{"command":"test"}"#;
        let req = format!(
            "POST /api/agents/fake/execute HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 404"));
    }

    #[tokio::test]
    async fn test_webui_config_update_invalid_toml() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let body = "this is not valid toml {{{";
        let req = format!(
            "PUT /api/config HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 400"));
        assert!(resp.contains("invalid TOML"));
    }
}

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

/// Embedded HTML activity feed page (compiled into the binary)
const ACTIVITY_FEED_HTML: &str = include_str!("../static/activity_feed.html");

/// Embedded HTML sessions list page (compiled into the binary)
const SESSIONS_HTML: &str = include_str!("../static/sessions.html");

/// Embedded HTML session detail page (compiled into the binary)
const SESSION_DETAIL_HTML: &str = include_str!("../static/session_detail.html");

/// Embedded HTML search page (compiled into the binary)
const SEARCH_HTML: &str = include_str!("../static/search.html");

/// Embedded HTML statistics page (compiled into the binary)
const STATS_HTML: &str = include_str!("../static/stats.html");

/// Embedded HTML team network map page (compiled into the binary)
const TEAM_MAP_HTML: &str = include_str!("../static/team_map.html");

/// Pretty HTML for rate limiting
const TOO_MANY_REQUESTS_HTML: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Slow Down — EdgeClaw</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background: #050508; color: #f8fafc; height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .card { background: #12121a; border: 1px solid #2a2a3a; padding: 40px; border-radius: 16px; text-align: center; max-width: 400px; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }
        h1 { color: #6366f1; margin: 0 0 16px; font-size: 24px; }
        p { color: #94a3b8; line-height: 1.6; margin-bottom: 24px; }
        .btn { background: #6366f1; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; text-decoration: none; font-weight: 600; transition: 0.3s; }
        .btn:hover { background: #818cf8; transform: translateY(-2px); }
        .icon { font-size: 48px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">⌛</div>
        <h1>Too Many Requests</h1>
        <p>Whoa there! You're refreshing a bit too fast. Please take a second to breathe while we cool down the engines.</p>
        <a href="javascript:location.reload()" class="btn">Try Again</a>
    </div>
    <script>setTimeout(() => location.reload(), 5000);</script>
</body>
</html>
"#;

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
            break;
        }
        if buf.len() > 65536 {
            break;
        }
    }

    let request_header = String::from_utf8_lossy(&buf).to_string();
    let is_api =
        request_header.contains("/api/") || request_header.contains("Accept: application/json");

    // Rate-limit by peer IP (exempt localhost)
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let is_localhost = peer_ip == "127.0.0.1" || peer_ip == "::1";

    if !is_localhost {
        let rate_result = rate_limiter.check(&peer_ip);
        if !rate_result.is_allowed() {
            if is_api {
                send_response(
                    &mut stream,
                    429,
                    "application/json",
                    b"{\"error\":\"too many requests\"}",
                    cors_origin,
                )
                .await?;
            } else {
                send_response(
                    &mut stream,
                    429,
                    "text/html; charset=utf-8",
                    TOO_MANY_REQUESTS_HTML.as_bytes(),
                    cors_origin,
                )
                .await?;
            }
            return Ok(());
        }
    }

    // Now finish reading the body if necessary
    let s = String::from_utf8_lossy(&buf);
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

    let request = String::from_utf8_lossy(&buf).to_string();

    // Parse the HTTP request line
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        send_response(&mut stream, 400, "text/plain", b"Bad Request", cors_origin).await?;
        return Ok(());
    }

    let method = parts[0];
    let full_uri = parts[1];
    let path = full_uri.split('?').next().unwrap_or(full_uri);

    // Public endpoints (no auth needed)
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            return send_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                DASHBOARD_HTML.as_bytes(),
                cors_origin,
            )
            .await;
        }
        ("GET", "/chat") | ("GET", "/chat.html") => {
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
        ("GET", "/activity") => {
            return send_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                ACTIVITY_FEED_HTML.as_bytes(),
                cors_origin,
            )
            .await;
        }
        ("GET", "/sessions") => {
            return send_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                SESSIONS_HTML.as_bytes(),
                cors_origin,
            )
            .await;
        }
        _ if method == "GET" && path.starts_with("/session/") => {
            return send_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                SESSION_DETAIL_HTML.as_bytes(),
                cors_origin,
            )
            .await;
        }
        ("GET", "/search") => {
            return send_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                SEARCH_HTML.as_bytes(),
                cors_origin,
            )
            .await;
        }
        ("GET", "/stats") => {
            return send_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                STATS_HTML.as_bytes(),
                cors_origin,
            )
            .await;
        }
        ("GET", "/team") => {
            return send_response(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                TEAM_MAP_HTML.as_bytes(),
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
        ("POST", "/api/agent/mode") => {
            let body = extract_body(&request);
            handle_agent_mode(&mut stream, &engine, &body, cors_origin).await
        }
        ("GET", "/api/memory") => handle_memory_info(&mut stream, &engine, cors_origin).await,
        // ─── Task Board API ──────────────────────────────
        ("GET", "/api/tasks") => {
            handle_tasks_list(&mut stream, &engine, &request, cors_origin).await
        }
        ("POST", "/api/tasks") => {
            let body = extract_body(&request);
            handle_task_create(&mut stream, &engine, &body, cors_origin).await
        }
        _ if method == "POST" && path.starts_with("/api/tasks/") && path.ends_with("/move") => {
            let task_id = path
                .strip_prefix("/api/tasks/")
                .and_then(|s| s.strip_suffix("/move"))
                .unwrap_or("");
            let body = extract_body(&request);
            handle_task_move(&mut stream, &engine, task_id, &body, cors_origin).await
        }
        _ if method == "POST" && path.starts_with("/api/tasks/") && path.ends_with("/assign") => {
            let task_id = path
                .strip_prefix("/api/tasks/")
                .and_then(|s| s.strip_suffix("/assign"))
                .unwrap_or("");
            let body = extract_body(&request);
            handle_task_assign(&mut stream, &engine, task_id, &body, cors_origin).await
        }
        _ if method == "POST" && path.starts_with("/api/agents/") && path.ends_with("/execute") => {
            let agent_id = path
                .strip_prefix("/api/agents/")
                .and_then(|s| s.strip_suffix("/execute"))
                .unwrap_or("");
            let body = extract_body(&request);
            handle_agent_execute(&mut stream, &engine, agent_id, &body, cors_origin).await
        }
        ("POST", "/api/agents") => {
            let body = extract_body(&request);
            handle_agent_register(&mut stream, &engine, &body, cors_origin).await
        }
        ("POST", "/api/agents/discover") => {
            handle_agents_discover(&mut stream, &engine, cors_origin).await
        }
        _ if method == "DELETE" && path.starts_with("/api/agents/") => {
            let agent_id = path.strip_prefix("/api/agents/").unwrap_or("");
            handle_agent_delete(&mut stream, &engine, agent_id, cors_origin).await
        }
        _ if method == "GET" && path.starts_with("/api/agents/") => {
            let agent_id = path.strip_prefix("/api/agents/").unwrap_or("");
            handle_agent_profile(&mut stream, &engine, agent_id, cors_origin).await
        }
        // ─── V4.0 Activity REST API ──────────────────────
        ("GET", "/api/activities") => {
            handle_activities_list(&mut stream, &engine, &request, cors_origin).await
        }
        ("POST", "/api/activities/search") => {
            let body = extract_body(&request);
            handle_activities_search(&mut stream, &engine, &body, cors_origin).await
        }
        ("GET", "/api/activities/stats") => {
            handle_activities_stats(&mut stream, &engine, cors_origin).await
        }
        _ if method == "GET" && path.starts_with("/api/activities/") => {
            let entry_id = path.strip_prefix("/api/activities/").unwrap_or("");
            handle_activity_detail(&mut stream, &engine, entry_id, cors_origin).await
        }
        ("GET", "/api/sessions") => {
            handle_sessions_list(&mut stream, &engine, &request, cors_origin).await
        }
        _ if method == "GET"
            && path.starts_with("/api/sessions/")
            && path.ends_with("/timeline") =>
        {
            let session_id = path
                .strip_prefix("/api/sessions/")
                .and_then(|s| s.strip_suffix("/timeline"))
                .unwrap_or("");
            handle_session_timeline(&mut stream, &engine, session_id, cors_origin).await
        }
        _ if method == "GET"
            && path.starts_with("/api/sessions/")
            && path.ends_with("/context") =>
        {
            let session_id = path
                .strip_prefix("/api/sessions/")
                .and_then(|s| s.strip_suffix("/context"))
                .unwrap_or("");
            handle_session_context(&mut stream, &engine, session_id, cors_origin).await
        }
        _ if method == "GET" && path.starts_with("/api/sessions/") => {
            let session_id = path.strip_prefix("/api/sessions/").unwrap_or("");
            handle_session_detail(&mut stream, &engine, session_id, cors_origin).await
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

fn parse_local_agent_index(agent_id: &str, max_agents: u16) -> Option<u16> {
    let idx = if agent_id == "local" || agent_id == "web-client" {
        Some(0)
    } else if let Some(rest) = agent_id.strip_prefix("local-") {
        rest.parse::<u16>().ok()
    } else if let Some(rest) = agent_id.strip_prefix("web-client-") {
        rest.parse::<u16>().ok()
    } else {
        None
    }?;

    if idx < max_agents {
        Some(idx)
    } else {
        None
    }
}

fn local_agent_peer_id(index: u16) -> String {
    if index == 0 {
        "web-client".to_string()
    } else {
        format!("web-client-{}", index)
    }
}

fn local_agent_id(index: u16) -> String {
    if index == 0 {
        "local".to_string()
    } else {
        format!("local-{}", index)
    }
}

fn local_agent_name(base_name: &str, index: u16) -> String {
    if index == 0 {
        base_name.to_string()
    } else {
        format!("{}-{}", base_name, index + 1)
    }
}

/// GET /api/agents — Multi-agent instance info + remote agent registry
async fn handle_agents_info(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let config = engine.config();
    let max = config.webui.effective_max_agents();
    let online_agents = engine.agent_registry().count_online();
    let mut instances = Vec::new();
    let mut local_agents = Vec::new();
    for i in 0..max {
        let port = config.webui.agent_port(i);
        let id = local_agent_id(i);
        let peer_id = local_agent_peer_id(i);
        let name = local_agent_name(&config.agent.device_name, i);

        instances.push(serde_json::json!({
            "index": i,
            "port": port,
            "url": format!("http://{}:{}", config.webui.bind, port),
            "peer_id": peer_id,
        }));

        local_agents.push(serde_json::json!({
            "id": id,
            "name": name,
            "profile": config.webui.work_profile,
            "address": config.webui.bind,
            "port": port,
            "status": "online",
            "source": "local",
            "capabilities": engine.get_capabilities(),
            "peer_id": peer_id,
            "instance_index": i,
        }));
    }

    // Include remote agents from the persistent registry
    let registered: Vec<serde_json::Value> = engine
        .agent_registry()
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
                "source": "remote",
            })
        })
        .collect();

    let mut all_agents = local_agents.clone();
    all_agents.extend(registered.clone());
    let registered_count = registered.len();

    let body = serde_json::json!({
        "license_tier": config.webui.license_tier,
        "max_agents": max,
        "max_agents_for_tier": config.webui.max_agents_for_tier(),
        "work_profile": config.webui.work_profile,
        "base_port": config.webui.port,
        "instances": instances,
        "local_agents": local_agents,
        "local_count": max,
        "registered_agents": registered,
        "registered_count": registered_count,
        "online_registered_count": online_agents,
        "agents": all_agents,
        "active_agents_total": max as usize + online_agents,
        "pricing": {
            "free": { "agents": 1, "price": "$0/mo" },
            "pro": { "agents": 5, "price": "$29/mo" },
            "enterprise": { "agents": 10, "price": "$99/mo" },
        }
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// POST /api/agents/{id}/execute — Execute command on local agent or forward to remote agent.
async fn handle_agent_execute(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    agent_id: &str,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    if let Some(index) =
        parse_local_agent_index(agent_id, engine.config().webui.effective_max_agents())
    {
        #[derive(serde::Deserialize)]
        struct ExecuteReq {
            command: String,
            #[serde(default)]
            args: Vec<String>,
            action: Option<String>,
            timeout_secs: Option<u64>,
        }

        let req: ExecuteReq = match serde_json::from_str(body) {
            Ok(r) => r,
            Err(e) => {
                let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
                let json = serde_json::to_vec(&err).unwrap_or_default();
                return send_response(stream, 400, "application/json", &json, cors_origin).await;
            }
        };

        if req.command.trim().is_empty() {
            let err = serde_json::json!({"error": "command is required"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }

        let peer_id = local_agent_peer_id(index);
        let agent_name = local_agent_name(&engine.config().agent.device_name, index);
        let _ = engine.add_peer(&peer_id, &agent_name, "local-worker", "127.0.0.1", "owner");

        let timeout = req
            .timeout_secs
            .unwrap_or(30)
            .clamp(1, engine.config().execution.max_timeout_secs);
        let action = req.action.unwrap_or_else(|| "shell_exec".to_string());
        let exec_req = crate::executor::ExecRequest {
            execution_id: uuid::Uuid::new_v4().to_string(),
            action,
            command: req.command,
            args: req.args,
            timeout_secs: timeout,
            working_dir: None,
        };

        return match engine.execute_command(&peer_id, exec_req).await {
            Ok(exec_result) => {
                let status = if exec_result.success {
                    "completed"
                } else {
                    "failed"
                };
                let resp = serde_json::json!({
                    "agent_id": local_agent_id(index),
                    "agent_name": agent_name,
                    "status": status,
                    "exec_result": exec_result,
                });
                let json = serde_json::to_vec(&resp).unwrap_or_default();
                send_response(stream, 200, "application/json", &json, cors_origin).await
            }
            Err(e) => {
                let err = serde_json::json!({"error": e.to_string()});
                let json = serde_json::to_vec(&err).unwrap_or_default();
                send_response(stream, 500, "application/json", &json, cors_origin).await
            }
        };
    }

    let agent = engine.agent_registry().get(agent_id);

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
    engine: &AgentEngine,
    agent_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    if parse_local_agent_index(agent_id, engine.config().webui.effective_max_agents()).is_some() {
        let err = serde_json::json!({"error": "local agents cannot be deleted"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
    }

    if engine.agent_registry().remove(agent_id) {
        let _ = engine.agent_registry().save();
        let resp = serde_json::json!({"removed": agent_id});
        let json = serde_json::to_vec(&resp).unwrap_or_default();
        send_response(stream, 200, "application/json", &json, cors_origin).await
    } else {
        let err = serde_json::json!({"error": format!("agent '{}' not found", agent_id)});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        send_response(stream, 404, "application/json", &json, cors_origin).await
    }
}

/// GET /api/memory — Full memory state (Core + Tiers + Lessons)
async fn handle_memory_info(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let json = {
        let memory = engine
            .memory_engine()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        serde_json::to_vec(&*memory).unwrap_or_default()
    };
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/agents/{id} — Detailed agent profile including reputation
async fn handle_agent_profile(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    agent_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    // If it's a local agent instance, return rich info
    if let Some(index) =
        parse_local_agent_index(agent_id, engine.config().webui.effective_max_agents())
    {
        let ai = engine.ai_status();
        let sys = engine.get_system_info();
        let score = engine.reputation_score();
        let name = local_agent_name(&engine.config().agent.device_name, index);
        let id = local_agent_id(index);
        let port = engine.config().webui.agent_port(index);
        let peer_id = local_agent_peer_id(index);
        let tasks = engine.list_tasks_filtered(None, Some(&id));

        let body = serde_json::json!({
            "id": id,
            "name": name,
            "profile": engine.config().webui.work_profile,
            "status": "online",
            "reputation_score": score,
            "capabilities": engine.get_capabilities(),
            "uptime_secs": engine.uptime_secs(),
            "address": engine.config().webui.bind,
            "port": port,
            "peer_id": peer_id,
            "system": {
                "cpu": sys.cpu_usage,
                "memory": sys.memory_usage_percent,
                "platform": sys.hostname,
            },
            "recent_tasks": tasks.iter().take(5).collect::<Vec<_>>(),
            "ai_provider": ai["provider"],
        });
        let json = serde_json::to_vec(&body).unwrap_or_default();
        return send_response(stream, 200, "application/json", &json, cors_origin).await;
    }

    // Otherwise check registry
    match engine.agent_registry().get(agent_id) {
        Some(a) => {
            let body = serde_json::json!({
                "id": a.id,
                "name": a.name,
                "profile": a.profile,
                "address": a.address,
                "port": a.port,
                "status": a.status.to_string(),
                "version": a.version,
                "capabilities": a.capabilities,
                "reputation_score": 85.0, // Remote agents dummy score for now
            });
            let json = serde_json::to_vec(&body).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        None => {
            let err = serde_json::json!({"error": format!("agent '{}' not found", agent_id)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 404, "application/json", &json, cors_origin).await
        }
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

/// API access level for RBAC middleware.
///
/// Maps REST endpoints to required minimum roles.
/// Viewer can read activities/sessions/stats.
/// Operator can additionally search.
/// Admin and Owner can access everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
enum ApiAccessLevel {
    /// Any authenticated user
    Viewer = 0,
    /// Viewer + search/export
    Operator = 1,
    /// Operator + config/write ops
    Admin = 2,
    /// All access
    Owner = 3,
}

/// Determine the required access level for an API path.
#[allow(dead_code)]
fn required_access_level(method: &str, path: &str) -> ApiAccessLevel {
    match (method, path) {
        // Read-only endpoints: Viewer
        ("GET", p)
            if p.starts_with("/api/activities")
                || p.starts_with("/api/sessions")
                || p == "/api/status"
                || p == "/api/health" =>
        {
            ApiAccessLevel::Viewer
        }
        // Search/stats: Operator
        ("POST", "/api/activities/search") => ApiAccessLevel::Operator,
        // Config changes: Admin
        ("PUT", "/api/config") => ApiAccessLevel::Admin,
        // Agent execution: Admin
        _ if method == "POST" && path.contains("/execute") => ApiAccessLevel::Admin,
        // Everything else: Viewer
        _ => ApiAccessLevel::Viewer,
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

/// Send a JSON response with pagination headers (Link + X-Total-Count).
async fn send_paginated_response(
    stream: &mut TcpStream,
    body: &[u8],
    cors_origin: &str,
    total: usize,
    offset: usize,
    limit: usize,
    base_path: &str,
) -> Result<(), AgentError> {
    let mut link_parts = Vec::new();
    if offset + limit < total {
        link_parts.push(format!(
            "<{base_path}?offset={}&limit={limit}>; rel=\"next\"",
            offset + limit,
        ));
    }
    if offset > 0 {
        let prev = offset.saturating_sub(limit);
        link_parts.push(format!(
            "<{base_path}?offset={prev}&limit={limit}>; rel=\"prev\"",
        ));
    }

    let link_header = if link_parts.is_empty() {
        String::new()
    } else {
        format!("Link: {}\r\n", link_parts.join(", "))
    };

    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         X-Total-Count: {total}\r\n\
         {link_header}\
         Access-Control-Allow-Origin: {cors_origin}\r\n\
         Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
         Access-Control-Expose-Headers: Link, X-Total-Count\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
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

// ─── Task Board handlers ─────────────────────────────────

fn parse_task_status(status: &str) -> crate::task_board::TaskStatus {
    match status.to_lowercase().as_str() {
        "in_progress" | "inprogress" | "progress" => crate::task_board::TaskStatus::InProgress,
        "review" => crate::task_board::TaskStatus::Review,
        "done" => crate::task_board::TaskStatus::Done,
        "archived" => crate::task_board::TaskStatus::Archived,
        _ => crate::task_board::TaskStatus::Backlog,
    }
}

/// GET /api/tasks — List all tasks.
async fn handle_tasks_list(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    raw_request: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let status_filter = parse_query_param(raw_request, "status").map(parse_task_status);
    let assignee_filter = parse_query_param(raw_request, "assignee")
        .and_then(|v| (!v.trim().is_empty()).then_some(v));

    let tasks = engine.list_tasks_filtered(status_filter.as_ref(), assignee_filter);
    let json = serde_json::to_vec(&tasks).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// POST /api/tasks — Create a new task.
async fn handle_task_create(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    #[derive(serde::Deserialize)]
    struct CreateReq {
        title: String,
        description: Option<String>,
        priority: String,
        assignee: Option<String>,
        tags: Vec<String>,
    }

    let req: CreateReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    if req.title.trim().is_empty() {
        let err = serde_json::json!({"error": "title is required"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
    }

    let priority = match req.priority.to_lowercase().as_str() {
        "critical" => crate::task_board::TaskPriority::Critical,
        "high" => crate::task_board::TaskPriority::High,
        "low" => crate::task_board::TaskPriority::Low,
        _ => crate::task_board::TaskPriority::Medium,
    };

    let tag_refs: Vec<&str> = req.tags.iter().map(|s| s.as_str()).collect();
    let mut task = engine.create_task(&req.title, req.description.as_deref(), priority, &tag_refs);

    if let Some(assignee) = req
        .assignee
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Ok(updated) = engine.assign_task(task.id, assignee) {
            task = updated;
        }
    }

    let json = serde_json::to_vec(&task).unwrap_or_default();
    send_response(stream, 201, "application/json", &json, cors_origin).await
}

/// POST /api/tasks/:id/move — Move task to new status.
async fn handle_task_move(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    task_id: &str,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match uuid::Uuid::parse_str(task_id) {
        Ok(u) => u,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    #[derive(serde::Deserialize)]
    struct MoveReq {
        status: String,
    }

    let req: MoveReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let status = parse_task_status(&req.status);

    match engine.move_task(uuid, status) {
        Ok(task) => {
            let json = serde_json::to_vec(&task).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        Err(e) => {
            let err = serde_json::json!({"error": e.to_string()});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 404, "application/json", &json, cors_origin).await
        }
    }
}

/// POST /api/tasks/:id/assign — Assign task to agent.
async fn handle_task_assign(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    task_id: &str,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match uuid::Uuid::parse_str(task_id) {
        Ok(u) => u,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    #[derive(serde::Deserialize)]
    struct AssignReq {
        assignee: String,
    }

    let req: AssignReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let assignee = req.assignee.trim();
    if assignee.is_empty() {
        let err = serde_json::json!({"error": "assignee is required"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
    }

    match engine.assign_task(uuid, assignee) {
        Ok(task) => {
            let json = serde_json::to_vec(&task).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        Err(e) => {
            let err = serde_json::json!({"error": e.to_string()});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 404, "application/json", &json, cors_origin).await
        }
    }
}

// ─── V4.0 Activity REST API handlers ─────────────────────

/// GET /api/activities — Paginated activity list.
/// Query params: ?offset=N&limit=N&importance=N&project=X&agent=X&type=X&since=ISO&until=ISO
async fn handle_activities_list(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    raw_request: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let offset = parse_query_param(raw_request, "offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let limit = parse_query_param(raw_request, "limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(500);

    let min_imp = parse_query_param(raw_request, "importance").and_then(|v| v.parse::<u8>().ok());
    let project_filter = parse_query_param(raw_request, "project");
    let agent_filter = parse_query_param(raw_request, "agent");
    let type_filter = parse_query_param(raw_request, "type");
    let since_filter = parse_query_param(raw_request, "since")
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));
    let until_filter = parse_query_param(raw_request, "until")
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    // Fetch a large window to filter from
    let fetch_count = (offset + limit) * 2 + 1000;
    let all_entries = if let Some(imp) = min_imp {
        engine
            .activity_manager()
            .filter_by_importance(imp, fetch_count)
    } else {
        engine.recent_activities(fetch_count)
    };

    // Apply additional filters
    let filtered: Vec<&crate::activity_log::ActivityEntry> = all_entries
        .iter()
        .filter(|e| {
            if let Some(p) = &project_filter {
                if !e.project.eq_ignore_ascii_case(p) {
                    return false;
                }
            }
            if let Some(a) = &agent_filter {
                if !e.agent_id.eq_ignore_ascii_case(a) {
                    return false;
                }
            }
            if let Some(t) = &type_filter {
                if e.activity_type.type_tag() != &**t {
                    return false;
                }
            }
            if let Some(s) = &since_filter {
                if e.timestamp < *s {
                    return false;
                }
            }
            if let Some(u) = &until_filter {
                if e.timestamp > *u {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = filtered.len();
    let page: Vec<&&crate::activity_log::ActivityEntry> =
        filtered.iter().skip(offset).take(limit).collect();

    let body = serde_json::json!({
        "count": page.len(),
        "total": total,
        "offset": offset,
        "limit": limit,
        "entries": page,
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_paginated_response(
        stream,
        &json,
        cors_origin,
        total,
        offset,
        limit,
        "/api/activities",
    )
    .await
}

/// POST /api/activities/search — Full-text search.
async fn handle_activities_search(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    #[derive(serde::Deserialize)]
    struct SearchReq {
        query: String,
        #[serde(default = "default_limit")]
        limit: usize,
    }
    fn default_limit() -> usize {
        50
    }

    let req: SearchReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let results = engine.search_activities(&req.query, req.limit.min(500));
    let resp = serde_json::json!({
        "query": req.query,
        "count": results.len(),
        "entries": results,
    });
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/activities/stats — Aggregate activity statistics.
async fn handle_activities_stats(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let stats = engine.activity_stats();
    let json = serde_json::to_vec(&stats).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/activities/:id — Single activity entry by UUID.
async fn handle_activity_detail(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    entry_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match uuid::Uuid::parse_str(entry_id) {
        Ok(u) => u,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    // Search through recent entries
    let entries = engine.recent_activities(10000);
    let found = entries.iter().find(|e| e.id == uuid);

    match found {
        Some(entry) => {
            let json = serde_json::to_vec(entry).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        None => {
            let err = serde_json::json!({"error": "entry not found"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 404, "application/json", &json, cors_origin).await
        }
    }
}

/// GET /api/sessions — List all sessions (active + completed).
/// Query params: ?offset=N&limit=N&agent=X&status=X
async fn handle_sessions_list(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    raw_request: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let offset = parse_query_param(raw_request, "offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let limit = parse_query_param(raw_request, "limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(200);
    let agent_filter = parse_query_param(raw_request, "agent");
    let status_filter = parse_query_param(raw_request, "status");

    let mgr = engine.activity_manager();
    let all_sessions = mgr.all_sessions();

    let filtered: Vec<&crate::activity_log::AgentSession> = all_sessions
        .iter()
        .filter(|s| {
            if let Some(a) = &agent_filter {
                if !s.agent_id.eq_ignore_ascii_case(a) {
                    return false;
                }
            }
            if let Some(st) = &status_filter {
                let status_str = format!("{:?}", s.status).to_lowercase();
                if status_str != st.to_lowercase() {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = filtered.len();
    let page: Vec<&&crate::activity_log::AgentSession> =
        filtered.iter().skip(offset).take(limit).collect();

    let stats = mgr.stats();
    let resp = serde_json::json!({
        "count": page.len(),
        "total": total,
        "offset": offset,
        "limit": limit,
        "total_cost_usd": stats.total_cost_usd,
        "total_tokens": stats.total_tokens,
        "sessions": page,
    });
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_paginated_response(
        stream,
        &json,
        cors_origin,
        total,
        offset,
        limit,
        "/api/sessions",
    )
    .await
}

/// GET /api/sessions/:id — Session detail.
async fn handle_session_detail(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    session_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match uuid::Uuid::parse_str(session_id) {
        Ok(u) => u,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let mgr = engine.activity_manager();
    match mgr.get_session(uuid) {
        Some(session) => {
            // Count entries belonging to this session
            let entries = engine.recent_activities(10000);
            let entry_count = entries.iter().filter(|e| e.session_id == uuid).count();

            let resp = serde_json::json!({
                "session": session,
                "entry_count": entry_count,
            });
            let json = serde_json::to_vec(&resp).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        None => {
            let err = serde_json::json!({"error": "session not found"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 404, "application/json", &json, cors_origin).await
        }
    }
}

/// GET /api/sessions/:id/timeline — Activity timeline for a session.
async fn handle_session_timeline(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    session_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match uuid::Uuid::parse_str(session_id) {
        Ok(u) => u,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    // Filter entries belonging to this session
    let entries = engine.recent_activities(10000);
    let timeline: Vec<&crate::activity_log::ActivityEntry> =
        entries.iter().filter(|e| e.session_id == uuid).collect();

    let resp = serde_json::json!({
        "session_id": session_id,
        "count": timeline.len(),
        "entries": timeline,
    });
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/sessions/:id/context — Session context injection data.
///
/// Returns the context payload that would be injected into a new agent session,
/// including recent summaries, important activities, recent errors, and decisions.
async fn handle_session_context(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    session_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match uuid::Uuid::parse_str(session_id) {
        Ok(u) => u,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let mgr = engine.activity_manager();
    // Find the session to get its project
    let project = mgr
        .get_session(uuid)
        .map(|s| s.project.clone())
        .unwrap_or_default();

    let context = mgr.build_context_injection(&project);
    let resp = serde_json::json!({
        "session_id": session_id,
        "project": project,
        "context": context,
    });
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// POST /api/agents — Register a new agent manually
async fn handle_agent_register(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let info: crate::registry::AgentInfo = match serde_json::from_str(body) {
        Ok(i) => i,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    if parse_local_agent_index(&info.id, engine.config().webui.effective_max_agents()).is_some() {
        let err = serde_json::json!({"error": "local agent IDs are reserved"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
    }

    engine.agent_registry().register(info.clone())?;

    let resp = serde_json::json!({"registered": info.id, "name": info.name});
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// POST /api/agents/discover — Trigger mDNS discovery scan
async fn handle_agents_discover(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let mut found = engine
        .discovery_service()
        .discover_mdns()
        .unwrap_or_default();

    // Fallback: If no agents found via mDNS, try a local TCP scan of common ports
    if found.is_empty() {
        let common_ports = [8443, 8543, 9443, 9543];
        for port in common_ports {
            // Don't scan our own port
            if port == engine.config().agent.listen_port {
                continue;
            }

            let addr = format!("127.0.0.1:{}", port);
            if let Ok(Ok(_)) = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            {
                found.push(crate::discovery::DiscoveredAgent {
                    name: format!("local-agent:{}", port),
                    address: "127.0.0.1".to_string(),
                    port,
                    profile: "all".to_string(),
                    version: "2.0.0".to_string(),
                    last_seen: chrono::Utc::now(),
                });
            }
        }
    }

    // Auto-register discovered agents into the registry for convenience
    for agent in &found {
        let info = crate::registry::AgentInfo {
            id: agent.name.clone(),
            name: agent.name.clone(),
            profile: agent.profile.clone(),
            address: agent.address.clone(),
            port: agent.port,
            status: crate::registry::AgentStatus::Online,
            capabilities: vec![], // Will be updated on first connection
            version: agent.version.clone(),
            last_heartbeat: chrono::Utc::now(),
            registered_at: chrono::Utc::now(),
        };
        let _ = engine.agent_registry().register(info);
    }

    let json = serde_json::to_vec(&found).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// POST /api/agent/mode — Switch between Sanctum and Market modes
async fn handle_agent_mode(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    #[derive(serde::Deserialize)]
    struct ModeRequest {
        mode: String,
    }

    let req: ModeRequest = serde_json::from_str(body)
        .map_err(|e| AgentError::SerializationError(format!("Invalid mode body: {e}")))?;

    engine.set_mode(&req.mode)?;

    let resp = serde_json::json!({"status": "success", "mode": req.mode});
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
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
    fn test_activity_feed_html_embedded() {
        assert!(!ACTIVITY_FEED_HTML.is_empty());
        assert!(ACTIVITY_FEED_HTML.contains("EdgeClaw"));
        assert!(ACTIVITY_FEED_HTML.contains("Activity"));
        assert!(ACTIVITY_FEED_HTML.contains("WebSocket"));
    }

    #[test]
    fn test_sessions_html_embedded() {
        assert!(!SESSIONS_HTML.is_empty());
        assert!(SESSIONS_HTML.contains("EdgeClaw"));
        assert!(SESSIONS_HTML.contains("Sessions"));
    }

    #[test]
    fn test_session_detail_html_embedded() {
        assert!(!SESSION_DETAIL_HTML.is_empty());
        assert!(SESSION_DETAIL_HTML.contains("EdgeClaw"));
        assert!(SESSION_DETAIL_HTML.contains("Session Detail"));
    }

    #[test]
    fn test_search_html_embedded() {
        assert!(!SEARCH_HTML.is_empty());
        assert!(SEARCH_HTML.contains("EdgeClaw"));
        assert!(SEARCH_HTML.contains("Search"));
    }

    #[test]
    fn test_stats_html_embedded() {
        assert!(!STATS_HTML.is_empty());
        assert!(STATS_HTML.contains("EdgeClaw"));
        assert!(STATS_HTML.contains("Statistics"));
    }

    #[test]
    fn test_team_map_html_embedded() {
        assert!(!TEAM_MAP_HTML.is_empty());
        assert!(TEAM_MAP_HTML.contains("EdgeClaw"));
        assert!(TEAM_MAP_HTML.contains("Team"));
        assert!(TEAM_MAP_HTML.contains("canvas"));
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

    fn http_body(response: &str) -> &str {
        if let Some((_, body)) = response.split_once("\r\n\r\n") {
            body
        } else if let Some((_, body)) = response.split_once("\n\n") {
            body
        } else {
            ""
        }
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
        assert!(resp.contains("\"local_agents\""));
    }

    #[tokio::test]
    async fn test_webui_delete_local_agent_rejected() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "DELETE /api/agents/local HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 400"));
        assert!(resp.contains("local agents cannot be deleted"));
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
    async fn test_webui_execute_local_agent() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let body = r#"{"command":"whoami","args":[]}"#;
        let req = format!(
            "POST /api/agents/local/execute HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"exec_result\""));
    }

    #[tokio::test]
    async fn test_webui_task_assign_and_filter() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Create task assigned to local-1.
        let create_body = r#"{"title":"assigned task","description":"test","priority":"Medium","assignee":"local-1","tags":["webui"]}"#;
        let create_req = format!(
            "POST /api/tasks HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            create_body.len(),
            create_body
        );
        let create_resp = http_request(&addr, &create_req).await;
        assert!(create_resp.contains("HTTP/1.1 201"));
        let created: serde_json::Value = serde_json::from_str(http_body(&create_resp)).unwrap();
        assert_eq!(created["assignee"], "local-1");
        let task_id = created["id"].as_str().unwrap().to_string();

        // Filter by assignee
        let filtered_resp = http_request(
            &addr,
            "GET /api/tasks?assignee=local-1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(filtered_resp.contains("HTTP/1.1 200"));
        let filtered: serde_json::Value = serde_json::from_str(http_body(&filtered_resp)).unwrap();
        assert!(filtered
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"] == task_id));

        // Re-assign task to local and verify.
        let assign_body = r#"{"assignee":"local"}"#;
        let assign_req = format!(
            "POST /api/tasks/{}/assign HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            task_id,
            assign_body.len(),
            assign_body
        );
        let assign_resp = http_request(&addr, &assign_req).await;
        assert!(assign_resp.contains("HTTP/1.1 200"));
        let assigned: serde_json::Value = serde_json::from_str(http_body(&assign_resp)).unwrap();
        assert_eq!(assigned["assignee"], "local");
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

    // ─── V4.0 Activity REST API tests ────────────────────

    #[tokio::test]
    async fn test_activities_list_empty() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /api/activities HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"count\":0"));
        assert!(resp.contains("\"total\":0"));
        assert!(resp.contains("X-Total-Count: 0"));
    }

    #[tokio::test]
    async fn test_activities_list_with_params() {
        let (addr, engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Record some activities
        let sid = uuid::Uuid::new_v4();
        for i in 0..5 {
            engine.activity_manager().record(
                crate::activity_log::ActivityType::CommandExec {
                    command: format!("cmd {i}"),
                    exit_code: 0,
                    duration_ms: 10,
                    output_summary: None,
                },
                &format!("test activity {i}"),
                sid,
                (i % 3) as u8 + 1,
                &["test"],
                None,
                "test-project",
            );
        }

        let resp = http_request(
            &addr,
            "GET /api/activities?limit=3&offset=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"limit\":3"));
        assert!(resp.contains("\"offset\":1"));
    }

    #[tokio::test]
    async fn test_activities_search() {
        let (addr, engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let sid = uuid::Uuid::new_v4();
        engine.activity_manager().record(
            crate::activity_log::ActivityType::CommandExec {
                command: "cargo test".into(),
                exit_code: 0,
                duration_ms: 100,
                output_summary: None,
            },
            "Running cargo test suite",
            sid,
            2,
            &["rust", "test"],
            None,
            "edgeclaw",
        );

        let body = r#"{"query":"cargo","limit":10}"#;
        let req = format!(
            "POST /api/activities/search HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(), body
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"query\":\"cargo\""));
    }

    #[tokio::test]
    async fn test_activities_stats() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /api/activities/stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("total_entries"));
    }

    #[tokio::test]
    async fn test_activity_detail_not_found() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let fake_id = uuid::Uuid::new_v4();
        let req = format!(
            "GET /api/activities/{fake_id} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 404"));
        assert!(resp.contains("entry not found"));
    }

    #[tokio::test]
    async fn test_sessions_list_empty() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let resp = http_request(
            &addr,
            "GET /api/sessions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"total\":0"));
        assert!(resp.contains("X-Total-Count: 0"));
    }

    #[tokio::test]
    async fn test_session_detail_not_found() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let fake_id = uuid::Uuid::new_v4();
        let req = format!(
            "GET /api/sessions/{fake_id} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 404"));
        assert!(resp.contains("session not found"));
    }

    #[tokio::test]
    async fn test_session_timeline() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let fake_id = uuid::Uuid::new_v4();
        let req = format!(
            "GET /api/sessions/{fake_id}/timeline HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("\"count\":0"));
    }

    #[tokio::test]
    async fn test_session_context() {
        let (addr, _engine, _tx) = start_test_server("").await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let fake_id = uuid::Uuid::new_v4();
        let req = format!(
            "GET /api/sessions/{fake_id}/context HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        );
        let resp = http_request(&addr, &req).await;
        assert!(resp.contains("HTTP/1.1 200"));
        assert!(resp.contains("context"));
    }

    #[test]
    fn test_rbac_access_levels() {
        assert_eq!(
            required_access_level("GET", "/api/activities"),
            ApiAccessLevel::Viewer
        );
        assert_eq!(
            required_access_level("GET", "/api/sessions"),
            ApiAccessLevel::Viewer
        );
        assert_eq!(
            required_access_level("POST", "/api/activities/search"),
            ApiAccessLevel::Operator
        );
        assert_eq!(
            required_access_level("PUT", "/api/config"),
            ApiAccessLevel::Admin
        );
        assert_eq!(
            required_access_level("POST", "/api/agents/abc/execute"),
            ApiAccessLevel::Admin
        );
    }

    #[test]
    fn test_rbac_ordering() {
        assert!(ApiAccessLevel::Viewer < ApiAccessLevel::Operator);
        assert!(ApiAccessLevel::Operator < ApiAccessLevel::Admin);
        assert!(ApiAccessLevel::Admin < ApiAccessLevel::Owner);
    }
}

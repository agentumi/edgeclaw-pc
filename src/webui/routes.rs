use crate::error::AgentError;
use crate::metrics::MetricsRegistry;
use crate::security::RateLimiter;
use crate::webui::handlers;
use crate::webui::http::{
    extract_bearer_token, extract_body, parse_content_length, send_cors_preflight, send_response,
};
use crate::webui::static_assets::*;
use crate::webui::{SessionManager, WebUiConfig};
use crate::AgentEngine;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub async fn handle_connection(
    stream: &mut TcpStream,
    engine: &Arc<AgentEngine>,
    metrics: &Arc<MetricsRegistry>,
    rate_limiter: &RateLimiter,
    sessions: &SessionManager,
    config: &WebUiConfig,
) -> Result<(), AgentError> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];

    // Read headers
    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| AgentError::ConnectionError(e.to_string()))?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 65536 {
            return Err(AgentError::ConnectionError("Headers too large".into()));
        }
    }

    let request_str = String::from_utf8_lossy(&buf).to_string();
    let first_line = request_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 2 {
        send_response(stream, 400, "text/plain", b"Bad Request", "*").await?;
        return Ok(());
    }

    let method = parts[0];
    let full_uri = parts[1];
    let path = full_uri.split('?').next().unwrap_or(full_uri);

    let cors_origin = if config.cors_origin.is_empty() {
        "*"
    } else {
        &config.cors_origin
    };
    let auth_required = !config.auth_password.is_empty();

    // Rate limiting
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    if peer_ip != "127.0.0.1" && peer_ip != "::1" {
        let rate_result = rate_limiter.check(&peer_ip);
        if !rate_result.is_allowed() {
            let is_api = path.starts_with("/api/");
            if is_api {
                return send_response(
                    stream,
                    429,
                    "application/json",
                    b"{\"error\":\"too many requests\"}",
                    cors_origin,
                )
                .await;
            } else {
                return send_response(
                    stream,
                    429,
                    "text/html",
                    TOO_MANY_REQUESTS_HTML.as_bytes(),
                    cors_origin,
                )
                .await;
            }
        }
    }

    // Read body if Content-Length exists
    let content_length = parse_content_length(&request_str);
    if content_length > 0 {
        let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let mut body_read = buf.len() - header_end;
        while body_read < content_length {
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|e| AgentError::ConnectionError(e.to_string()))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            body_read += n;
        }
    }
    let request_full = String::from_utf8_lossy(&buf).to_string();

    // Route public endpoints
    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            return send_response(
                stream,
                200,
                "text/html",
                DASHBOARD_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/dashboard.css") => {
            return send_response(
                stream,
                200,
                "text/css",
                DASHBOARD_CSS.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/js/dashboard/core.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_CORE_JS.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/js/dashboard/chat.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_CHAT_JS.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/js/dashboard/index.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_INDEX_JS.as_bytes(),
                cors_origin,
            )
            .await
        }

        ("GET", "/chat") | ("GET", "/chat.html") => {
            return send_response(stream, 200, "text/html", CHAT_HTML.as_bytes(), cors_origin).await
        }
        ("GET", "/activity") => {
            return send_response(
                stream,
                200,
                "text/html",
                ACTIVITY_FEED_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/sessions") => {
            return send_response(
                stream,
                200,
                "text/html",
                SESSIONS_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/search") => {
            return send_response(
                stream,
                200,
                "text/html",
                SEARCH_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/stats") => {
            return send_response(stream, 200, "text/html", STATS_HTML.as_bytes(), cors_origin)
                .await
        }
        ("GET", "/team") => {
            return send_response(
                stream,
                200,
                "text/html",
                TEAM_MAP_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/automations")
        | ("GET", "/automations.html")
        | ("GET", "/marketplace")
        | ("GET", "/marketplace.html")
        | ("GET", "/market")
        | ("GET", "/settings")
        | ("GET", "/settings.html")
        | ("GET", "/extensions")
        | ("GET", "/memory")
        | ("GET", "/dashboard")
        | ("GET", "/board")
        | ("GET", "/missions") => {
            return send_response(
                stream,
                200,
                "text/html",
                DASHBOARD_HTML.as_bytes(),
                cors_origin,
            )
            .await;
        }

        ("GET", "/metrics") => {
            return handlers::metrics::handle_metrics_prometheus(
                stream,
                metrics,
                engine,
                cors_origin,
            )
            .await
        }
        ("GET", "/health") | ("GET", "/api/health") => {
            return handlers::status::handle_health(stream, engine, cors_origin).await
        }

        ("POST", "/api/login") => {
            let body = extract_body(&request_full);
            return handlers::auth::handle_login(
                stream,
                sessions,
                &peer_ip,
                &config.auth_password,
                auth_required,
                &body,
                cors_origin,
            )
            .await;
        }

        ("OPTIONS", _) => return send_cors_preflight(stream, cors_origin).await,

        _ if path.starts_with("/session/") => {
            return send_response(
                stream,
                200,
                "text/html",
                SESSION_DETAIL_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        _ => {}
    }

    // Auth check for protected endpoints
    if auth_required {
        let token = extract_bearer_token(&request_full);
        if let Some(t) = token {
            if !sessions.validate(t, &peer_ip).await {
                let err = serde_json::json!({"error": "unauthorized", "login_required": true});
                let json = serde_json::to_vec(&err).unwrap_or_default();
                return send_response(stream, 401, "application/json", &json, cors_origin).await;
            }
        } else {
            let err = serde_json::json!({"error": "unauthorized", "login_required": true});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 401, "application/json", &json, cors_origin).await;
        }
    }

    // Route protected API endpoints
    match (method, path) {
        ("GET", "/api/status") => {
            handlers::status::handle_status(stream, engine, cors_origin).await
        }
        ("GET", "/api/infra/summary") | ("GET", "/api/v1/infra/summary") => {
            handlers::status::handle_infra_summary(stream, engine, cors_origin).await
        }
        ("GET", "/api/quick-actions") => {
            handlers::config::handle_quick_actions(stream, engine, cors_origin).await
        }
        ("GET", "/api/market/stats") => {
            handlers::config::handle_market_stats(stream, engine, cors_origin).await
        }
        ("GET", "/api/agents") => {
            handlers::agents::handle_agents_info(stream, engine, cors_origin).await
        }
        ("GET", "/api/agents/graph") => {
            handlers::agents::handle_agents_graph(stream, engine, cors_origin).await
        }
        ("POST", "/api/agents/discover") => {
            handlers::agents::handle_agents_discover(stream, engine, cors_origin).await
        }
        ("POST", "/api/agents") => {
            let body = extract_body(&request_full);
            handlers::agents::handle_agent_register(stream, engine, &body, cors_origin).await
        }

        ("GET", "/api/metrics/history") => {
            handlers::metrics::handle_metrics_history(stream, metrics, engine, cors_origin).await
        }
        ("GET", "/api/audit/entries") => {
            handlers::metrics::handle_audit_entries(stream, engine, &request_full, cors_origin)
                .await
        }
        ("GET", "/api/audit/verify") => {
            handlers::metrics::handle_audit_verify(stream, engine, cors_origin).await
        }

        ("GET", "/api/config") => {
            handlers::config::handle_config_get(stream, engine, cors_origin).await
        }
        ("PUT", "/api/config") => {
            let body = extract_body(&request_full);
            handlers::config::handle_config_update(stream, engine, &body, cors_origin).await
        }
        ("PUT", "/api/config/identity") => {
            let body = extract_body(&request_full);
            handlers::config::handle_config_identity_update(stream, engine, &body, cors_origin)
                .await
        }
        ("PUT", "/api/config/avatar") => {
            let body = extract_body(&request_full);
            handlers::config::handle_config_avatar_update(stream, engine, &body, cors_origin).await
        }

        ("GET", "/api/rent-policies") => {
            handlers::config::handle_rent_policy_get(stream, engine, cors_origin).await
        }
        ("PUT", "/api/rent-policies") => {
            let body = extract_body(&request_full);
            handlers::config::handle_rent_policy_update(stream, engine, &body, cors_origin).await
        }

        ("POST", "/api/chat") => {
            let body = extract_body(&request_full);
            handlers::chat::handle_chat(stream, engine, &body, cors_origin).await
        }
        ("GET", "/api/chat/history") => {
            handlers::chat::handle_chat_history(stream, engine, cors_origin).await
        }
        ("DELETE", "/api/chat") => {
            handlers::chat::handle_chat_clear(stream, engine, cors_origin).await
        }

        ("GET", "/api/memory") => {
            handlers::memory::handle_memory_info(stream, engine, cors_origin).await
        }
        ("GET", "/api/memory/storage") => {
            handlers::memory::handle_memory_storage(stream, engine, cors_origin).await
        }
        ("GET", "/api/memory/graph") => {
            handlers::memory::handle_memory_graph(stream, engine, cors_origin).await
        }
        ("PUT", "/api/memory/core") => {
            let body = extract_body(&request_full);
            handlers::memory::handle_memory_core_update(stream, engine, &body, cors_origin).await
        }
        ("POST", "/api/memory/tier") => {
            let body = extract_body(&request_full);
            handlers::memory::handle_memory_tier_add(stream, engine, &body, cors_origin).await
        }
        ("POST", "/api/memory/lessons") => {
            let body = extract_body(&request_full);
            handlers::memory::handle_memory_lesson_add(stream, engine, &body, cors_origin).await
        }

        ("GET", "/api/tasks") => {
            handlers::tasks::handle_tasks_list(stream, engine, &request_full, cors_origin).await
        }
        ("POST", "/api/tasks") => {
            let body = extract_body(&request_full);
            handlers::tasks::handle_task_create(stream, engine, &body, cors_origin).await
        }
        ("GET", "/api/templates") => {
            handlers::templates::handle_templates_list(stream, engine, cors_origin).await
        }
        ("GET", "/api/missions") => {
            handlers::tasks::handle_missions_list(stream, engine, cors_origin).await
        }
        ("GET", "/api/v1/mission/active") => {
            handlers::tasks::handle_mission_active(stream, engine, cors_origin).await
        }

        ("POST", "/api/automations") => {
            let body = extract_body(&request_full);
            handlers::templates::handle_automation_create(stream, engine, &body, cors_origin).await
        }

        ("GET", "/api/activities") => {
            handlers::activities::handle_activities_list(stream, engine, &request_full, cors_origin)
                .await
        }
        ("POST", "/api/activities/search") => {
            let body = extract_body(&request_full);
            handlers::activities::handle_activities_search(stream, engine, &body, cors_origin).await
        }
        ("GET", "/api/activities/stats") => {
            handlers::activities::handle_activities_stats(stream, engine, cors_origin).await
        }

        ("GET", "/api/sessions") => {
            handlers::activities::handle_sessions_list(stream, engine, &request_full, cors_origin)
                .await
        }

        _ => {
            // Path-parameter routes
            if path.starts_with("/api/memory/search") {
                let query = full_uri
                    .split('?')
                    .nth(1)
                    .and_then(|qs| qs.split('&').find(|p| p.starts_with("q=")))
                    .map(|p| p.strip_prefix("q=").unwrap_or(""))
                    .unwrap_or("");
                handlers::memory::handle_memory_search(stream, engine, query, cors_origin).await
            } else if path.starts_with("/api/memory/") && method == "DELETE" {
                let mem_id = path.strip_prefix("/api/memory/").unwrap_or("");
                handlers::memory::handle_memory_delete(stream, engine, mem_id, cors_origin).await
            } else if path.starts_with("/api/templates/") && method == "GET" {
                let template_id = path.strip_prefix("/api/templates/").unwrap_or("");
                handlers::templates::handle_template_detail(
                    stream,
                    engine,
                    template_id,
                    cors_origin,
                )
                .await
            } else if path.starts_with("/api/tasks/") && path.ends_with("/move") && method == "POST"
            {
                let task_id = path
                    .strip_prefix("/api/tasks/")
                    .and_then(|s| s.strip_suffix("/move"))
                    .unwrap_or("");
                let body = extract_body(&request_full);
                handlers::tasks::handle_task_move(stream, engine, task_id, &body, cors_origin).await
            } else if path.starts_with("/api/tasks/")
                && path.ends_with("/assign")
                && method == "POST"
            {
                let task_id = path
                    .strip_prefix("/api/tasks/")
                    .and_then(|s| s.strip_suffix("/assign"))
                    .unwrap_or("");
                let body = extract_body(&request_full);
                handlers::tasks::handle_task_assign(stream, engine, task_id, &body, cors_origin)
                    .await
            } else if path.starts_with("/api/tasks/") && method == "DELETE" {
                let task_id = path.strip_prefix("/api/tasks/").unwrap_or("");
                handlers::tasks::handle_task_delete(stream, engine, task_id, cors_origin).await
            } else if path.starts_with("/api/agents/")
                && path.ends_with("/execute")
                && method == "POST"
            {
                let agent_id = path
                    .strip_prefix("/api/agents/")
                    .and_then(|s| s.strip_suffix("/execute"))
                    .unwrap_or("");
                let body = extract_body(&request_full);
                handlers::agents::handle_agent_execute(stream, engine, agent_id, &body, cors_origin)
                    .await
            } else if path.starts_with("/api/agents/")
                && path.ends_with("/metrics")
                && method == "GET"
            {
                let agent_id = path
                    .strip_prefix("/api/agents/")
                    .and_then(|s| s.strip_suffix("/metrics"))
                    .unwrap_or("");
                handlers::agents::handle_agent_metrics(stream, engine, agent_id, cors_origin).await
            } else if path.starts_with("/api/agents/") && method == "DELETE" {
                let agent_id = path.strip_prefix("/api/agents/").unwrap_or("");
                handlers::agents::handle_agent_delete(stream, engine, agent_id, cors_origin).await
            } else if path.starts_with("/api/agents/") && method == "GET" {
                let agent_id = path.strip_prefix("/api/agents/").unwrap_or("");
                handlers::agents::handle_agent_profile(stream, engine, agent_id, cors_origin).await
            } else if path.starts_with("/api/avatars/") && method == "GET" {
                let name = path.strip_prefix("/api/avatars/").unwrap_or("");
                handlers::agents::handle_avatar_get(stream, engine, name, cors_origin).await
            } else if path.starts_with("/api/activities/") && method == "GET" {
                let entry_id = path.strip_prefix("/api/activities/").unwrap_or("");
                handlers::activities::handle_activity_detail(stream, engine, entry_id, cors_origin)
                    .await
            } else if path.starts_with("/api/sessions/")
                && path.ends_with("/timeline")
                && method == "GET"
            {
                let session_id = path
                    .strip_prefix("/api/sessions/")
                    .and_then(|s| s.strip_suffix("/timeline"))
                    .unwrap_or("");
                handlers::activities::handle_session_timeline(
                    stream,
                    engine,
                    session_id,
                    cors_origin,
                )
                .await
            } else if path.starts_with("/api/sessions/")
                && path.ends_with("/context")
                && method == "GET"
            {
                let session_id = path
                    .strip_prefix("/api/sessions/")
                    .and_then(|s| s.strip_suffix("/context"))
                    .unwrap_or("");
                handlers::activities::handle_session_context(
                    stream,
                    engine,
                    session_id,
                    cors_origin,
                )
                .await
            } else if path.starts_with("/api/sessions/") && method == "GET" {
                let session_id = path.strip_prefix("/api/sessions/").unwrap_or("");
                handlers::activities::handle_session_detail(stream, engine, session_id, cors_origin)
                    .await
            } else if path.starts_with("/api/automations/")
                && path.ends_with("/run")
                && method == "POST"
            {
                let automation_id = path
                    .strip_prefix("/api/automations/")
                    .and_then(|s| s.strip_suffix("/run"))
                    .unwrap_or("");
                handlers::templates::handle_automation_run(
                    stream,
                    engine,
                    automation_id,
                    cors_origin,
                )
                .await
            } else if path.starts_with("/api/extensions/")
                && path.ends_with("/config")
                && method == "POST"
            {
                let ext_id = path
                    .strip_prefix("/api/extensions/")
                    .and_then(|s| s.strip_suffix("/config"))
                    .unwrap_or("");
                let body = extract_body(&request_full);
                handlers::extensions::handle_extension_config(
                    stream,
                    engine,
                    ext_id,
                    &body,
                    cors_origin,
                )
                .await
            } else if path.starts_with("/api/extensions/")
                && path.ends_with("/run")
                && method == "POST"
            {
                let ext_id = path
                    .strip_prefix("/api/extensions/")
                    .and_then(|s| s.strip_suffix("/run"))
                    .unwrap_or("");
                handlers::extensions::handle_extension_run(stream, engine, ext_id, cors_origin)
                    .await
            } else if path.starts_with("/api/extensions/")
                && path.ends_with("/runs")
                && method == "GET"
            {
                let ext_id = path
                    .strip_prefix("/api/extensions/")
                    .and_then(|s| s.strip_suffix("/runs"))
                    .unwrap_or("");
                handlers::extensions::handle_extension_runs(stream, ext_id, cors_origin).await
            } else {
                send_response(
                    stream,
                    404,
                    "application/json",
                    b"{\"error\":\"not found\"}",
                    cors_origin,
                )
                .await
            }
        }
    }
}

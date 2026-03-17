use crate::error::AgentError;
use crate::webui::http::{parse_query_param, send_paginated_response, send_response};
use crate::AgentEngine;
use tokio::net::TcpStream;
use uuid::Uuid;

/// GET /api/activities — Paginated list of all activities
pub async fn handle_activities_list(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    request: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let limit = parse_query_param(request, "limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(1000);
    let offset = parse_query_param(request, "offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let (entries, total) = engine.activity_manager().list(limit, offset);
    let count = entries.len();

    let body = serde_json::json!({
        "limit": limit,
        "offset": offset,
        "count": count,
        "total": total,
        "entries": entries,
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

/// POST /api/activities/search — Full-text search in activities
pub async fn handle_activities_search(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    #[derive(serde::Deserialize)]
    struct SearchReq {
        query: String,
        limit: Option<usize>,
    }

    let req: SearchReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let limit = req.limit.unwrap_or(50).min(500);
    let results = engine.activity_manager().search(&req.query, limit);

    let body_resp = serde_json::json!({
        "query": req.query,
        "limit": limit,
        "count": results.len(),
        "entries": results,
    });
    let json = serde_json::to_vec(&body_resp).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/activities/stats — Activity summary counters
pub async fn handle_activities_stats(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let stats = engine.activity_manager().stats();
    let json = serde_json::to_vec(&stats).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/activities/{id} — Single activity detail
pub async fn handle_activity_detail(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    entry_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match Uuid::parse_str(entry_id) {
        Ok(u) => u,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    match engine.activity_manager().get_entry(uuid) {
        Some(entry) => {
            let json = serde_json::to_vec(&entry).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        None => {
            let err = serde_json::json!({"error": "entry not found"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 404, "application/json", &json, cors_origin).await
        }
    }
}

/// GET /api/sessions — Paginated list of sessions
pub async fn handle_sessions_list(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    request: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let limit = parse_query_param(request, "limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(500);
    let offset = parse_query_param(request, "offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let (sessions, total) = engine.activity_manager().list_sessions(limit, offset);
    let body = serde_json::json!({
        "limit": limit,
        "offset": offset,
        "total": total,
        "sessions": sessions,
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
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

/// GET /api/sessions/{id} — Single session metadata
pub async fn handle_session_detail(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    session_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match Uuid::parse_str(session_id) {
        Ok(u) => u,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    match engine.activity_manager().get_session(uuid) {
        Some(session) => {
            let json = serde_json::to_vec(&session).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        None => {
            let err = serde_json::json!({"error": "session not found"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 404, "application/json", &json, cors_origin).await
        }
    }
}

/// GET /api/sessions/{id}/timeline — All events for a specific session
pub async fn handle_session_timeline(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    session_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match Uuid::parse_str(session_id) {
        Ok(u) => u,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let entries = engine.activity_manager().session_timeline(uuid);
    let body = serde_json::json!({
        "session_id": session_id,
        "count": entries.len(),
        "entries": entries,
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/sessions/{id}/context — Re-construct world context from session state
pub async fn handle_session_context(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    session_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match Uuid::parse_str(session_id) {
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

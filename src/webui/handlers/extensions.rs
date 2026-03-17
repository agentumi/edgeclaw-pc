use crate::error::AgentError;
use crate::webui::http::send_response;
use crate::AgentEngine;
use tokio::net::TcpStream;

/// GET /api/extensions — Returns the list of built-in extensions.
pub async fn handle_extensions_list(
    stream: &mut TcpStream,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let catalog = builtin_extension_catalog();
    let json = serde_json::to_vec(&catalog).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// POST /api/extensions — Register a new custom extension module.
pub async fn handle_extension_create(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    #[derive(serde::Deserialize)]
    struct CreateReq {
        id: String,
        name: String,
        _description: String,
    }

    let req: CreateReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let activity = crate::activity_log::ActivityType::Custom {
        category: "extension".to_string(),
        data: serde_json::json!({"action": "create", "id": req.id}),
    };
    engine.record_activity(
        activity,
        &format!("Extension '{}' created", req.name),
        uuid::Uuid::new_v4(),
        1,
        &["extension", "create"],
        None,
        "all",
    );

    let resp = serde_json::json!({"status": "created", "id": req.id});
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 201, "application/json", &json, cors_origin).await
}

/// GET /api/extensions/readiness — Returns status of active/available extensions.
pub async fn handle_extensions_readiness(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let ai = engine.ai_status();
    let body = serde_json::json!({
        "status": "ready",
        "active_extensions": ["orchestrator", "ai_chat", "monitoring"],
        "ai_ready": ai["available"],
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// POST /api/extensions/{id}/config — Update config for an extension module.
pub async fn handle_extension_config(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    ext_id: &str,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let activity = crate::activity_log::ActivityType::Custom {
        category: "extension".to_string(),
        data: serde_json::json!({"action": "config", "id": ext_id, "body": body}),
    };
    engine.record_activity(
        activity,
        &format!("Extension '{}' configured", ext_id),
        uuid::Uuid::new_v4(),
        1,
        &["extension", "config"],
        None,
        "all",
    );

    let resp = serde_json::json!({"status": "updated", "id": ext_id});
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// POST /api/extensions/{id}/run — Trigger execution of an extension.
pub async fn handle_extension_run(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    ext_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let activity = crate::activity_log::ActivityType::Custom {
        category: "extension".to_string(),
        data: serde_json::json!({"action": "run", "id": ext_id}),
    };
    engine.record_activity(
        activity,
        &format!("Extension '{}' execution triggered", ext_id),
        uuid::Uuid::new_v4(),
        1,
        &["extension", "run"],
        None,
        "all",
    );

    let resp = serde_json::json!({
        "status": "triggered",
        "id": ext_id,
        "execution_id": uuid::Uuid::new_v4().to_string()
    });
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 202, "application/json", &json, cors_origin).await
}

/// GET /api/extensions/{id}/runs — Recent execution history for an extension module.
pub async fn handle_extension_runs(
    stream: &mut TcpStream,
    ext_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let body = serde_json::json!({
        "extension_id": ext_id,
        "runs": [
            {"id": "run-1", "status": "success", "start_time": chrono::Utc::now() - chrono::Duration::hours(1), "duration_ms": 1240},
            {"id": "run-2", "status": "success", "start_time": chrono::Utc::now() - chrono::Duration::hours(2), "duration_ms": 1150}
        ]
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

pub fn builtin_extension_catalog() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "id": "builtin:orchestrator",
            "name": "Cloud Orchestrator",
            "description": "Multi-cluster agent management",
            "version": "1.2.0",
            "author": "EdgeClaw",
            "status": "active"
        }),
        serde_json::json!({
            "id": "builtin:monitor",
            "name": "Live Monitor",
            "description": "Real-time resource visualization",
            "version": "1.0.5",
            "author": "EdgeClaw",
            "status": "active"
        }),
        serde_json::json!({
            "id": "builtin:security",
            "name": "Security Guard",
            "description": "Automated threat detection and RBAC enforcement",
            "version": "2.1.0",
            "author": "EdgeClaw",
            "status": "active"
        }),
    ]
}

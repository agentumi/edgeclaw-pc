use crate::error::AgentError;
use crate::webui::http::send_response;
use crate::AgentEngine;
use tokio::net::TcpStream;

/// GET /api/v2.3/groups
pub async fn handle_groups_list(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let groups = engine.group_manager().list_all();
    let json_bytes = serde_json::to_vec(&groups).unwrap_or_default();
    send_response(stream, 200, "application/json", &json_bytes, cors_origin).await
}

/// POST /api/v2.3/groups
pub async fn handle_group_create(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let req: serde_json::Value = serde_json::from_str(body)?;
    let name = req["name"].as_str().unwrap_or("New Team");
    let desc = req["description"].as_str().unwrap_or("");

    let group = engine.group_manager().create_group(name, desc);
    let json_bytes = serde_json::to_vec(&group).unwrap_or_default();
    send_response(stream, 201, "application/json", &json_bytes, cors_origin).await
}
/// POST /api/v2.3/groups/:id/members
pub async fn handle_group_add_member(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    group_id: &str,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let req: serde_json::Value = serde_json::from_str(body)?;
    let peer_id = req["peer_id"]
        .as_str()
        .ok_or_else(|| AgentError::ExecutionError("peer_id required".into()))?;

    engine.group_manager().add_member(group_id, peer_id)?;
    send_response(
        stream,
        200,
        "application/json",
        b"{\"status\":\"success\"}",
        cors_origin,
    )
    .await
}

/// GET /api/v2.3/groups/:id/members
pub async fn handle_group_members_list(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    group_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    if let Some(group) = engine.group_manager().get_group(group_id) {
        let members: Vec<String> = group.member_ids.into_iter().collect();
        let json_bytes = serde_json::to_vec(&members).unwrap_or_default();
        send_response(stream, 200, "application/json", &json_bytes, cors_origin).await
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
/// POST /api/v2.3/groups/:id/policy
pub async fn handle_group_set_policy(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    group_id: &str,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let req: serde_json::Value = serde_json::from_str(body)?;
    let capability = req["capability"]
        .as_str()
        .ok_or_else(|| AgentError::ExecutionError("capability required".into()))?;
    let allowed = req["allowed"].as_bool().unwrap_or(false);

    engine
        .group_manager()
        .set_policy_override(group_id, capability, allowed)?;
    send_response(
        stream,
        200,
        "application/json",
        b"{\"status\":\"success\"}",
        cors_origin,
    )
    .await
}

/// POST /api/v2.3/groups/:id/memory/sync
pub async fn handle_group_toggle_memory(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    group_id: &str,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let req: serde_json::Value = serde_json::from_str(body)?;
    let sync = req["sync"].as_bool().unwrap_or(true);

    engine.group_manager().set_memory_sync(group_id, sync)?;
    send_response(
        stream,
        200,
        "application/json",
        b"{\"status\":\"success\"}",
        cors_origin,
    )
    .await
}

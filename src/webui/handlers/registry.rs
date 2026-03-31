use crate::error::AgentError;
use crate::registry::AgentStatus;
use crate::webui::http::send_response;
use crate::AgentEngine;
use serde::Deserialize;
use tokio::net::TcpStream;

/// GET /api/agents — List all agents in the registry
pub async fn handle_list_agents(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let registry = engine.agent_registry();
    let agents = registry.list_all();
    let json = serde_json::to_vec(&agents).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

#[derive(Deserialize)]
struct UpdateAgentReq {
    name: Option<String>,
    profile: Option<String>,
    persona: Option<String>,
    status: Option<String>,
}

/// POST /api/agents/:id — Update agent information
pub async fn handle_update_agent(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    agent_id: &str,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let req: UpdateAgentReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let registry = engine.agent_registry();
    let mut info = match registry.get(agent_id) {
        Some(i) => i,
        None => {
            let err = serde_json::json!({"error": format!("Agent {} not found", agent_id)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 404, "application/json", &json, cors_origin).await;
        }
    };

    if let Some(n) = req.name {
        info.name = n;
    }
    if let Some(p) = req.profile {
        info.profile = p;
    }
    if let Some(per) = req.persona {
        info.persona = per;
    }

    if let Some(s_str) = req.status {
        match s_str.to_lowercase().as_str() {
            "online" => info.status = AgentStatus::Online,
            "busy" => info.status = AgentStatus::Busy,
            "offline" => info.status = AgentStatus::Offline,
            "error" => info.status = AgentStatus::Error,
            _ => {}
        }
    }

    registry.register(info.clone())?;

    let resp = serde_json::json!({"success": true, "agent": info});
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

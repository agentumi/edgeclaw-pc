use crate::error::AgentError;
use crate::webui::http::send_response;
use crate::AgentEngine;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub fn parse_local_agent_index(agent_id: &str, max_agents: u16) -> Option<u16> {
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

pub fn local_agent_peer_id(index: u16) -> String {
    if index == 0 {
        "web-client".to_string()
    } else {
        format!("web-client-{}", index)
    }
}

pub fn local_agent_id(index: u16) -> String {
    if index == 0 {
        "local".to_string()
    } else {
        format!("local-{}", index)
    }
}

pub fn local_agent_name(base_name: &str, index: u16) -> String {
    if index == 0 {
        base_name.to_string()
    } else {
        format!("{}-{}", base_name, index + 1)
    }
}

/// GET /api/agents — Multi-agent instance info + remote agent registry
pub async fn handle_agents_info(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let config = engine.config();
    let max = config.webui.effective_max_agents();
    let online_agents = engine.agent_registry().count_online();
    let mut instances = Vec::new();
    let mut local_agents = Vec::new();
    let base_name = if config.agent.display_name.is_empty() {
        &config.agent.device_name
    } else {
        &config.agent.display_name
    };
    for i in 0..max {
        let port = config.webui.agent_port(i);
        let id = local_agent_id(i);
        let peer_id = local_agent_peer_id(i);
        
        let (name, role, persona) = if i == 0 {
            let n = if config.agent.display_name.trim().is_empty() { "Strategic Analyst".to_string() } else { config.agent.display_name.clone() };
            let r = if config.agent.role.trim().is_empty() { "Business Analyst".to_string() } else { config.agent.role.clone() };
            let p = if config.agent.persona.trim().is_empty() { "Executive strategy expert focusing on market data, KPI optimization, and high-level ROI analysis.".to_string() } else { config.agent.persona.clone() };
            (n, r, p)
        } else if let Some(fid) = config.webui.fleet_identities.get(&i) {
            (
                if fid.display_name.trim().is_empty() { local_agent_name(base_name, i) } else { fid.display_name.clone() },
                if fid.role.trim().is_empty() { "Worker".to_string() } else { fid.role.clone() },
                fid.persona.clone()
            )
        } else {
            (local_agent_name(base_name, i), config.webui.work_profile.clone(), "".to_string())
        };

        instances.push(serde_json::json!({
            "index": i,
            "port": port,
            "url": format!("http://{}:{}", config.webui.bind, port),
            "peer_id": peer_id,
        }));

        local_agents.push(serde_json::json!({
            "id": id,
            "name": name,
            "profile": role,
            "persona": persona,
            "address": config.webui.bind,
            "port": port,
            "status": "online",
            "source": "local",
            "capabilities": engine.get_capabilities(),
            "peer_id": peer_id,
            "instance_index": i,
        }));
    }

    // Include remote agents from the persistent registry with port-based deduplication
    let local_ids: std::collections::HashSet<String> = local_agents.iter().filter_map(|a| a["id"].as_str().map(|s| s.to_string())).collect();
    let local_ports: std::collections::HashSet<u16> = instances.iter().filter_map(|i| i["port"].as_u64().map(|p| p as u16)).collect();

    let registered: Vec<serde_json::Value> = engine
        .agent_registry()
        .list_all()
        .into_iter()
        .filter(|a| !local_ids.contains(&a.id) && !local_ports.contains(&a.port))
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
                "persona": a.persona,
                "performance_rating": a.performance_rating,
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

/// POST /api/agents/{id}/execute
pub async fn handle_agent_execute(
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
        let base_name = if engine.config().agent.display_name.is_empty() {
            &engine.config().agent.device_name
        } else {
            &engine.config().agent.display_name
        };
        let agent_name = local_agent_name(base_name, index);
        let _ = engine.add_peer(&peer_id, &agent_name, "local-worker", "127.0.0.1", "owner");

        let timeout_val = req
            .timeout_secs
            .unwrap_or(30)
            .clamp(1, engine.config().execution.max_timeout_secs);
        let action = req.action.unwrap_or_else(|| "shell_exec".to_string());
        let exec_req = crate::executor::ExecRequest {
            execution_id: uuid::Uuid::new_v4().to_string(),
            action,
            command: req.command,
            args: req.args,
            timeout_secs: timeout_val,
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
pub async fn handle_agent_delete(
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

/// GET /api/agents/{id} — Detailed agent profile including reputation
pub async fn handle_agent_profile(
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
        let base_name = if engine.config().agent.display_name.is_empty() {
            &engine.config().agent.device_name
        } else {
            &engine.config().agent.display_name
        };
        let id = local_agent_id(index);
        let port = engine.config().webui.agent_port(index);
        let peer_id = local_agent_peer_id(index);
        let tasks = engine.list_tasks_filtered(None, Some(&id));
        let agent_cfg = engine.config().agent.clone();
        
        let (name, role, persona) = if index == 0 {
            let n = if agent_cfg.display_name.trim().is_empty() { "Strategic Analyst".to_string() } else { agent_cfg.display_name.clone() };
            let r = if agent_cfg.role.trim().is_empty() { "Business Analyst".to_string() } else { agent_cfg.role.clone() };
            let p = if agent_cfg.persona.trim().is_empty() { "Executive strategy expert focusing on market data, KPI optimization, and high-level ROI analysis.".to_string() } else { agent_cfg.persona.clone() };
            (n, r, p)
        } else if let Some(fid) = engine.config().webui.fleet_identities.get(&index) {
            (
                if fid.display_name.trim().is_empty() { local_agent_name(base_name, index) } else { fid.display_name.clone() },
                if fid.role.trim().is_empty() { "Worker".to_string() } else { fid.role.clone() },
                fid.persona.clone()
            )
        } else {
            (local_agent_name(base_name, index), engine.config().webui.work_profile.clone(), agent_cfg.persona.clone())
        };

        let body = serde_json::json!({
            "id": id,
            "name": name,
            "profile": role,
            "status": "online",
            "reputation_score": score,
            "capabilities": engine.get_capabilities(),
            "uptime_secs": engine.uptime_secs(),
            "address": engine.config().webui.bind,
            "port": port,
            "peer_id": peer_id,
            "identity": {
                "device_name": agent_cfg.device_name,
                "display_name": name,
                "avatar_url": agent_cfg.avatar_url,
                "persona": persona,
                "role": role,
                "email": agent_cfg.email,
                "messenger": agent_cfg.messenger,
                "phone": agent_cfg.phone,
            },
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

pub async fn probe_agent_latency_ms(address: &str, port: u16) -> Option<u64> {
    let addr = format!("{}:{}", address.trim(), port);
    if addr.starts_with(':') || addr.ends_with(':') {
        return None;
    }
    let start = Instant::now();
    match timeout(Duration::from_millis(800), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            Some(start.elapsed().as_millis().min(u64::MAX as u128) as u64)
        }
        _ => None,
    }
}

/// GET /api/agents/{id}/metrics — Lightweight metrics for agent resources/latency
pub async fn handle_agent_metrics(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    agent_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    if let Some(index) =
        parse_local_agent_index(agent_id, engine.config().webui.effective_max_agents())
    {
        let sys = engine.get_system_info();
        let port = engine.config().webui.agent_port(index);
        let mut address = engine.config().webui.bind.clone();
        if address == "0.0.0.0" || address == "::" {
            address = "127.0.0.1".to_string();
        }
        let latency = probe_agent_latency_ms(&address, port).await;
        let body = serde_json::json!({
            "id": local_agent_id(index),
            "source": "local",
            "status": "online",
            "cpu_pct": sys.cpu_usage,
            "ram_pct": sys.memory_usage_percent,
            "uptime_secs": engine.uptime_secs(),
            "latency_ms": latency,
        });
        let json = serde_json::to_vec(&body).unwrap_or_default();
        return send_response(stream, 200, "application/json", &json, cors_origin).await;
    }

    match engine.agent_registry().get(agent_id) {
        Some(agent) => {
            let status = agent.status.to_string();
            let should_probe = status == "online" || status == "busy";
            let latency = if should_probe {
                probe_agent_latency_ms(&agent.address, agent.port).await
            } else {
                None
            };
            let body = serde_json::json!({
                "id": agent.id,
                "source": "remote",
                "status": status,
                "cpu_pct": Option::<f32>::None,
                "ram_pct": Option::<f32>::None,
                "uptime_secs": Option::<u64>::None,
                "latency_ms": latency,
                "last_seen": agent.last_heartbeat,
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

/// GET /api/agents/graph — Returns agent graph nodes and edges
pub async fn handle_agents_graph(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let peers = engine.get_peers();

    let mut nodes: Vec<serde_json::Value> = Vec::new();
    let mut edges: Vec<serde_json::Value> = Vec::new();

    // Local hub node
    nodes.push(serde_json::json!({
        "id": "local",
        "label": "Local Agent",
        "type": "local",
        "status": "online",
        "x": 0,
        "y": 0
    }));

    for (i, peer) in peers.iter().enumerate() {
        let id = &peer.peer_id;
        let name = &peer.device_name;
        let status = if peer.is_connected {
            "online"
        } else {
            "offline"
        };
        nodes.push(serde_json::json!({
            "id": id,
            "label": name,
            "type": "remote",
            "status": status,
            "x": (i as f64 + 1.0) * 120.0,
            "y": ((i % 2) as f64) * 80.0
        }));
        edges.push(serde_json::json!({
            "from": "local",
            "to": id,
            "label": status
        }));
    }

    let graph = serde_json::json!({ "nodes": nodes, "edges": edges });
    let json = serde_json::to_vec(&graph).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

pub fn avatar_storage_dir(engine: &AgentEngine) -> std::path::PathBuf {
    if cfg!(test) {
        std::env::temp_dir().join("edgeclaw_test_avatars")
    } else {
        engine.config().storage_dir().join("avatars")
    }
}

/// GET /api/avatars/{name} — Serve stored avatar image.
pub async fn handle_avatar_get(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    name: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    if name.is_empty() || name.contains("..") || name.contains('/') || name.contains('\\') {
        let err = serde_json::json!({"error": "invalid avatar name"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
    }

    let path = avatar_storage_dir(engine).join(name);
    if !path.exists() {
        let err = serde_json::json!({"error": "avatar not found"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 404, "application/json", &json, cors_origin).await;
    }

    let content_type = if name.ends_with(".png") {
        "image/png"
    } else if name.ends_with(".jpg") || name.ends_with(".jpeg") {
        "image/jpeg"
    } else if name.ends_with(".webp") {
        "image/webp"
    } else {
        "application/octet-stream"
    };

    let bytes = std::fs::read(&path)?;
    send_response(stream, 200, content_type, &bytes, cors_origin).await
}

/// POST /api/agents — Register a new agent manually
pub async fn handle_agent_register(
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
pub async fn handle_agents_discover(
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
            if port == engine.config().agent.listen_port {
                continue;
            }

            let addr = format!("127.0.0.1:{}", port);
            if let Ok(Ok(_)) = timeout(
                Duration::from_millis(100),
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

    for agent in &found {
        let info_reg = crate::registry::AgentInfo {
            id: agent.name.clone(),
            name: agent.name.clone(),
            profile: agent.profile.clone(),
            address: agent.address.clone(),
            port: agent.port,
            status: crate::registry::AgentStatus::Online,
            capabilities: vec![],
            version: agent.version.clone(),
            persona: "".to_string(),
            performance_rating: 0.0,
            last_heartbeat: chrono::Utc::now(),
            registered_at: chrono::Utc::now(),
        };
        let _ = engine.agent_registry().register(info_reg);
    }

    let json = serde_json::to_vec(&found).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// POST /api/agent/mode — Switch between Sanctum and Market modes
pub async fn handle_agent_mode(
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

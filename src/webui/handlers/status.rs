use crate::error::AgentError;
use crate::webui::handlers::config::resolve_chain_balance;
use crate::webui::http::send_response;
use crate::AgentEngine;
use tokio::net::TcpStream;

/// GET /health, /api/health — Lightweight health check for Docker/load balancers
pub async fn handle_health(
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
pub async fn handle_status(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let (provider, ai_available, ai_local) = {
        let ai = engine
            .ai_manager()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        (
            ai.provider_name().to_string(),
            ai.is_available(),
            ai.is_local(),
        )
    };
    let sys = engine.get_system_info();
    let caps = engine.get_capabilities();
    let active_mission = {
        let ai = engine
            .ai_manager()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ai.active_mission().map(|m| {
            serde_json::json!({
                "id": m.id,
                "name": m.name,
                "description": m.description,
                "status": format!("{:?}", m.status),
                "progress": m.progress,
                "category": m.category,
                "tags": m.tags,
                "created_at": m.created_at,
                "started_at": m.started_at,
                "completed_at": m.completed_at,
            })
        })
    };

    let balance = resolve_chain_balance(engine);
    let balances = if let Some(b) = balance {
        serde_json::json!([{
            "symbol": b.symbol,
            "amount": b.amount.to_string(),
            "decimals": b.decimals,
            "value": (b.amount as f64) / 10f64.powi(b.decimals as i32)
        }])
    } else {
        serde_json::json!([{
            "symbol": "SUI",
            "amount": "0",
            "decimals": 9,
            "value": 0.0
        }])
    };

    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "provider": provider,
        "ai_available": ai_available,
        "ai_local": ai_local,
        "port": engine.config().agent.listen_port,
        "capabilities": caps.len(),
        "cpu_usage": sys.cpu_usage,
        "memory_percent": sys.memory_usage_percent,
        "hostname": sys.hostname,
        "uptime_secs": engine.uptime_secs(),
        "active_agents": engine.agent_registry().list_all().len(),
        "log_count": engine.activity_manager().count(),
        "active_mission": active_mission,
        "balances": balances,
        "marketStatVol": "0.0",
        "marketStatPrice": "0.0",
        "marketStatChange": "0.0%",
    });

    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/infra/summary, /api/v1/infra/summary
pub async fn handle_infra_summary(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let sys = engine.get_system_info();
    let json = serde_json::json!({
        "cpu_pct": sys.cpu_usage,
        "ram_pct": sys.memory_usage_percent,
        "containers": 0, // Mock container count (TODO: connect to docker engine)
        "uptime_sec": engine.uptime_secs(),
        "updated_at": chrono::Utc::now()
    });
    let body = serde_json::to_vec(&json).unwrap_or_default();
    send_response(stream, 200, "application/json", &body, cors_origin).await
}

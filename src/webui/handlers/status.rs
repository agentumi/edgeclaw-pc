use crate::error::AgentError;
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
        "marketStatVol": "12.4B",
        "marketStatPrice": "68,420",
        "marketStatChange": "+4.2%",
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
        "containers": 12, // Mock container count
        "uptime_sec": engine.uptime_secs(),
        "updated_at": chrono::Utc::now()
    });
    let body = serde_json::to_vec(&json).unwrap_or_default();
    send_response(stream, 200, "application/json", &body, cors_origin).await
}

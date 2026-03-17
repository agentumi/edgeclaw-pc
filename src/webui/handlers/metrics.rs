use crate::error::AgentError;
use crate::metrics::MetricsRegistry;
use crate::webui::http::{parse_query_param, send_response};
use crate::AgentEngine;
use tokio::net::TcpStream;

/// GET /api/audit/entries — List tamper-evident audit logs.
pub async fn handle_audit_entries(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    raw_request: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
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
pub async fn handle_audit_verify(
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

/// GET /metrics — Prometheus text exposition format.
pub async fn handle_metrics_prometheus(
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
pub async fn handle_metrics_history(
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

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
    let raw_path = full_uri.split('?').next().unwrap_or(full_uri);
    
    // V2.4 Legacy Route Redirector 🏮
    let path_owned: String;
    let path = if raw_path.starts_with("/api/v2.3/") {
        path_owned = raw_path.replace("/api/v2.3/", "/api/");
        println!("[V2.4] Internal redirect: {} -> {}", raw_path, path_owned);
        &path_owned
    } else {
        raw_path
    };

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
        ("GET", "/js/dashboard/loader.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_LOADER_JS.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/js/dashboard/v2.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_V2_JS.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/js/dashboard/extensions.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_EXTENSIONS_JS.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/js/dashboard/templates.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_TEMPLATES_JS.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/js/dashboard/tasks.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_TASKS_JS.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/js/dashboard/marketplace.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_MARKETPLACE_JS.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/js/dashboard/agent-board.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_AGENT_BOARD_JS.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/js/dashboard/memory.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_MEMORY_JS.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/js/dashboard/mission.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_MISSION_JS.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/js/dashboard/settings.js") => {
            return send_response(
                stream,
                200,
                "application/javascript",
                DASHBOARD_SETTINGS_JS.as_bytes(),
                cors_origin,
            )
            .await
        }

        // View Partials
        ("GET", "/views/dashboard.html") => {
            return send_response(
                stream,
                200,
                "text/html",
                VIEW_DASHBOARD_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/views/aichat.html") => {
            return send_response(
                stream,
                200,
                "text/html",
                VIEW_AICHAT_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/views/chat.html") => {
            return send_response(
                stream,
                200,
                "text/html",
                VIEW_CHAT_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/views/fleet.html") => {
            return send_response(
                stream,
                200,
                "text/html",
                VIEW_FLEET_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/views/board.html") => {
            return send_response(
                stream,
                200,
                "text/html",
                VIEW_BOARD_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/views/memory.html") => {
            return send_response(
                stream,
                200,
                "text/html",
                VIEW_MEMORY_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/views/market.html") => {
            return send_response(
                stream,
                200,
                "text/html",
                VIEW_MARKET_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/views/automations.html") => {
            return send_response(
                stream,
                200,
                "text/html",
                VIEW_AUTOMATIONS_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/views/extensions.html") => {
            return send_response(
                stream,
                200,
                "text/html",
                VIEW_EXTENSIONS_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/views/settings.html") => {
            return send_response(
                stream,
                200,
                "text/html",
                VIEW_SETTINGS_HTML.as_bytes(),
                cors_origin,
            )
            .await
        }
        ("GET", "/views/modals.html") => {
            return send_response(
                stream,
                200,
                "text/html",
                VIEW_MODALS_HTML.as_bytes(),
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
        ("GET", "/api/fleet/status") => {
            handlers::fleet::handle_fleet_status(stream, engine, cors_origin).await
        }
        ("GET", "/api/groups") => {
            handlers::groups::handle_groups_list(stream, engine, cors_origin).await
        }
        ("POST", "/api/groups") => {
            let body = extract_body(&request_full);
            handlers::groups::handle_group_create(stream, engine, &body, cors_origin).await
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
        ("GET", "/api/chat/models") => {
            handlers::chat::handle_chat_models(stream, engine, cors_origin).await
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
        ("GET", "/api/memory/knowledge") => {
            let gid = full_uri.split('?').next().and_then(|u| u.split('=').nth(1));
            handlers::memory::handle_memory_knowledge_list(stream, engine, gid, cors_origin).await
        }
        ("POST", "/api/memory/knowledge") => {
            let body = extract_body(&request_full);
            handlers::memory::handle_memory_knowledge_add(stream, engine, &body, cors_origin).await
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
        ("GET", "/api/extensions") => {
            handlers::extensions::handle_extensions_list(stream, cors_origin).await
        }
        ("POST", "/api/extensions") => {
            let body = extract_body(&request_full);
            handlers::extensions::handle_extension_create(stream, engine, &body, cors_origin).await
        }
        ("GET", "/api/extensions/readiness") => {
            handlers::extensions::handle_extensions_readiness(stream, engine, cors_origin).await
        }
        ("GET", "/api/v1/mission/active") => {
            handlers::tasks::handle_mission_active(stream, engine, cors_origin).await
        }
        ("POST", "/api/mission/confirm") => {
            let body = extract_body(&request_full);
            handlers::tasks::handle_mission_confirm(stream, engine, &body, cors_origin).await
        }

        ("POST", "/api/automations") => {
            let body = extract_body(&request_full);
            handlers::templates::handle_automation_create(stream, engine, &body, cors_origin).await
        }

        // V3: Process Type Selection API
        ("POST", "/api/v3/process-type") => {
            let body = extract_body(&request_full);
            let pt_str = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(|s| s.to_lowercase()))
                .unwrap_or_else(|| "fleet".to_string());
            let pt = match pt_str.as_str() {
                "quantum" => crate::ai::ProcessType::Quantum,
                "auto" => crate::ai::ProcessType::Auto,
                _ => crate::ai::ProcessType::Fleet,
            };
            engine.set_process_type(pt.clone());
            let resp = serde_json::json!({
                "ok": true,
                "process_type": format!("{:?}", pt),
                "message": format!("[V3] Process type switched to {:?}", pt)
            });
            let json = serde_json::to_vec(&resp).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        ("GET", "/api/v3/process-type") => {
            let pt = engine.process_type();
            let resp = serde_json::json!({
                "process_type": format!("{:?}", pt),
                "is_fleet": pt == crate::ai::ProcessType::Fleet,
                "is_quantum": pt == crate::ai::ProcessType::Quantum,
            });
            let json = serde_json::to_vec(&resp).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        ("GET", "/api/v3/quantum/stats") => {
            let stats = engine.quantum_hub_stats();
            let resp = serde_json::json!({
                "e_max_patterns": stats.e_max_count,
                "c_max_patterns": stats.c_max_count,
                "failure_insights": stats.failure_insights_count,
                "active_missions": stats.active_missions,
                "total_cycles": stats.total_cycles,
            });
            let json = serde_json::to_vec(&resp).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        // V3: Quantum Pattern Vault — full pattern + insights listing (P7-11)
        ("GET", "/api/v3/quantum/patterns") => {
            let json = {
                let qe = engine.quantum_engine.lock().unwrap_or_else(|e| e.into_inner());
                let resp = serde_json::json!({
                    "e_max": qe.hub.e_max_patterns.iter().map(|p| serde_json::json!({
                        "id": p.id, "name": p.name, "domain": p.domain,
                        "success_rate": p.avg_success_rate, "applications": p.application_count,
                    })).collect::<Vec<_>>(),
                    "c_max": qe.hub.c_max_patterns.iter().map(|p| serde_json::json!({
                        "id": p.id, "name": p.name, "domain": p.domain,
                        "success_rate": p.avg_success_rate, "applications": p.application_count,
                    })).collect::<Vec<_>>(),
                    "insights": qe.hub.failure_insights.iter().rev().take(20).map(|i| serde_json::json!({
                        "id": i.id, "failure": i.original_failure, "insight": i.extracted_insight,
                        "value": i.potential_business_value, "viral_score": i.viral_score,
                        "diffusions": i.diffusion_count, "created_at": i.created_at,
                    })).collect::<Vec<_>>(),
                });
                serde_json::to_vec(&resp).unwrap_or_default()
            }; // MutexGuard dropped here
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }

        // ─── V2 Collective Intelligence API ─────────────────────────

        ("POST", "/api/v2/orchestrate") => {
            let body = extract_body(&request_full);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let mission_desc = parsed.get("mission").and_then(|v| v.as_str()).unwrap_or("");
            let force_type = parsed.get("process_type").and_then(|v| v.as_str()).unwrap_or("Auto");

            if mission_desc.is_empty() {
                let resp = serde_json::json!({"error": "mission field is required"});
                let json = serde_json::to_vec(&resp).unwrap_or_default();
                return send_response(stream, 400, "application/json", &json, cors_origin).await;
            }

            // Detect domain and suggest experts
            let domain = crate::ai::DomainDetector::detect_domain(mission_desc);
            let expert_roles = crate::ai::DomainDetector::get_expert_roles(domain);
            let role_labels: Vec<String> = expert_roles.iter().map(|r| r.label().to_string()).collect();

            // Build planning prompt
            let peer_count = {
                let pm = engine.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
                pm.list_peers().len().max(1)
            };
            let planning_prompt = crate::ai::FleetMissionPlanner::build_mission_planning_prompt(
                mission_desc, domain, peer_count
            );

            // Execute via AI manager
            let planning_request = crate::ai::AiRequest {
                user_input: planning_prompt,
                available_capabilities: engine.get_capabilities(),
                peer_role: "owner".to_string(),
                system_context: Some("CRITICAL: Respond ONLY with valid JSON.".to_string()),
                history: Vec::new(),
                model: None,
                attachments: Vec::new(),
                parallel: force_type != "Single",
                strategies: vec!["orchestration".to_string()],
                preferred_language: Some(engine.config.agent.language.clone()),
            };

            let result = {
                let mgr = engine.ai_manager.lock().unwrap_or_else(|e| e.into_inner());
                mgr.process(&planning_request)
            };

            match result {
                Ok(resp) => {
                    let quality = if let Some(ref intent) = resp.intent {
                        if let Some(ref mission) = intent.mission {
                            crate::ai::MissionQualityEvaluator::evaluate(mission)
                        } else { 0.0 }
                    } else { 0.0 };

                    let orchestr_resp = serde_json::json!({
                        "ok": true,
                        "domain": domain,
                        "experts": role_labels,
                        "process_type": force_type,
                        "confidence": resp.confidence,
                        "quality_score": quality,
                        "mission": resp.intent.as_ref().and_then(|i| i.mission.as_ref()),
                        "message": resp.message,
                        "sub_responses_count": resp.sub_responses.len(),
                    });
                    let json = serde_json::to_vec(&orchestr_resp).unwrap_or_default();
                    send_response(stream, 200, "application/json", &json, cors_origin).await
                }
                Err(e) => {
                    let resp = serde_json::json!({"error": format!("{}", e)});
                    let json = serde_json::to_vec(&resp).unwrap_or_default();
                    send_response(stream, 500, "application/json", &json, cors_origin).await
                }
            }
        }

        ("POST", "/api/v2/review") => {
            let body = extract_body(&request_full);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let mission_id = parsed.get("mission_id").and_then(|v| v.as_str()).unwrap_or("");
            let result_text = parsed.get("result").and_then(|v| v.as_str()).unwrap_or("");

            // Quality evaluation via MissionQualityEvaluator
            let hallucination_score = crate::ai::MissionQualityEvaluator::detect_hallucination(result_text);
            let word_count = result_text.split_whitespace().count();
            let has_structure = result_text.contains('#') || result_text.contains("```") || result_text.contains("- ");

            let review_score = if hallucination_score > 0.7 {
                0.2 // High hallucination → low quality
            } else if word_count < 20 {
                0.3 // Too short
            } else if has_structure && word_count > 50 {
                0.9 // Well-structured and substantial
            } else {
                0.6 // Average
            };

            let resp = serde_json::json!({
                "ok": true,
                "mission_id": mission_id,
                "review_score": review_score,
                "hallucination_score": hallucination_score,
                "word_count": word_count,
                "has_structure": has_structure,
                "verdict": if review_score >= 0.7 { "APPROVED" } else if review_score >= 0.4 { "NEEDS_REVISION" } else { "REJECTED" },
            });
            let json = serde_json::to_vec(&resp).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }

        ("POST", "/api/v3/quantum/pattern") => {
            let body = extract_body(&request_full);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let name = parsed.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed");
            let domain = parsed.get("domain").and_then(|v| v.as_str()).unwrap_or("general");
            let success_rate = parsed.get("success_rate").and_then(|v| v.as_f64()).unwrap_or(0.5);
            let pattern_type = match parsed.get("type").and_then(|v| v.as_str()).unwrap_or("emax") {
                "cmax" | "CMax" => crate::quantum_engine::PatternType::CMax,
                _ => crate::quantum_engine::PatternType::EMax,
            };

            let pattern_id = {
                let mut qe = engine.quantum_engine.lock().unwrap_or_else(|e| e.into_inner());
                qe.hub.register_pattern(name, domain, success_rate, pattern_type)
            };

            let resp = serde_json::json!({
                "ok": true,
                "pattern_id": pattern_id,
                "message": format!("Pattern '{}' registered in Quantum Memory Hub", name),
            });
            let json = serde_json::to_vec(&resp).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
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
            } else if path.starts_with("/api/agents/") && method == "POST" {
                let agent_id = path.strip_prefix("/api/agents/").unwrap_or("");
                let body = extract_body(&request_full);
                handlers::registry::handle_update_agent(stream, engine, agent_id, &body, cors_origin).await
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
            } else if path.starts_with("/api/groups/")
                && path.ends_with("/members")
                && method == "POST"
            {
                let group_id = path
                    .strip_prefix("/api/groups/")
                    .and_then(|s| s.strip_suffix("/members"))
                    .unwrap_or("");
                let body = extract_body(&request_full);
                handlers::groups::handle_group_add_member(
                    stream,
                    engine,
                    group_id,
                    &body,
                    cors_origin,
                )
                .await
            } else if path.starts_with("/api/groups/")
                && path.ends_with("/members")
                && method == "GET"
            {
                let group_id = path
                    .strip_prefix("/api/groups/")
                    .and_then(|s| s.strip_suffix("/members"))
                    .unwrap_or("");
                handlers::groups::handle_group_members_list(stream, engine, group_id, cors_origin)
                    .await
            } else if path.starts_with("/api/groups/")
                && path.ends_with("/policy")
                && method == "POST"
            {
                let group_id = path
                    .strip_prefix("/api/groups/")
                    .and_then(|s| s.strip_suffix("/policy"))
                    .unwrap_or("");
                let body = extract_body(&request_full);
                handlers::groups::handle_group_set_policy(
                    stream,
                    engine,
                    group_id,
                    &body,
                    cors_origin,
                )
                .await
            } else if path.starts_with("/api/groups/")
                && path.ends_with("/memory/sync")
                && method == "POST"
            {
                let group_id = path
                    .strip_prefix("/api/groups/")
                    .and_then(|s| s.strip_suffix("/memory/sync"))
                    .unwrap_or("");
                let body = extract_body(&request_full);
                handlers::groups::handle_group_toggle_memory(
                    stream,
                    engine,
                    group_id,
                    &body,
                    cors_origin,
                )
                .await
            } else {
                // V2.4 Silence diagnostic requests (Chrome DevTools, Favicon, etc.) 🤫
                if path.ends_with("com.chrome.devtools.json") || path.contains(".well-known") || path.ends_with("favicon.ico") {
                   return send_response(stream, 404, "application/json", b"{}", cors_origin).await;
                }

                println!("[V2.4][404] Route not found: {} {}", method, path);
                tracing::warn!(%method, %path, "Route not found");
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

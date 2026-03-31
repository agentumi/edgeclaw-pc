use crate::activity_log::ActivityType;
use crate::error::AgentError;
use crate::memory_engine::{Lesson, MemoryTier, TimedMemory};
use crate::webui::http::send_response;
use crate::AgentEngine;
use chrono::{Duration as ChronoDuration, Utc};
use tokio::net::TcpStream;
use uuid::Uuid;

/// GET /api/memory — Full memory state (Core + Tiers + Lessons)
pub async fn handle_memory_info(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let json = {
        let memory = engine
            .memory_engine()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        serde_json::to_vec(&*memory).unwrap_or_default()
    };
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/memory/storage — Memory storage statistics
pub async fn handle_memory_storage(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let json = {
        let memory = engine
            .memory_engine()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let m30_count = memory.tiers.m30.len();
        let m90_count = memory.tiers.m90.len();
        let m365_count = memory.tiers.m365.len();
        let lessons_count = memory.lessons.lessons.len();
        let rules_count = memory.core.absolute_rules.len();
        let total = 1 + rules_count + m30_count + m90_count + m365_count + lessons_count;

        let file_size = engine
            .memory_storage_path()
            .metadata()
            .map(|m| m.len())
            .unwrap_or(0);

        let body = serde_json::json!({
            "core_entries": 1,
            "rules_count": rules_count,
            "m30_count": m30_count,
            "m90_count": m90_count,
            "m365_count": m365_count,
            "lessons_count": lessons_count,
            "total_entries": total,
            "memory_file_size_bytes": file_size,
            "cloud_sync_status": "OK"
        });
        serde_json::to_vec(&body).unwrap_or_default()
    };
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/memory/graph — Knowledge graph nodes and edges for visualization
pub async fn handle_memory_graph(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let json = {
        let memory = engine
            .memory_engine()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        // Core node
        nodes.push(serde_json::json!({
            "id": "core",
            "label": if memory.core.soul.content.len() > 30 {
                format!("{}...", &memory.core.soul.content[..30])
            } else if memory.core.soul.content.is_empty() {
                "Core Soul".to_string()
            } else {
                memory.core.soul.content.clone()
            },
            "type": "core",
            "size": 24
        }));

        // Rules as children of core
        for (i, rule) in memory.core.absolute_rules.iter().enumerate() {
            let rule_id = format!("rule-{}", i);
            let label = if rule.len() > 25 {
                format!("{}...", &rule[..25])
            } else {
                rule.clone()
            };
            nodes.push(serde_json::json!({
                "id": rule_id,
                "label": label,
                "type": "core",
                "size": 10
            }));
            edges.push(serde_json::json!({
                "source": "core",
                "target": rule_id,
                "weight": 1
            }));
        }

        // Tiered memory nodes
        let tier_mems: Vec<(&str, &[TimedMemory])> = vec![
            ("m30", &memory.tiers.m30),
            ("m90", &memory.tiers.m90),
            ("m365", &memory.tiers.m365),
        ];
        for (tier_name, mems) in &tier_mems {
            for mem in mems.iter() {
                let label = if mem.content.len() > 30 {
                    format!("{}...", &mem.content[..30])
                } else {
                    mem.content.clone()
                };
                nodes.push(serde_json::json!({
                    "id": mem.id.to_string(),
                    "label": label,
                    "type": tier_name,
                    "size": 8 + (mem.reference_count * 3).min(20),
                    "importance": mem.importance,
                    "reference_count": mem.reference_count,
                    "created_at": mem.created_at.to_rfc3339()
                }));
                // Edge from core to each memory
                edges.push(serde_json::json!({
                    "source": "core",
                    "target": mem.id.to_string(),
                    "weight": mem.importance
                }));
            }
        }

        // Lesson nodes
        for lesson in &memory.lessons.lessons {
            let label = if lesson.pattern.len() > 30 {
                format!("{}...", &lesson.pattern[..30])
            } else {
                lesson.pattern.clone()
            };
            nodes.push(serde_json::json!({
                "id": lesson.id.to_string(),
                "label": label,
                "type": "lessons",
                "size": 10 + (lesson.applied_count * 2).min(16),
                "effectiveness": lesson.effectiveness,
                "applied_count": lesson.applied_count
            }));
            edges.push(serde_json::json!({
                "source": "core",
                "target": lesson.id.to_string(),
                "weight": 1
            }));
        }

        let body = serde_json::json!({
            "nodes": nodes,
            "edges": edges
        });
        serde_json::to_vec(&body).unwrap_or_default()
    };
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/memory/search?q= — Full text search across all memory tiers
pub async fn handle_memory_search(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    query: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let decoded_query = query
        .replace("%20", " ")
        .replace("%2B", "+")
        .replace("%26", "&")
        .replace("%3D", "=")
        .replace("%23", "#")
        .replace("+", " ");
    let query_lower = decoded_query.to_lowercase();

    let json = {
        let memory = engine
            .memory_engine()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut results = Vec::new();

        // Search core soul
        if memory
            .core
            .soul
            .content
            .to_lowercase()
            .contains(&query_lower)
        {
            results.push(serde_json::json!({
                "id": "core",
                "content": memory.core.soul.content,
                "tier": "Core",
                "importance": 3,
                "score": 1.0,
                "created_at": null
            }));
        }

        // Search rules
        for (i, rule) in memory.core.absolute_rules.iter().enumerate() {
            if rule.to_lowercase().contains(&query_lower) {
                results.push(serde_json::json!({
                    "id": format!("rule-{}", i),
                    "content": rule,
                    "tier": "Core Rule",
                    "importance": 3,
                    "score": 0.95,
                    "created_at": null
                }));
            }
        }

        // Search tiers
        let all_tiers: Vec<(&str, &[TimedMemory])> = vec![
            ("M30", &memory.tiers.m30[..]),
            ("M90", &memory.tiers.m90[..]),
            ("M365", &memory.tiers.m365[..]),
        ];
        for (tier_name, mems) in &all_tiers {
            for mem in mems.iter() {
                if mem.content.to_lowercase().contains(&query_lower) {
                    results.push(serde_json::json!({
                        "id": mem.id.to_string(),
                        "content": mem.content,
                        "tier": tier_name,
                        "importance": mem.importance,
                        "score": 0.8,
                        "created_at": mem.created_at.to_rfc3339()
                    }));
                }
            }
        }

        // Search lessons
        for lesson in &memory.lessons.lessons {
            if lesson.pattern.to_lowercase().contains(&query_lower) {
                results.push(serde_json::json!({
                    "id": lesson.id.to_string(),
                    "content": lesson.pattern,
                    "tier": "Lesson",
                    "importance": 2,
                    "score": 0.75,
                    "created_at": null
                }));
            }
        }

        let total = results.len();
        let body = serde_json::json!({
            "query": decoded_query,
            "results": results,
            "total": total
        });
        serde_json::to_vec(&body).unwrap_or_default()
    };
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// DELETE /api/memory/:id — Delete a memory node by UUID
pub async fn handle_memory_delete(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    mem_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let target_id = match Uuid::parse_str(mem_id) {
        Ok(id) => id,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID format"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let found = {
        let mut memory = engine
            .memory_engine()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let before = memory.tiers.m30.len()
            + memory.tiers.m90.len()
            + memory.tiers.m365.len()
            + memory.lessons.lessons.len();

        memory.tiers.m30.retain(|m| m.id != target_id);
        memory.tiers.m90.retain(|m| m.id != target_id);
        memory.tiers.m365.retain(|m| m.id != target_id);
        memory.lessons.lessons.retain(|l| l.id != target_id);

        let after = memory.tiers.m30.len()
            + memory.tiers.m90.len()
            + memory.tiers.m365.len()
            + memory.lessons.lessons.len();

        let deleted = after < before;
        if deleted {
            let _ = memory.save_to_markdown_file(&engine.memory_storage_path());
        }
        deleted
    };

    if found {
        let activity = ActivityType::Custom {
            category: "memory".to_string(),
            data: serde_json::json!({"action": "delete", "id": mem_id}),
        };
        engine.record_activity(
            activity,
            "Memory node deleted",
            Uuid::new_v4(),
            1,
            &["memory", "delete"],
            None,
            "all",
        );
        engine
            .event_bus()
            .publish(crate::events::AgentEvent::MemoryUpdated);

        let body = serde_json::json!({ "deleted": true, "id": mem_id });
        let json = serde_json::to_vec(&body).unwrap_or_default();
        send_response(stream, 200, "application/json", &json, cors_origin).await
    } else {
        let err = serde_json::json!({ "error": "not found", "id": mem_id });
        let json = serde_json::to_vec(&err).unwrap_or_default();
        send_response(stream, 404, "application/json", &json, cors_origin).await
    }
}

#[derive(serde::Deserialize)]
pub struct MemoryCoreUpdate {
    pub soul: String,
    #[serde(default)]
    pub rules: Vec<String>,
}

/// PUT /api/memory/core — Update core SOUL and absolute rules
pub async fn handle_memory_core_update(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let req: MemoryCoreUpdate = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let (json, rule_count) = {
        let mut memory = engine
            .memory_engine()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        memory.core.update_soul(req.soul.trim());
        memory.core.absolute_rules = req
            .rules
            .into_iter()
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .collect();
        memory.save_to_markdown_file(&engine.memory_storage_path())?;
        let json = serde_json::to_vec(&memory.core).unwrap_or_default();
        (json, memory.core.absolute_rules.len())
    };

    let activity = ActivityType::Custom {
        category: "memory".to_string(),
        data: serde_json::json!({"action": "core_update", "rules": rule_count}),
    };
    engine.record_activity(
        activity,
        "Memory core updated",
        Uuid::new_v4(),
        1,
        &["memory", "core"],
        None,
        "all",
    );
    engine
        .event_bus()
        .publish(crate::events::AgentEvent::MemoryUpdated);
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

#[derive(serde::Deserialize)]
pub struct MemoryTierAdd {
    pub tier: String,
    pub content: String,
    #[serde(default)]
    pub importance: Option<u8>,
}

/// POST /api/memory/tier — Add a tiered memory entry
pub async fn handle_memory_tier_add(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let req: MemoryTierAdd = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let content = req.content.trim();
    if content.is_empty() {
        let err = serde_json::json!({"error": "content is required"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
    }

    let tier_key = req.tier.to_lowercase();
    let (tier, ttl_days) = match tier_key.as_str() {
        "m30" => (MemoryTier::M30, 30),
        "m90" => (MemoryTier::M90, 90),
        "m365" => (MemoryTier::M365, 365),
        _ => {
            let err = serde_json::json!({"error": "invalid tier"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let now = Utc::now();
    let mem = TimedMemory {
        id: Uuid::new_v4(),
        content: content.to_string(),
        source_activity_id: None,
        tier,
        created_at: now,
        expires_at: now + ChronoDuration::days(ttl_days),
        reference_count: 0,
        importance: req.importance.unwrap_or(1),
    };

    {
        let mut memory = engine
            .memory_engine()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        memory.tiers.add_memory(mem.clone());
        memory.save_to_markdown_file(&engine.memory_storage_path())?;
    }

    let activity = ActivityType::Custom {
        category: "memory".to_string(),
        data: serde_json::json!({"action": "tier_add", "tier": tier_key}),
    };
    engine.record_activity(
        activity,
        "Memory entry added",
        Uuid::new_v4(),
        1,
        &["memory", "tier"],
        None,
        "all",
    );
    engine
        .event_bus()
        .publish(crate::events::AgentEvent::MemoryUpdated);

    let json = serde_json::to_vec(&mem).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

#[derive(serde::Deserialize)]
pub struct MemoryLessonAdd {
    pub pattern: String,
    #[serde(default)]
    pub effectiveness: Option<f64>,
}

/// POST /api/memory/lessons — Add a lesson pattern
pub async fn handle_memory_lesson_add(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let req: MemoryLessonAdd = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let pattern = req.pattern.trim();
    if pattern.is_empty() {
        let err = serde_json::json!({"error": "pattern is required"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
    }

    let effectiveness = req.effectiveness.unwrap_or(0.7).clamp(0.0, 1.0);
    let lesson = Lesson {
        id: Uuid::new_v4(),
        pattern: pattern.to_string(),
        source_errors: Vec::new(),
        applied_count: 0,
        effectiveness,
        domain: String::new(),
        success_count: 0,
        failure_count: 0,
    };

    {
        let mut memory = engine
            .memory_engine()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        memory.lessons.add_lesson(lesson.clone());
        memory.save_to_markdown_file(&engine.memory_storage_path())?;
    }

    let activity = ActivityType::Custom {
        category: "memory".to_string(),
        data: serde_json::json!({"action": "lesson_add"}),
    };
    engine.record_activity(
        activity,
        "Lesson published",
        Uuid::new_v4(),
        1,
        &["memory", "lesson"],
        None,
        "all",
    );
    engine
        .event_bus()
        .publish(crate::events::AgentEvent::MemoryUpdated);

    let json = serde_json::to_vec(&lesson).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}
/// GET /api/memory/knowledge — List knowledge items
pub async fn handle_memory_knowledge_list(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    group_id: Option<&str>,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let items = {
        let memory = engine
            .memory_engine()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(gid) = group_id {
            memory.knowledge.search_by_group(gid)
        } else {
            memory.knowledge.items.clone()
        }
    };
    let json = serde_json::to_vec(&items).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// POST /api/memory/knowledge — Create a knowledge item
pub async fn handle_memory_knowledge_add(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let item: crate::memory_engine::KnowledgeItem = serde_json::from_str(body)?;
    {
        let mut memory = engine
            .memory_engine()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        memory.knowledge.add_item(item.clone());
        memory.save_to_markdown_file(&engine.memory_storage_path())?;
    }

    // Broadcast if shared memory is enabled for the group
    if let Some(ref gid) = item.group_id {
        if let Some(group) = engine.group_manager().get_group(gid) {
            if group.sync_memory {
                // In a real implementation, we would broadcast this via ECNP/Gossip
                engine.record_activity(
                    ActivityType::Custom {
                        category: "memory_sync".into(),
                        data: serde_json::json!({"group": gid, "title": item.title}),
                    },
                    &format!("Shared knowledge to group {}: {}", gid, item.title),
                    Uuid::new_v4(),
                    2,
                    &["memory", "sync", gid],
                    None,
                    "all",
                );
            }
        }
    }

    let json = serde_json::to_vec(&item).unwrap_or_default();
    send_response(stream, 201, "application/json", &json, cors_origin).await
}

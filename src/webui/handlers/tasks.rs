use crate::error::AgentError;
use crate::webui::http::{parse_query_param, send_response};
use crate::AgentEngine;
use tokio::net::TcpStream;
use uuid::Uuid;

pub fn parse_task_status(status: &str) -> crate::task_board::TaskStatus {
    match status.to_lowercase().as_str() {
        "in_progress" | "inprogress" | "progress" => crate::task_board::TaskStatus::InProgress,
        "review" => crate::task_board::TaskStatus::Review,
        "done" => crate::task_board::TaskStatus::Done,
        "archived" => crate::task_board::TaskStatus::Archived,
        _ => crate::task_board::TaskStatus::Backlog,
    }
}

/// GET /api/tasks — List all tasks.
pub async fn handle_tasks_list(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    raw_request: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let status_filter = parse_query_param(raw_request, "status").map(parse_task_status);
    let assignee_filter = parse_query_param(raw_request, "assignee")
        .and_then(|v| (!v.trim().is_empty()).then_some(v));

    let tasks = engine.list_tasks_filtered(status_filter.as_ref(), assignee_filter);
    let json = serde_json::to_vec(&tasks).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// POST /api/tasks — Create a new task.
pub async fn handle_task_create(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    #[derive(serde::Deserialize)]
    struct CreateReq {
        title: String,
        description: Option<String>,
        priority: String,
        assignee: Option<String>,
        tags: Vec<String>,
    }

    let req: CreateReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    if req.title.trim().is_empty() {
        let err = serde_json::json!({"error": "title is required"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
    }

    let priority = match req.priority.to_lowercase().as_str() {
        "critical" => crate::task_board::TaskPriority::Critical,
        "high" => crate::task_board::TaskPriority::High,
        "low" => crate::task_board::TaskPriority::Low,
        _ => crate::task_board::TaskPriority::Medium,
    };

    let tag_refs: Vec<&str> = req.tags.iter().map(|s| s.as_str()).collect();
    let mut task = engine.create_task(&req.title, req.description.as_deref(), priority, &tag_refs);

    if let Some(assignee) = req
        .assignee
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Ok(updated) = engine.assign_task(task.id, assignee) {
            task = updated;
        }
    }

    let json = serde_json::to_vec(&task).unwrap_or_default();
    send_response(stream, 201, "application/json", &json, cors_origin).await
}

/// POST /api/tasks/:id/move — Move task to new status.
pub async fn handle_task_move(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    task_id: &str,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match Uuid::parse_str(task_id) {
        Ok(u) => u,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    #[derive(serde::Deserialize)]
    struct MoveReq {
        status: String,
    }

    let req: MoveReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let new_status = parse_task_status(&req.status);
    match engine.move_task(uuid, new_status) {
        Ok(updated) => {
            let json = serde_json::to_vec(&updated).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        Err(e) => {
            let err = serde_json::json!({"error": e.to_string()});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 500, "application/json", &json, cors_origin).await
        }
    }
}

/// DELETE /api/tasks/:id — Delete a task.
pub async fn handle_task_delete(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    task_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match Uuid::parse_str(task_id) {
        Ok(u) => u,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    if engine.delete_task(uuid) {
        let resp = serde_json::json!({"deleted": true, "id": task_id});
        let json = serde_json::to_vec(&resp).unwrap_or_default();
        send_response(stream, 200, "application/json", &json, cors_origin).await
    } else {
        let err = serde_json::json!({"error": "task not found"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        send_response(stream, 404, "application/json", &json, cors_origin).await
    }
}

/// GET /api/v1/mission/active — Get current active mission
pub async fn handle_mission_active(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let tasks = engine.list_tasks();
    let active_task = tasks.iter().find(|t| {
        let s = t.status.display().to_lowercase();
        s.contains("running") || s.contains("progress")
    });

    let json = if let Some(t) = active_task {
        let s = t.status.display().to_lowercase();
        // Base progress on status
        let progress: f64 = if s.contains("done") {
            100.0
        } else if s.contains("review") {
            90.0
        } else if s.contains("progress") || s.contains("running") {
            68.0
        } else {
            10.0
        };

        // If there's an assignee, use them; otherwise, default to a generated step.
        // We will build a dynamic steps list based on tags and status.
        let is_done = s.contains("done");
        let is_running = s.contains("progress") || s.contains("running") || s.contains("review");
        let step_state = if is_done {
            "Completed"
        } else if is_running {
            "Running"
        } else {
            "Pending"
        };

        let mut steps = Vec::new();
        if !t.tags.is_empty() {
            for (i, tag) in t.tags.iter().enumerate() {
                steps.push(serde_json::json!({
                    "id": format!("s_{}", i + 1),
                    "index": i + 1,
                    "name": format!("Process: {}", tag),
                    "state": step_state,
                }));
            }
        } else {
            steps.push(serde_json::json!({
                "id": "s_1",
                "index": 1,
                "name": format!("Execute: {}", t.title),
                "state": step_state,
            }));
        }

        serde_json::json!({
            "id": t.id,
            "name": t.title,
            "state": t.status.display(),
            "progress": progress,
            "eta_sec": 300,
            "current_step_id": "s_1",
            "steps": steps,
            "created_at": t.created_at,
            "updated_at": t.updated_at
        })
    } else {
        serde_json::json!({
            "id": "none",
            "name": "Idle",
            "state": "Waiting",
            "progress": 0.0,
            "steps": []
        })
    };
    let body = serde_json::to_vec(&json).unwrap_or_default();
    send_response(stream, 200, "application/json", &body, cors_origin).await
}

/// GET /api/missions — List missions (alias for active tasks)
pub async fn handle_missions_list(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let tasks = engine.list_tasks();
    let missions: Vec<serde_json::Value> = tasks
        .into_iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "name": t.title,
                "status": t.status.display(),
                "priority": t.priority.display(),
                "created_at": t.created_at,
            })
        })
        .collect();
    let body = serde_json::json!({
        "missions": missions,
        "total": missions.len()
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}
/// POST /api/tasks/:id/assign — Assign task to agent.
pub async fn handle_task_assign(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    task_id: &str,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let uuid = match Uuid::parse_str(task_id) {
        Ok(u) => u,
        Err(_) => {
            let err = serde_json::json!({"error": "invalid UUID"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    #[derive(serde::Deserialize)]
    struct AssignReq {
        assignee: String,
    }

    let req: AssignReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let assignee = req.assignee.trim();
    if assignee.is_empty() {
        let err = serde_json::json!({"error": "assignee is required"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
    }

    match engine.assign_task(uuid, assignee) {
        Ok(updated) => {
            let json = serde_json::to_vec(&updated).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        Err(e) => {
            let err = serde_json::json!({"error": e.to_string()});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 500, "application/json", &json, cors_origin).await
        }
    }
}

/// POST /api/mission/confirm — Confirm a proposed AI mission
pub async fn handle_mission_confirm(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    #[derive(serde::Deserialize)]
    struct ConfirmReq {
        mission_id: String,
    }

    let req: ConfirmReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let res: Result<crate::ai::MissionMetadata, String> = {
        let ai_mgr = match engine.ai_manager.lock() {
            Ok(a) => a,
            Err(e) => e.into_inner(),
        };
        let registry = ai_mgr.mission_registry();
        let mut missions = match registry.missions.write() {
            Ok(m) => m,
            Err(e) => e.into_inner(),
        };
        if let Some(m) = missions.get_mut(&req.mission_id) {
            m.status = crate::ai::MissionStatus::Planning; // Change to Planning to start
            Ok(m.clone())
        } else {
            let known: Vec<String> = missions.keys().cloned().collect();
            println!("[V2.4] Mission ID '{}' not in registry. Known: {:?}", req.mission_id, known);
            Err(format!("mission not found: {}. Known: {:?}", req.mission_id, known))
        }
    };

    match res {
        Ok(m) => {
            tracing::info!(mission_id = %m.id, "Mission confirmed and starting");
            let resp = serde_json::json!({"success": true, "mission": m});
            let json = serde_json::to_vec(&resp).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        Err(e) => {
            tracing::error!(id = %req.mission_id, error = %e, "Mission confirmation failed: not in registry");
            let err = serde_json::json!({"error": e});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 404, "application/json", &json, cors_origin).await
        }
    }
}

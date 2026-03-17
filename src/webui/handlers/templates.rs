use crate::error::AgentError;
use crate::webui::http::send_response;
use crate::AgentEngine;
use std::collections::HashMap;
use tokio::net::TcpStream;

/// GET /api/templates — List all templates.
pub async fn handle_templates_list(
    stream: &mut TcpStream,
    _engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    use crate::task_templates::TemplateRegistry;
    let registry = TemplateRegistry::default_library();
    let mut templates: Vec<serde_json::Value> = registry
        .list()
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "category": t.category.to_string(),
                "tags": t.tags,
                "capability": t.capability,
                "builtin": t.builtin,
                "estimated_secs": t.estimated_secs,
                "type": "sequential"
            })
        })
        .collect();

    // Add YAML-based workflow templates
    use crate::workflow_engine::TemplateRegistry as WorkflowRegistry;
    let wf_registry = WorkflowRegistry::new();
    for t in wf_registry.list(None) {
        templates.push(serde_json::json!({
            "id": t.template.id,
            "name": t.template.name,
            "description": t.template.description,
            "category": t.template.category,
            "tags": t.template.metadata.tags,
            "capability": "workflow:exec",
            "builtin": false,
            "estimated_secs": t.requirements.resources.timeout_sec,
            "type": "dag"
        }));
    }

    let body = serde_json::json!({
        "templates": templates,
        "total": templates.len()
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/templates/:id — Get template detail.
pub async fn handle_template_detail(
    stream: &mut TcpStream,
    _engine: &AgentEngine,
    template_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    use crate::task_templates::TemplateRegistry;
    let registry = TemplateRegistry::default_library();

    if let Some(t) = registry.get(template_id) {
        let body = serde_json::json!({
            "id": t.id,
            "name": t.name,
            "description": t.description,
            "category": t.category.to_string(),
            "tags": t.tags,
            "capability": t.capability,
            "required_role": t.required_role.to_string(),
            "builtin": t.builtin,
            "estimated_secs": t.estimated_secs,
            "type": "sequential",
            "steps": t.steps.iter().map(|s| {
                serde_json::json!({
                    "order": s.order,
                    "description": s.description,
                    "command": s.command,
                    "args": s.args,
                    "timeout_secs": s.timeout_secs,
                })
            }).collect::<Vec<_>>(),
        });
        let json = serde_json::to_vec(&body).unwrap_or_default();
        return send_response(stream, 200, "application/json", &json, cors_origin).await;
    }

    // Try workflow registry
    use crate::workflow_engine::TemplateRegistry as WorkflowRegistry;
    let wf_registry = WorkflowRegistry::new();
    if let Some(t) = wf_registry.get(template_id) {
        let body = serde_json::json!({
            "id": t.template.id,
            "name": t.template.name,
            "description": t.template.description,
            "category": t.template.category,
            "tags": t.template.metadata.tags,
            "capability": "workflow:exec",
            "builtin": false,
            "estimated_secs": t.requirements.resources.timeout_sec,
            "type": "dag",
            "version": t.template.version,
            "variables": t.variables,
            "workflow": t.workflow,
        });
        let json = serde_json::to_vec(&body).unwrap_or_default();
        return send_response(stream, 200, "application/json", &json, cors_origin).await;
    }

    let err = serde_json::json!({ "error": format!("template '{}' not found", template_id) });
    let json = serde_json::to_vec(&err).unwrap_or_default();
    send_response(stream, 404, "application/json", &json, cors_origin).await
}

/// POST /api/automations — Create a new automation template.
pub async fn handle_automation_create(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    #[derive(serde::Deserialize)]
    struct CreateReq {
        name: String,
        _description: String,
        template_id: String,
        #[serde(default)]
        _variables: HashMap<String, String>,
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
        category: "automation".to_string(),
        data: serde_json::json!({
            "action": "create",
            "name": req.name,
            "template": req.template_id
        }),
    };
    engine.record_activity(
        activity,
        &format!("Automation '{}' created", req.name),
        uuid::Uuid::new_v4(),
        1,
        &["automation", "create"],
        None,
        "all",
    );

    let resp = serde_json::json!({
        "status": "created",
        "id": uuid::Uuid::new_v4().to_string(),
        "name": req.name
    });
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 201, "application/json", &json, cors_origin).await
}

/// POST /api/automations/{id}/run — Trigger an automation.
pub async fn handle_automation_run(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    auto_id: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let activity = crate::activity_log::ActivityType::Custom {
        category: "automation".to_string(),
        data: serde_json::json!({"action": "run", "id": auto_id}),
    };
    engine.record_activity(
        activity,
        &format!("Automation '{}' triggered", auto_id),
        uuid::Uuid::new_v4(),
        1,
        &["automation", "run"],
        None,
        "all",
    );

    let resp = serde_json::json!({
        "status": "running",
        "automation_id": auto_id,
        "job_id": uuid::Uuid::new_v4().to_string()
    });
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 202, "application/json", &json, cors_origin).await
}

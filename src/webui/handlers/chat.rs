use crate::error::AgentError;
use crate::webui::http::send_response;
use crate::AgentEngine;
use tokio::net::TcpStream;

/// POST /api/chat — Chat with AI agent
pub async fn handle_chat(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    #[derive(serde::Deserialize)]
    struct ChatReq {
        message: String,
        model: Option<String>,
        attachments: Option<Vec<crate::ai::FileAttachment>>,
        lang: Option<String>,
    }

    let req: ChatReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    match engine.chat(
        "web-client",
        &req.message,
        req.model,
        req.attachments.unwrap_or_default(),
        req.lang,
    ) {
        Ok(response) => {
            // CRITICAL: Register proposed mission in the registry so confirm/active can find it
            if let Some(ref intent) = response.intent {
                if let Some(ref mission) = intent.mission {
                    let ai_mgr = engine.ai_manager.lock().unwrap_or_else(|e| e.into_inner());
                    ai_mgr.mission_registry().register(mission.clone());
                }
            }

            let json = serde_json::to_vec(&response).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        Err(e) => {
            println!("[ERROR] Chat interaction failed: {}", e);
            let status = if matches!(e, AgentError::ConnectionError(_)) { 503 } else { 500 };
            let err = serde_json::json!({"error": e.to_string()});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, status, "application/json", &json, cors_origin).await
        }
    }
}

/// GET /api/chat/history — Recent chat history
pub async fn handle_chat_history(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let history = engine.get_chat_history();
    let json = serde_json::to_vec(&history).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// DELETE /api/chat — Clear chat history
pub async fn handle_chat_clear(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    engine.clear_chat_history();
    let resp = serde_json::json!({"status": "cleared"});
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/chat/models — List available AI models
pub async fn handle_chat_models(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let models = engine.list_ai_models();
    let json = serde_json::to_vec(&models).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

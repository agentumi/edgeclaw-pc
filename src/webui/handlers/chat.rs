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
    ) {
        Ok(response) => {
            let json = serde_json::to_vec(&response).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        Err(e) => {
            let err = serde_json::json!({"error": e.to_string()});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 500, "application/json", &json, cors_origin).await
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


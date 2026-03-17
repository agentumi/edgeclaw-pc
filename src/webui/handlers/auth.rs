use crate::error::AgentError;
use crate::webui::http::send_response;
use crate::webui::{SessionManager, SESSION_TTL};
use tokio::net::TcpStream;
use tracing::info;

/// POST /api/login — Authenticate and get session token
pub async fn handle_login(
    stream: &mut TcpStream,
    sessions: &SessionManager,
    peer_ip: &str,
    auth_password: &str,
    auth_required: bool,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    // If no auth required, always succeed
    if !auth_required {
        let token = sessions.create_session(peer_ip).await;
        let resp = serde_json::json!({
            "token": token,
            "expires_in": SESSION_TTL.as_secs(),
            "auth_required": false,
        });
        let json = serde_json::to_vec(&resp).unwrap_or_default();
        return send_response(stream, 200, "application/json", &json, cors_origin).await;
    }

    #[derive(serde::Deserialize)]
    struct LoginReq {
        password: String,
    }

    let req: LoginReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    if req.password == auth_password {
        let token = sessions.create_session(peer_ip).await;
        info!(peer = %peer_ip, "WebUI login successful");
        let resp = serde_json::json!({
            "token": token,
            "expires_in": SESSION_TTL.as_secs(),
        });
        let json = serde_json::to_vec(&resp).unwrap_or_default();
        send_response(stream, 200, "application/json", &json, cors_origin).await
    } else {
        tracing::warn!(peer = %peer_ip, "WebUI login failed — bad password");
        let err = serde_json::json!({"error": "invalid password"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        send_response(stream, 401, "application/json", &json, cors_origin).await
    }
}

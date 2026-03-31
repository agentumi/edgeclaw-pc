use crate::error::AgentError;
use crate::webui::http::send_response;
use crate::AgentEngine;
use tokio::net::TcpStream;

/// GET /api/v3/passport — Get the current Agent Passport NFT info
pub async fn handle_passport_get(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let passport = {
        let lock = engine.agent_passport.lock().unwrap_or_else(|e| e.into_inner());
        lock.clone()
    };

    if let Some(p) = passport {
        let json = serde_json::to_vec(&p).unwrap_or_default();
        send_response(stream, 200, "application/json", &json, cors_origin).await
    } else {
        // Not initialized yet
        let res = serde_json::json!({
            "error": "passport_not_initialized",
            "message": "Passport has not been created yet."
        });
        let json = serde_json::to_vec(&res).unwrap_or_default();
        send_response(stream, 404, "application/json", &json, cors_origin).await
    }
}

/// POST /api/v3/passport — Create or update Passport NFT
pub async fn handle_passport_create(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    #[derive(serde::Deserialize)]
    struct CreateReq {
        name: String,
        platform: String,
        capabilities: Vec<String>,
        mcp_compatible: bool,
        a2a_capable: bool,
    }

    let req: CreateReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let p = crate::identity_passport::AgentPassport::new(
        engine.config().agent.device_name.clone(),
        req.name,
        req.platform,
        req.capabilities,
        req.mcp_compatible,
        req.a2a_capable,
    );

    let cloned_p = {
        let mut lock = engine.agent_passport.lock().unwrap_or_else(|e| e.into_inner());
        *lock = Some(p.clone());
        p
    };

    let json = serde_json::to_vec(&cloned_p).unwrap_or_default();
    send_response(stream, 201, "application/json", &json, cors_origin).await
}

/// POST /api/v3/delegation/route — Route a task to A2A Delegation Engine
pub async fn handle_delegation_route(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    #[derive(serde::Deserialize)]
    struct RouteReq {
        delegator_id: String,
        capability: String,
        description: String,
        escrow_amount: f64,
    }

    let req: RouteReq = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let result = {
        let mut router = engine.agent_router.lock().unwrap_or_else(|e| e.into_inner());
        router.route(&req.delegator_id, &req.capability, &req.description, req.escrow_amount)
    };

    match result {
        Ok(crate::agent_router::RoutingResult::Delegated(contract)) => {
            let res = serde_json::json!({
                "status": "delegated",
                "contract": contract
            });
            let json = serde_json::to_vec(&res).unwrap_or_default();
            send_response(stream, 200, "application/json", &json, cors_origin).await
        }
        Ok(crate::agent_router::RoutingResult::Queued(uuid)) => {
            let res = serde_json::json!({
                "status": "queued",
                "task_id": uuid
            });
            let json = serde_json::to_vec(&res).unwrap_or_default();
            send_response(stream, 202, "application/json", &json, cors_origin).await
        }
        Err(e) => {
            let res = serde_json::json!({"error": e.to_string()});
            let json = serde_json::to_vec(&res).unwrap_or_default();
            send_response(stream, 500, "application/json", &json, cors_origin).await
        }
    }
}

/// GET /api/v3/delegation/contracts — List A2A contracts
pub async fn handle_delegation_list(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    raw_request: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let delegator = crate::webui::http::parse_query_param(raw_request, "delegator")
        .unwrap_or("all");

    let contracts = {
        let mut router = engine.agent_router.lock().unwrap_or_else(|e| e.into_inner());
        if delegator == "all" {
            // We shouldn't do this easily with current API, but let's mock empty
            // To get all, we could have a method, but delegation doesn't expose it.
            vec![]
        } else {
            router.delegation_mut().list_contracts(delegator).iter().map(|c| (*c).clone()).collect::<Vec<_>>()
        }
    };

    let json = serde_json::to_vec(&contracts).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

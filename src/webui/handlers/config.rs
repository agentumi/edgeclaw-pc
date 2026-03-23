use crate::chain::{create_provider, ChainProviderConfig, ChainType, MultiChainClient};
use crate::error::AgentError;
use crate::webui::http::send_response;
use crate::AgentEngine;
use base64::Engine as _;
use std::collections::HashMap;
use tokio::net::TcpStream;

fn non_empty_opt(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub fn resolve_chain_balance(engine: &AgentEngine) -> Option<crate::chain::ChainBalance> {
    let config = engine.config();
    let identity_addr = engine
        .get_identity()
        .ok()
        .map(|id| id.public_key_hex.clone())
        .unwrap_or_else(|| config.agent.device_name.clone());
    let address = identity_addr.trim();
    if address.is_empty() {
        return None;
    }

    if config.multi_chain.enabled && !config.multi_chain.chains.is_empty() {
        let mut client = MultiChainClient::new();
        for (chain_name, chain_cfg) in &config.multi_chain.chains {
            if let Some(chain) = ChainType::from_str_loose(chain_name) {
                let rpc_url = if chain_cfg.rpc_url.trim().is_empty() {
                    chain.default_rpc_url().to_string()
                } else {
                    chain_cfg.rpc_url.clone()
                };
                let provider_cfg = ChainProviderConfig {
                    rpc_url,
                    chain_id: non_empty_opt(&chain_cfg.chain_id),
                    contract_address: non_empty_opt(&chain_cfg.contract_address),
                    wallet_key_path: non_empty_opt(&chain_cfg.wallet_key_path),
                    gas_budget: chain_cfg.gas_budget,
                    custom_options: HashMap::new(),
                };
                let _ = client.register_provider(chain, provider_cfg);
            }
        }

        if let Some(primary) = ChainType::from_str_loose(&config.multi_chain.primary_chain) {
            let _ = client.set_primary(primary);
        }

        if let Some(provider) = client.primary_provider() {
            return provider.get_balance(address).ok();
        }
        return None;
    }

    if config.blockchain.enabled {
        if let Some(chain) = ChainType::from_str_loose(&config.blockchain.chain) {
            let rpc_url = if config.blockchain.rpc_url.trim().is_empty() {
                chain.default_rpc_url().to_string()
            } else {
                config.blockchain.rpc_url.clone()
            };
            let provider_cfg = ChainProviderConfig {
                rpc_url,
                chain_id: None,
                contract_address: non_empty_opt(&config.blockchain.contract_address),
                wallet_key_path: non_empty_opt(&config.blockchain.wallet_key_path),
                gas_budget: config.blockchain.gas_budget,
                custom_options: HashMap::new(),
            };
            let provider = create_provider(chain, provider_cfg);
            return provider.get_balance(address).ok();
        }
    }

    None
}

/// GET /api/config — Get current agent configuration
pub async fn handle_config_get(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let config = engine.config();
    let json = serde_json::json!({
        "agent": config.agent,
        "security": config.security,
        "execution": config.execution,
        "ai": config.ai,
        "webui": config.webui,
        "blockchain": config.blockchain,
        "settingsApiKey": format!("{}-{}", config.ai.primary, config.ai.local.model),
    });
    let body = serde_json::to_vec(&json).unwrap_or_default();
    send_response(stream, 200, "application/json", &body, cors_origin).await
}

/// PUT /api/config — Update agent config (TOML body).
pub async fn handle_config_update(
    stream: &mut TcpStream,
    _engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    // Validate TOML syntax
    match toml::from_str::<crate::config::AgentConfig>(body) {
        Ok(new_config) => {
            let config_path = crate::config::AgentConfig::default_path();
            match new_config.save(&config_path) {
                Ok(()) => {
                    let resp = serde_json::json!({
                        "status": "saved",
                        "path": config_path.to_string_lossy(),
                        "message": "Config saved. Restart agent to apply changes."
                    });
                    let json = serde_json::to_vec(&resp).unwrap_or_default();
                    send_response(stream, 200, "application/json", &json, cors_origin).await
                }
                Err(e) => {
                    let err = serde_json::json!({"error": format!("save failed: {}", e)});
                    let json = serde_json::to_vec(&err).unwrap_or_default();
                    send_response(stream, 500, "application/json", &json, cors_origin).await
                }
            }
        }
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid TOML: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            send_response(stream, 400, "application/json", &json, cors_origin).await
        }
    }
}

#[derive(serde::Deserialize)]
pub struct IdentityConfigUpdate {
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub persona: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub messenger: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
}

/// PUT /api/config/identity — Update agent identity fields (JSON body).
pub async fn handle_config_identity_update(
    stream: &mut TcpStream,
    _engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let req: IdentityConfigUpdate = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let device_name = req.device_name.as_deref().map(str::trim).unwrap_or("");
    let display_name = req.display_name.as_deref().map(str::trim).unwrap_or("");
    if device_name.is_empty() && display_name.is_empty() {
        let err = serde_json::json!({"error": "device_name or display_name is required"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
    }

    let config_path = if cfg!(test) {
        std::env::temp_dir().join("edgeclaw_test_agent.toml")
    } else {
        crate::config::AgentConfig::default_path()
    };

    let mut config = crate::config::AgentConfig::load(&config_path)?;
    if !device_name.is_empty() {
        config.agent.device_name = device_name.to_string();
    }
    if !display_name.is_empty() {
        config.agent.display_name = display_name.to_string();
    }
    if let Some(value) = req.avatar_url.as_deref().map(str::trim) {
        config.agent.avatar_url = value.to_string();
    }
    if let Some(value) = req.persona.as_deref().map(str::trim) {
        config.agent.persona = value.to_string();
    }
    if let Some(value) = req.role.as_deref().map(str::trim) {
        config.agent.role = value.to_string();
    }
    if let Some(value) = req.email.as_deref().map(str::trim) {
        config.agent.email = value.to_string();
    }
    if let Some(value) = req.messenger.as_deref().map(str::trim) {
        config.agent.messenger = value.to_string();
    }
    if let Some(value) = req.phone.as_deref().map(str::trim) {
        config.agent.phone = value.to_string();
    }
    if let Some(value) = req.language.as_deref().map(str::trim) {
        config.agent.language = value.to_string();
    }
    config.save(&config_path)?;

    let resp = serde_json::json!({
        "status": "saved",
        "path": config_path.to_string_lossy(),
        "message": "Config saved. Restart agent to apply changes."
    });
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

#[derive(serde::Deserialize)]
pub struct AvatarUploadRequest {
    pub data_url: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub filename: Option<String>,
}

pub fn parse_data_url(data_url: &str) -> Result<(String, Vec<u8>), AgentError> {
    if !data_url.starts_with("data:") {
        return Err(AgentError::InvalidParameter(
            "data_url must be a data URL".into(),
        ));
    }
    let mut parts = data_url.splitn(2, ',');
    let meta = parts.next().unwrap_or("");
    let b64 = parts.next().unwrap_or("");
    if !meta.contains(";base64") {
        return Err(AgentError::InvalidParameter(
            "data_url must be base64".into(),
        ));
    }
    let mime = meta.trim_start_matches("data:").trim_end_matches(";base64");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| AgentError::InvalidParameter(format!("base64 decode failed: {e}")))?;
    Ok((mime.to_string(), decoded))
}

pub fn avatar_ext_for_mime(mime: &str) -> Option<&'static str> {
    match mime {
        "image/png" => Some("png"),
        "image/jpeg" => Some("jpg"),
        "image/jpg" => Some("jpg"),
        "image/webp" => Some("webp"),
        _ => None,
    }
}

/// PUT /api/config/avatar — Upload avatar image (JSON with data URL).
pub async fn handle_config_avatar_update(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let req: AvatarUploadRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let (mime, bytes) = match parse_data_url(req.data_url.trim()) {
        Ok(v) => v,
        Err(e) => {
            let err = serde_json::json!({"error": e.to_string()});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let ext = match avatar_ext_for_mime(&mime) {
        Some(ext) => ext,
        None => {
            let err = serde_json::json!({"error": "unsupported image type"});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    let max_bytes = 2 * 1024 * 1024;
    if bytes.len() > max_bytes {
        let err = serde_json::json!({"error": "image exceeds 2MB limit"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
    }

    let dir = crate::webui::handlers::agents::avatar_storage_dir(engine);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        let err = serde_json::json!({"error": format!("avatar dir create failed: {}", e)});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 500, "application/json", &json, cors_origin).await;
    }

    let filename = format!("avatar.{}", ext);
    let path = dir.join(&filename);
    if let Err(e) = std::fs::write(&path, &bytes) {
        let err = serde_json::json!({"error": format!("avatar save failed: {}", e)});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 500, "application/json", &json, cors_origin).await;
    }

    let config_path = if cfg!(test) {
        std::env::temp_dir().join("edgeclaw_test_agent.toml")
    } else {
        crate::config::AgentConfig::default_path()
    };
    let mut config = crate::config::AgentConfig::load(&config_path)?;
    config.agent.avatar_url = format!("/api/avatars/{}", filename);
    config.save(&config_path)?;

    let resp = serde_json::json!({
        "status": "saved",
        "avatar_url": format!("/api/avatars/{}", filename),
        "message": "Avatar saved. Restart agent to apply changes."
    });
    let json = serde_json::to_vec(&resp).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RentPolicy {
    #[serde(default)]
    pub base_rate: f64,
    #[serde(default)]
    pub max_active: u32,
    #[serde(default)]
    pub min_reputation: f64,
    #[serde(default)]
    pub auto_approve: bool,
}

impl Default for RentPolicy {
    fn default() -> Self {
        Self {
            base_rate: 0.0,
            max_active: 0,
            min_reputation: 0.0,
            auto_approve: false,
        }
    }
}

pub fn rent_policy_path(engine: &AgentEngine) -> std::path::PathBuf {
    if cfg!(test) {
        std::env::temp_dir().join("edgeclaw_test_rent_policies.json")
    } else {
        engine.config().storage_dir().join("rent_policies.json")
    }
}

pub fn load_rent_policy(engine: &AgentEngine) -> Result<RentPolicy, AgentError> {
    let path = rent_policy_path(engine);
    if !path.exists() {
        return Ok(RentPolicy::default());
    }
    let content = std::fs::read_to_string(path)?;
    let policy: RentPolicy = serde_json::from_str(&content)?;
    Ok(policy)
}

pub fn save_rent_policy(engine: &AgentEngine, policy: &RentPolicy) -> Result<(), AgentError> {
    let path = rent_policy_path(engine);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(policy)?;
    std::fs::write(path, content)?;
    Ok(())
}

/// GET /api/rent-policies — Fetch current rent policy.
pub async fn handle_rent_policy_get(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let policy = load_rent_policy(engine)?;
    let json = serde_json::to_vec(&policy).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

#[derive(serde::Deserialize)]
pub struct RentPolicyUpdate {
    pub base_rate: f64,
    pub max_active: u32,
    pub min_reputation: f64,
    pub auto_approve: bool,
}

/// PUT /api/rent-policies — Update rent policy.
pub async fn handle_rent_policy_update(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    body: &str,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let req: RentPolicyUpdate = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            let err = serde_json::json!({"error": format!("invalid JSON: {}", e)});
            let json = serde_json::to_vec(&err).unwrap_or_default();
            return send_response(stream, 400, "application/json", &json, cors_origin).await;
        }
    };

    if req.base_rate.is_sign_negative() || req.min_reputation.is_sign_negative() {
        let err = serde_json::json!({"error": "values must be non-negative"});
        let json = serde_json::to_vec(&err).unwrap_or_default();
        return send_response(stream, 400, "application/json", &json, cors_origin).await;
    }

    let policy = RentPolicy {
        base_rate: req.base_rate,
        max_active: req.max_active,
        min_reputation: req.min_reputation,
        auto_approve: req.auto_approve,
    };
    save_rent_policy(engine, &policy)?;

    let json = serde_json::to_vec(&policy).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/market/stats
pub async fn handle_market_stats(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let stats = engine.activity_stats();
    let reputation = engine.reputation_score();
    let local_capacity = engine.config().webui.effective_max_agents() as usize;
    let remote_online = engine.agent_registry().count_online();
    let runs_total = stats
        .entries_by_type
        .get("command_exec")
        .copied()
        .unwrap_or(stats.total_entries);
    let balance = resolve_chain_balance(engine);
    let body = serde_json::json!({
        "rating": reputation,
        "reputation_score": reputation,
        "runs_total": runs_total,
        "activity": stats,
        "agents": {
            "local_capacity": local_capacity,
            "remote_online": remote_online,
            "active_total": local_capacity + remote_online,
        },
        "balance": balance,
        "balance_source": if balance.is_some() { "chain" } else { "unconfigured" },
    });
    let json = serde_json::to_vec(&body).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

/// GET /api/quick-actions
pub async fn handle_quick_actions(
    stream: &mut TcpStream,
    engine: &AgentEngine,
    cors_origin: &str,
) -> Result<(), AgentError> {
    let actions: Vec<crate::ai::QuickAction> = engine.get_quick_actions("owner");
    let json = serde_json::to_vec(&actions).unwrap_or_default();
    send_response(stream, 200, "application/json", &json, cors_origin).await
}

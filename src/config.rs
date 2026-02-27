use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_agent")]
    pub agent: AgentSection,
    #[serde(default)]
    pub transport: TransportSection,
    #[serde(default)]
    pub security: SecuritySection,
    #[serde(default)]
    pub execution: ExecutionSection,
    #[serde(default)]
    pub resource: ResourceSection,
    #[serde(default)]
    pub logging: LoggingSection,
    #[serde(default)]
    pub ai: AiConfig,
    #[serde(default)]
    pub webui: WebUiSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSection {
    #[serde(default = "default_device_name")]
    pub device_name: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportSection {
    #[serde(default = "default_true")]
    pub tcp_enabled: bool,
    #[serde(default)]
    pub quic_enabled: bool,
    #[serde(default)]
    pub ble_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySection {
    #[serde(default = "default_policy_mode")]
    pub policy_mode: String,
    #[serde(default = "default_role")]
    pub default_role: String,
    #[serde(default = "default_session_timeout")]
    pub session_timeout_secs: u64,
    #[serde(default = "default_session_timeout")]
    pub key_rotation_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSection {
    #[serde(default = "default_true")]
    pub sandbox_enabled: bool,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default = "default_timeout")]
    pub default_timeout_secs: u64,
    #[serde(default = "default_max_timeout")]
    pub max_timeout_secs: u64,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSection {
    #[serde(default = "default_cpu_limit")]
    pub cpu_limit_percent: u8,
    #[serde(default = "default_mem_limit")]
    pub memory_limit_percent: u8,
    #[serde(default)]
    pub gpu_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingSection {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default = "default_rotation")]
    pub rotation: String,
    #[serde(default = "default_max_log_files")]
    pub max_files: u32,
}

/// Web UI configuration section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebUiSection {
    /// Enable the web chat UI
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Base port for the web UI HTTP server (agents use port, port+1, ..., port+max_agents-1)
    #[serde(default = "default_webui_port")]
    pub port: u16,
    /// Bind address (default: 127.0.0.1 — local only)
    #[serde(default = "default_webui_bind")]
    pub bind: String,
    /// Auto-open browser on start
    #[serde(default = "default_true")]
    pub auto_open: bool,
    /// Maximum agent instances (1-10, determined by license tier)
    #[serde(default = "default_max_agents")]
    pub max_agents: u16,
    /// License tier: "free" (1), "pro" (5), "enterprise" (10)
    #[serde(default = "default_license_tier")]
    pub license_tier: String,
    /// Work profile: "system", "software_dev", "marketing", "all"
    #[serde(default = "default_work_profile")]
    pub work_profile: String,
    /// Authentication password for the web UI (empty = no auth)
    #[serde(default)]
    pub auth_password: String,
    /// CORS allowed origin (default: auto from bind+port)
    #[serde(default)]
    pub cors_origin: String,
}

impl Default for WebUiSection {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_webui_port(),
            bind: default_webui_bind(),
            auto_open: true,
            max_agents: default_max_agents(),
            license_tier: default_license_tier(),
            work_profile: default_work_profile(),
            auth_password: String::new(),
            cors_origin: String::new(),
        }
    }
}

fn default_webui_port() -> u16 {
    9444
}
fn default_webui_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_max_agents() -> u16 {
    1
}
fn default_license_tier() -> String {
    "free".to_string()
}
fn default_work_profile() -> String {
    "all".to_string()
}

impl WebUiSection {
    /// Get the maximum agents allowed by license tier
    pub fn max_agents_for_tier(&self) -> u16 {
        match self.license_tier.to_lowercase().as_str() {
            "free" => 1,
            "pro" | "professional" => 5,
            "enterprise" | "unlimited" => 10,
            _ => 1,
        }
    }

    /// Get the effective max agents (min of config and tier limit)
    pub fn effective_max_agents(&self) -> u16 {
        self.max_agents.min(self.max_agents_for_tier())
    }

    /// Get the port for a specific agent index (0-based)
    pub fn agent_port(&self, index: u16) -> u16 {
        self.port + index
    }
}

// Default value functions
fn default_agent() -> AgentSection {
    AgentSection {
        device_name: default_device_name(),
        listen_port: default_listen_port(),
        max_connections: default_max_connections(),
    }
}

fn default_device_name() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "edgeclaw-agent".to_string())
}

fn default_listen_port() -> u16 {
    8443
}
fn default_max_connections() -> usize {
    50
}
fn default_true() -> bool {
    true
}
fn default_policy_mode() -> String {
    "strict".to_string()
}
fn default_role() -> String {
    "viewer".to_string()
}
fn default_session_timeout() -> u64 {
    3600
}
fn default_max_concurrent() -> usize {
    5
}
fn default_timeout() -> u64 {
    60
}
fn default_max_timeout() -> u64 {
    3600
}
fn default_cpu_limit() -> u8 {
    80
}
fn default_mem_limit() -> u8 {
    85
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}
fn default_rotation() -> String {
    "daily".to_string()
}
fn default_max_log_files() -> u32 {
    30
}

// ─── AI Configuration ──────────────────────────────────────

/// AI provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// Primary provider: "local", "ollama", "openai", "claude", "none"
    #[serde(default = "default_ai_primary")]
    pub primary: String,
    /// Local AI settings
    #[serde(default)]
    pub local: AiLocalConfig,
    /// Cloud AI settings
    #[serde(default)]
    pub cloud: AiCloudConfig,
    /// AI policy settings
    #[serde(default)]
    pub policy: AiPolicyConfig,
}

/// Local AI provider settings (Ollama)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiLocalConfig {
    /// Ollama endpoint
    #[serde(default = "default_ollama_endpoint")]
    pub endpoint: String,
    /// Model name
    #[serde(default = "default_ollama_model")]
    pub model: String,
    /// Timeout in milliseconds
    #[serde(default = "default_ai_timeout")]
    pub timeout_ms: u64,
}

/// Cloud AI provider settings (OpenAI / Claude)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCloudConfig {
    /// Provider: "openai" or "claude"
    #[serde(default = "default_cloud_provider")]
    pub provider: String,
    /// Model name
    #[serde(default = "default_cloud_model")]
    pub model: String,
    /// API endpoint
    #[serde(default = "default_cloud_endpoint")]
    pub endpoint: String,
    /// Timeout in milliseconds
    #[serde(default = "default_cloud_timeout")]
    pub timeout_ms: u64,
}

/// AI policy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPolicyConfig {
    /// Confidence threshold for cloud escalation (0.0 - 1.0)
    #[serde(default = "default_escalation_threshold")]
    pub escalation_threshold: f64,
    /// Keywords that must never be sent to cloud AI
    #[serde(default = "default_never_cloud")]
    pub never_cloud: Vec<String>,
    /// Require explicit user consent before cloud escalation
    #[serde(default = "default_true")]
    pub require_consent: bool,
    /// Log all AI interactions to audit trail
    #[serde(default = "default_true")]
    pub audit_ai_calls: bool,
}

fn default_ai_primary() -> String {
    "none".to_string()
}
fn default_ollama_endpoint() -> String {
    "http://localhost:11434".to_string()
}
fn default_ollama_model() -> String {
    "llama3.2:3b".to_string()
}
fn default_ai_timeout() -> u64 {
    5000
}
fn default_cloud_provider() -> String {
    "openai".to_string()
}
fn default_cloud_model() -> String {
    "gpt-4o-mini".to_string()
}
fn default_cloud_endpoint() -> String {
    "https://api.openai.com".to_string()
}
fn default_cloud_timeout() -> u64 {
    30000
}
fn default_escalation_threshold() -> f64 {
    0.6
}
fn default_never_cloud() -> Vec<String> {
    vec![
        "password".to_string(),
        "secret".to_string(),
        "private_key".to_string(),
        "token".to_string(),
        "credential".to_string(),
        "api_key".to_string(),
    ]
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            primary: default_ai_primary(),
            local: AiLocalConfig::default(),
            cloud: AiCloudConfig::default(),
            policy: AiPolicyConfig::default(),
        }
    }
}

impl Default for AiLocalConfig {
    fn default() -> Self {
        Self {
            endpoint: default_ollama_endpoint(),
            model: default_ollama_model(),
            timeout_ms: default_ai_timeout(),
        }
    }
}

impl Default for AiCloudConfig {
    fn default() -> Self {
        Self {
            provider: default_cloud_provider(),
            model: default_cloud_model(),
            endpoint: default_cloud_endpoint(),
            timeout_ms: default_cloud_timeout(),
        }
    }
}

impl Default for AiPolicyConfig {
    fn default() -> Self {
        Self {
            escalation_threshold: default_escalation_threshold(),
            never_cloud: default_never_cloud(),
            require_consent: true,
            audit_ai_calls: true,
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent: default_agent(),
            transport: TransportSection::default(),
            security: SecuritySection::default(),
            execution: ExecutionSection::default(),
            resource: ResourceSection::default(),
            logging: LoggingSection::default(),
            ai: AiConfig::default(),
            webui: WebUiSection::default(),
        }
    }
}

impl Default for TransportSection {
    fn default() -> Self {
        Self {
            tcp_enabled: true,
            quic_enabled: false,
            ble_enabled: false,
        }
    }
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            policy_mode: default_policy_mode(),
            default_role: default_role(),
            session_timeout_secs: default_session_timeout(),
            key_rotation_secs: default_session_timeout(),
        }
    }
}

impl Default for ExecutionSection {
    fn default() -> Self {
        Self {
            sandbox_enabled: true,
            max_concurrent: default_max_concurrent(),
            default_timeout_secs: default_timeout(),
            max_timeout_secs: default_max_timeout(),
            allowed_paths: Vec::new(),
        }
    }
}

impl Default for ResourceSection {
    fn default() -> Self {
        Self {
            cpu_limit_percent: default_cpu_limit(),
            memory_limit_percent: default_mem_limit(),
            gpu_enabled: false,
        }
    }
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            file: None,
            rotation: default_rotation(),
            max_files: default_max_log_files(),
        }
    }
}

impl AgentConfig {
    /// Load config from a TOML file, or return defaults if the file doesn't exist.
    pub fn load(path: &PathBuf) -> Result<Self, crate::error::AgentError> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let config: AgentConfig = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    /// Save config to a TOML file.
    pub fn save(&self, path: &PathBuf) -> Result<(), crate::error::AgentError> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::error::AgentError::ConfigError(e.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Get the default config file path.
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("edgeclaw")
            .join("agent.toml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AgentConfig::default();
        assert_eq!(config.agent.listen_port, 8443);
        assert_eq!(config.agent.max_connections, 50);
        assert!(config.transport.tcp_enabled);
        assert!(!config.transport.quic_enabled);
        assert_eq!(config.security.policy_mode, "strict");
        assert_eq!(config.execution.max_concurrent, 5);
        assert_eq!(config.resource.cpu_limit_percent, 80);
    }

    #[test]
    fn test_config_serialize_roundtrip() {
        let config = AgentConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: AgentConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.agent.listen_port, config.agent.listen_port);
        assert_eq!(parsed.security.policy_mode, config.security.policy_mode);
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let path = PathBuf::from("/nonexistent/path/agent.toml");
        let config = AgentConfig::load(&path).unwrap();
        assert_eq!(config.agent.listen_port, 8443);
    }
}

use crate::error::AgentError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod cloud;
pub mod ensemble;
pub mod huggingface;
pub mod manager;
pub mod none_provider;
pub mod ollama;
pub mod prompt;

pub use ensemble::{
    ConsensusAlgorithm, DomainDetector, EnsembleConfig, EnsembleExecutor, EnsembleResult,
    ExpertRole, FleetMissionPlanner, MissionComparison, MissionComparisonEngine,
    MissionQualityEvaluator, ProcessType,
};
pub use huggingface::HuggingFaceProvider;
pub use manager::{AiManager, MissionRegistry};
pub use none_provider::NoneProvider;
pub use ollama::OllamaProvider;
pub use prompt::build_prompt;

// ─── AI Request / Response ─────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRequest {
    pub user_input: String,
    pub available_capabilities: Vec<String>,
    pub peer_role: String,
    pub system_context: Option<String>,
    pub history: Vec<ChatMessage>,
    pub model: Option<String>,
    pub attachments: Vec<FileAttachment>,
    pub parallel: bool,
    pub strategies: Vec<String>,
    pub preferred_language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAttachment {
    pub name: String,
    pub mime_type: String,
    pub content_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MissionMetadata {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub goals: Vec<String>,
    #[serde(default)]
    pub status: MissionStatus,
    #[serde(default)]
    pub progress: u32,
    #[serde(default)]
    pub tasks: Vec<TaskUnit>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskUnit {
    pub desc: String,
    pub capability: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum MissionStatus {
    #[default]
    Proposed,
    Discovery,
    Planning,
    Active,
    Verification,
    Success,
    Failure,
    Aborted,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AiResponse {
    pub message: String,
    pub intent: Option<ParsedIntent>,
    pub confidence: f64,
    pub provider: String,
    pub is_local: bool,
    pub sub_responses: Vec<AiResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParsedIntent {
    pub capability: String,
    pub command: String,
    pub args: Vec<String>,
    pub needs_confirmation: bool,
    pub mission: Option<MissionMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
    pub timestamp: String,
}

// ─── AI Dialogue Roles ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChatRole {
    User,
    Assistant,
    System,
}

impl std::fmt::Display for ChatRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChatRole::User => write!(f, "User"),
            ChatRole::Assistant => write!(f, "Assistant"),
            ChatRole::System => write!(f, "System"),
        }
    }
}

// ─── Quick Actions & Profiles ──────────────────────────────

/// Industry work profile for categorized quick actions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkProfile {
    System,
    SoftwareDev,
    Marketing,
    DevOps,
    Custom(String),
}

impl std::fmt::Display for WorkProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkProfile::System => write!(f, "System"),
            WorkProfile::SoftwareDev => write!(f, "Software Dev"),
            WorkProfile::Marketing => write!(f, "Marketing"),
            WorkProfile::DevOps => write!(f, "DevOps"),
            WorkProfile::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

/// Pre-defined quick actions for button-based UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickAction {
    pub label: String,
    pub icon: String,
    pub command: String,
    pub capability: String,
    pub needs_confirmation: bool,
    pub profile: WorkProfile,
    pub group: String,
}

#[allow(clippy::vec_init_then_push)]
pub fn default_quick_actions() -> Vec<QuickAction> {
    let mut actions = Vec::new();

    // Monitoring
    actions.push(QuickAction {
        label: "Server Status".into(),
        icon: "monitor".into(),
        command: "status".into(),
        capability: "status_query".into(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".into(),
    });
    actions.push(QuickAction {
        label: "CPU Usage".into(),
        icon: "speed".into(),
        command: "cpu".into(),
        capability: "system_info".into(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".into(),
    });
    actions.push(QuickAction {
        label: "Memory Usage".into(),
        icon: "memory".into(),
        command: "memory".into(),
        capability: "system_info".into(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".into(),
    });

    // Git
    actions.push(QuickAction {
        label: "Git Status".into(),
        icon: "code".into(),
        command: "git status".into(),
        capability: "shell_exec".into(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Git".into(),
    });
    actions.push(QuickAction {
        label: "Git Pull".into(),
        icon: "cloud_download".into(),
        command: "git pull".into(),
        capability: "shell_exec".into(),
        needs_confirmation: true,
        profile: WorkProfile::SoftwareDev,
        group: "Git".into(),
    });

    // Docker
    actions.push(QuickAction {
        label: "Docker Status".into(),
        icon: "inventory_2".into(),
        command: "docker ps".into(),
        capability: "docker_manage".into(),
        needs_confirmation: false,
        profile: WorkProfile::DevOps,
        group: "Docker".into(),
    });

    actions
}

pub fn quick_actions_by_profile(profile: Option<WorkProfile>) -> Vec<QuickAction> {
    let all = default_quick_actions();
    match profile {
        Some(p) => all
            .into_iter()
            .filter(|a| a.profile == p || a.profile == WorkProfile::System)
            .collect(),
        None => all,
    }
}

// ─── AI Provider Trait ─────────────────────────────────────

pub trait AiProvider: Send + Sync {
    fn name(&self) -> &str;
    fn is_available(&self) -> bool;
    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError>;
    fn is_local(&self) -> bool;
    fn set_model(&mut self, model: &str) -> Result<(), AgentError>;
    fn list_models(&self) -> Vec<String> {
        Vec::new()
    }
}

// ─── HTTP Helpers (Shared by providers) ───────────────────

pub fn ureq_get_with_timeout(url: &str, timeout: Duration) -> Result<String, AgentError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build();

    let response = agent
        .get(url)
        .call()
        .map_err(|e| AgentError::ConnectionError(format!("HTTP GET failed: {}", e)))?;

    response
        .into_string()
        .map_err(|e| AgentError::ConnectionError(format!("read body failed: {}", e)))
}

pub fn ureq_post_json_with_timeout(
    url: &str,
    body: &serde_json::Value,
    timeout: Duration,
) -> Result<String, AgentError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5)) // Fast failure if the server is offline (like Ollama not running)
        .timeout_read(timeout) // Unlimited or long wait for slow AI responses
        .timeout_write(timeout)
        .build();

    let response = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_json(body.clone())
        .map_err(|e| AgentError::ConnectionError(format!("HTTP POST failed: {}", e)))?;

    response
        .into_string()
        .map_err(|e| AgentError::ConnectionError(format!("read body failed: {}", e)))
}

pub fn ureq_post_json_with_auth(
    url: &str,
    body: &serde_json::Value,
    api_key: &str,
    timeout: Duration,
) -> Result<String, AgentError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build();

    let response = agent
        .post(url)
        .set("Content-Type", "application/json")
        .set("Authorization", &format!("Bearer {}", api_key))
        .send_json(body.clone())
        .map_err(|e| AgentError::ConnectionError(format!("HTTP POST failed: {}", e)))?;

    response
        .into_string()
        .map_err(|e| AgentError::ConnectionError(format!("read body failed: {}", e)))
}

pub fn ureq_post_json_with_anthropic_auth(
    url: &str,
    body: &serde_json::Value,
    api_key: &str,
    timeout: Duration,
) -> Result<String, AgentError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build();

    let response = agent
        .post(url)
        .set("Content-Type", "application/json")
        .set("x-api-key", api_key)
        .set("anthropic-version", "2023-06-01")
        .send_json(body.clone())
        .map_err(|e| AgentError::ConnectionError(format!("Claude POST failed: {}", e)))?;

    response
        .into_string()
        .map_err(|e| AgentError::ConnectionError(format!("read body failed: {}", e)))
}

pub fn parse_cloud_response(content: &str, provider: &str) -> Result<AiResponse, AgentError> {
    let json_str = if let Some(start) = content.find('{') {
        if let Some(end) = content.rfind('}') {
            &content[start..=end]
        } else {
            content
        }
    } else {
        content
    };

    #[derive(Deserialize)]
    struct RawResponse {
        message: Option<String>,
        intent: Option<ParsedIntent>,
        confidence: Option<f64>,
    }

    match serde_json::from_str::<RawResponse>(json_str) {
        Ok(parsed) => Ok(AiResponse {
            message: parsed.message.unwrap_or_else(|| content.to_string()),
            intent: parsed.intent,
            confidence: parsed.confidence.unwrap_or(0.8),
            provider: provider.to_string(),
            is_local: false,
            sub_responses: Vec::new(),
        }),
        Err(_) => Ok(AiResponse {
            message: content.to_string(),
            intent: None,
            confidence: 0.5,
            provider: provider.to_string(),
            is_local: false,
            sub_responses: Vec::new(),
        }),
    }
}

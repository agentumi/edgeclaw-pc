//! AI Provider plugin system — swappable AI backends for EdgeClaw Agent.
//!
//! Supports local (Ollama), cloud (OpenAI, Claude), and passthrough (None) providers.
//! AI is a plugin — security is the platform.

use crate::error::AgentError;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

// ─── AI Request / Response ─────────────────────────────────

/// A request to the AI provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRequest {
    /// The user's natural language input
    pub user_input: String,
    /// Available capabilities on this agent
    pub available_capabilities: Vec<String>,
    /// The requesting peer's role
    pub peer_role: String,
    /// System context (CPU, memory, etc.)
    pub system_context: Option<String>,
    /// Conversation history (last N messages)
    pub history: Vec<ChatMessage>,
}

/// AI provider response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiResponse {
    /// The AI's text response to display to the user
    pub message: String,
    /// Parsed intent (if any)
    pub intent: Option<ParsedIntent>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Which provider answered
    pub provider: String,
    /// Whether this was processed locally
    pub is_local: bool,
}

/// Parsed intent from natural language
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedIntent {
    /// The capability to invoke (e.g., "shell_exec", "file_read")
    pub capability: String,
    /// The command or path to operate on
    pub command: String,
    /// Additional arguments
    pub args: Vec<String>,
    /// Whether user confirmation is recommended
    pub needs_confirmation: bool,
}

/// Chat message for conversation history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
    pub timestamp: String,
}

/// Chat message role
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChatRole {
    User,
    Assistant,
    System,
}

// ─── AI Provider Trait ─────────────────────────────────────

/// Trait for AI providers — implement this to add a new AI backend
pub trait AiProvider: Send + Sync {
    /// Provider name (e.g., "ollama", "openai", "claude")
    fn name(&self) -> &str;

    /// Check if the provider is available and ready
    fn is_available(&self) -> bool;

    /// Process a chat request
    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError>;

    /// Whether this provider runs locally (no data leaves the network)
    fn is_local(&self) -> bool;
}

// ─── Ollama Provider (Local) ───────────────────────────────

/// Local AI provider using Ollama
pub struct OllamaProvider {
    endpoint: String,
    model: String,
    timeout: Duration,
}

impl OllamaProvider {
    /// Create a new Ollama provider
    pub fn new(endpoint: &str, model: &str, timeout_ms: u64) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            model: model.to_string(),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Build the prompt for intent classification
    fn build_prompt(&self, request: &AiRequest) -> String {
        let caps = request.available_capabilities.join(", ");
        let history_text = request
            .history
            .iter()
            .map(|m| {
                let role = match m.role {
                    ChatRole::User => "User",
                    ChatRole::Assistant => "Assistant",
                    ChatRole::System => "System",
                };
                format!("{}: {}", role, m.content)
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"You are EdgeClaw AI assistant. You help manage servers securely.

Available capabilities: [{caps}]
User role: {role}
{system_ctx}

{history}

User: {input}

Respond in this JSON format:
{{"message": "your response", "intent": {{"capability": "cap_name", "command": "cmd", "args": [], "needs_confirmation": true}}, "confidence": 0.95}}

If the user is just chatting (not requesting a command), set intent to null.
Keep responses concise and helpful. For elderly users, be extra clear and simple."#,
            caps = caps,
            role = request.peer_role,
            system_ctx = request
                .system_context
                .as_deref()
                .map(|s| format!("System: {}", s))
                .unwrap_or_default(),
            history = if history_text.is_empty() {
                String::new()
            } else {
                format!("Conversation:\n{}", history_text)
            },
            input = request.user_input,
        )
    }

    /// Parse the AI response JSON
    fn parse_response(&self, raw: &str) -> Result<AiResponse, AgentError> {
        // Try to extract JSON from response
        let json_str = if let Some(start) = raw.find('{') {
            if let Some(end) = raw.rfind('}') {
                &raw[start..=end]
            } else {
                raw
            }
        } else {
            raw
        };

        #[derive(Deserialize)]
        struct RawResponse {
            message: Option<String>,
            intent: Option<ParsedIntent>,
            confidence: Option<f64>,
        }

        match serde_json::from_str::<RawResponse>(json_str) {
            Ok(parsed) => Ok(AiResponse {
                message: parsed.message.unwrap_or_else(|| raw.to_string()),
                intent: parsed.intent,
                confidence: parsed.confidence.unwrap_or(0.5),
                provider: "ollama".to_string(),
                is_local: true,
            }),
            Err(_) => {
                // Fallback: treat the entire response as a message
                Ok(AiResponse {
                    message: raw.to_string(),
                    intent: None,
                    confidence: 0.3,
                    provider: "ollama".to_string(),
                    is_local: true,
                })
            }
        }
    }
}

impl AiProvider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn is_available(&self) -> bool {
        // Check if Ollama is running by hitting the API
        let url = format!("{}/api/tags", self.endpoint);
        ureq_get_with_timeout(&url, self.timeout).is_ok()
    }

    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        let prompt = self.build_prompt(request);
        let url = format!("{}/api/generate", self.endpoint);

        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "temperature": 0.3,
                "num_predict": 512
            }
        });

        let resp = ureq_post_json_with_timeout(&url, &body, self.timeout)?;

        #[derive(Deserialize)]
        struct OllamaResp {
            response: String,
        }

        let ollama_resp: OllamaResp = serde_json::from_str(&resp)
            .map_err(|e| AgentError::SerializationError(format!("ollama response: {}", e)))?;

        self.parse_response(&ollama_resp.response)
    }

    fn is_local(&self) -> bool {
        true
    }
}

// ─── OpenAI Provider (Cloud) ───────────────────────────────

/// Cloud AI provider using OpenAI API
pub struct OpenAiProvider {
    api_key: String,
    model: String,
    endpoint: String,
    timeout: Duration,
}

impl OpenAiProvider {
    /// Create a new OpenAI provider
    pub fn new(api_key: &str, model: &str, endpoint: &str, timeout_ms: u64) -> Self {
        Self {
            api_key: api_key.to_string(),
            model: model.to_string(),
            endpoint: endpoint.to_string(),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    fn build_messages(&self, request: &AiRequest) -> Vec<serde_json::Value> {
        let caps = request.available_capabilities.join(", ");

        let mut messages = vec![serde_json::json!({
            "role": "system",
            "content": format!(
                "You are EdgeClaw AI assistant for secure server management. \
                 Available capabilities: [{}]. User role: {}. \
                 Respond with JSON: {{\"message\": \"...\", \"intent\": {{\"capability\": \"...\", \
                 \"command\": \"...\", \"args\": [], \"needs_confirmation\": true}}, \"confidence\": 0.95}}. \
                 Set intent to null for non-command messages. Be concise. \
                 For elderly or non-technical users, be extra clear and simple.",
                caps, request.peer_role
            )
        })];

        for msg in &request.history {
            let role = match msg.role {
                ChatRole::User => "user",
                ChatRole::Assistant => "assistant",
                ChatRole::System => "system",
            };
            messages.push(serde_json::json!({
                "role": role,
                "content": msg.content
            }));
        }

        messages.push(serde_json::json!({
            "role": "user",
            "content": request.user_input
        }));

        messages
    }
}

impl AiProvider for OpenAiProvider {
    fn name(&self) -> &str {
        "openai"
    }

    fn is_available(&self) -> bool {
        !self.api_key.is_empty()
    }

    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        let messages = self.build_messages(request);
        let body = serde_json::json!({
            "model": self.model,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 512,
            "response_format": { "type": "json_object" }
        });

        let url = format!("{}/v1/chat/completions", self.endpoint);
        let resp = ureq_post_json_with_auth(&url, &body, &self.api_key, self.timeout)?;

        #[derive(Deserialize)]
        struct OpenAiResp {
            choices: Vec<OpenAiChoice>,
        }
        #[derive(Deserialize)]
        struct OpenAiChoice {
            message: OpenAiMsg,
        }
        #[derive(Deserialize)]
        struct OpenAiMsg {
            content: String,
        }

        let parsed: OpenAiResp = serde_json::from_str(&resp)
            .map_err(|e| AgentError::SerializationError(format!("openai response: {}", e)))?;

        let content = parsed
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        parse_cloud_response(&content, "openai")
    }

    fn is_local(&self) -> bool {
        false
    }
}

// ─── Claude Provider (Cloud) ───────────────────────────────

/// Cloud AI provider using Anthropic Claude API
pub struct ClaudeProvider {
    api_key: String,
    model: String,
    endpoint: String,
    timeout: Duration,
}

impl ClaudeProvider {
    /// Create a new Claude provider
    pub fn new(api_key: &str, model: &str, endpoint: &str, timeout_ms: u64) -> Self {
        Self {
            api_key: api_key.to_string(),
            model: model.to_string(),
            endpoint: endpoint.to_string(),
            timeout: Duration::from_millis(timeout_ms),
        }
    }
}

impl AiProvider for ClaudeProvider {
    fn name(&self) -> &str {
        "claude"
    }

    fn is_available(&self) -> bool {
        !self.api_key.is_empty()
    }

    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        let caps = request.available_capabilities.join(", ");

        let mut messages = Vec::new();
        for msg in &request.history {
            let role = match msg.role {
                ChatRole::User => "user",
                ChatRole::Assistant => "assistant",
                ChatRole::System => "user", // Claude uses user for system-like
            };
            messages.push(serde_json::json!({
                "role": role,
                "content": msg.content
            }));
        }
        messages.push(serde_json::json!({
            "role": "user",
            "content": request.user_input
        }));

        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 512,
            "system": format!(
                "You are EdgeClaw AI assistant for secure server management. \
                 Available capabilities: [{}]. User role: {}. \
                 Respond with JSON: {{\"message\": \"...\", \"intent\": {{\"capability\": \"...\", \
                 \"command\": \"...\", \"args\": [], \"needs_confirmation\": true}}, \"confidence\": 0.95}}. \
                 Set intent to null for non-command messages. Be concise.",
                caps, request.peer_role
            ),
            "messages": messages
        });

        let url = format!("{}/v1/messages", self.endpoint);
        let resp = ureq_post_json_with_anthropic_auth(&url, &body, &self.api_key, self.timeout)?;

        #[derive(Deserialize)]
        struct ClaudeResp {
            content: Vec<ClaudeContent>,
        }
        #[derive(Deserialize)]
        struct ClaudeContent {
            text: String,
        }

        let parsed: ClaudeResp = serde_json::from_str(&resp)
            .map_err(|e| AgentError::SerializationError(format!("claude response: {}", e)))?;

        let content = parsed
            .content
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_default();

        parse_cloud_response(&content, "claude")
    }

    fn is_local(&self) -> bool {
        false
    }
}

// ─── None Provider (Passthrough) ───────────────────────────

/// No AI — just parses simple commands directly
pub struct NoneProvider;

impl Default for NoneProvider {
    fn default() -> Self {
        Self
    }
}

impl NoneProvider {
    /// Create the passthrough provider
    pub fn new() -> Self {
        Self
    }

    /// Simple command parsing without AI
    fn parse_simple_command(input: &str) -> Option<ParsedIntent> {
        let input_lower = input.trim().to_lowercase();
        let parts: Vec<&str> = input_lower.splitn(2, ' ').collect();

        match parts.first().copied() {
            Some("status" | "상태") => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "status".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            Some("restart" | "재시작") => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: format!("systemctl restart {}", parts.get(1).unwrap_or(&"")),
                args: vec![],
                needs_confirmation: true,
            }),
            Some("log" | "logs" | "로그") => Some(ParsedIntent {
                capability: "log_read".to_string(),
                command: format!("tail -100 {}", parts.get(1).unwrap_or(&"/var/log/syslog")),
                args: vec![],
                needs_confirmation: false,
            }),
            Some("disk" | "디스크") => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "df -h".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            Some("memory" | "메모리" | "ram") => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "free -h".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            Some("cpu") => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "top -bn1 | head -20".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            Some("ps" | "process" | "프로세스") => Some(ParsedIntent {
                capability: "process_manage".to_string(),
                command: "ps aux --sort=-pcpu | head -20".to_string(),
                args: vec![],
                needs_confirmation: false,
            }),
            _ => None,
        }
    }
}

impl AiProvider for NoneProvider {
    fn name(&self) -> &str {
        "none"
    }

    fn is_available(&self) -> bool {
        true // Always available
    }

    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        match Self::parse_simple_command(&request.user_input) {
            Some(intent) => Ok(AiResponse {
                message: format!("Executing: {}", intent.command),
                intent: Some(intent),
                confidence: 1.0,
                provider: "none".to_string(),
                is_local: true,
            }),
            None => Ok(AiResponse {
                message: format!(
                    "I don't understand '{}'. Try: status, restart <service>, log, disk, memory, cpu, ps",
                    request.user_input
                ),
                intent: None,
                confidence: 0.0,
                provider: "none".to_string(),
                is_local: true,
            }),
        }
    }

    fn is_local(&self) -> bool {
        true
    }
}

// ─── AI Manager ────────────────────────────────────────────

/// Manages AI providers with fallback and escalation
pub struct AiManager {
    primary: Box<dyn AiProvider>,
    fallback: Option<Box<dyn AiProvider>>,
    escalation_threshold: f64,
    sensitive_keywords: Vec<String>,
    require_consent: bool,
}

impl AiManager {
    /// Create a new AI manager from config
    pub fn from_config(config: &crate::config::AiConfig) -> Self {
        let primary: Box<dyn AiProvider> = match config.primary.as_str() {
            "ollama" | "local" => Box::new(OllamaProvider::new(
                &config.local.endpoint,
                &config.local.model,
                config.local.timeout_ms,
            )),
            "openai" => {
                let api_key = std::env::var("EDGECLAW_OPENAI_KEY").unwrap_or_default();
                Box::new(OpenAiProvider::new(
                    &api_key,
                    &config.cloud.model,
                    &config.cloud.endpoint,
                    config.cloud.timeout_ms,
                ))
            }
            "claude" => {
                let api_key = std::env::var("EDGECLAW_CLAUDE_KEY").unwrap_or_default();
                Box::new(ClaudeProvider::new(
                    &api_key,
                    &config.cloud.model,
                    &config.cloud.endpoint,
                    config.cloud.timeout_ms,
                ))
            }
            _ => Box::new(NoneProvider::new()),
        };

        let fallback: Option<Box<dyn AiProvider>> = if config.primary != "none" {
            Some(Box::new(NoneProvider::new()))
        } else {
            None
        };

        Self {
            primary,
            fallback,
            escalation_threshold: config.policy.escalation_threshold,
            sensitive_keywords: config.policy.never_cloud.clone(),
            require_consent: config.policy.require_consent,
        }
    }

    /// Process a chat request with fallback
    pub fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        // Check for sensitive content if using cloud provider
        if !self.primary.is_local() && self.contains_sensitive(&request.user_input) {
            warn!("Sensitive content detected, blocking cloud AI");
            return Err(AgentError::PolicyDenied(
                "Command contains sensitive information; cannot send to cloud AI".to_string(),
            ));
        }

        // Try primary provider
        match self.primary.process(request) {
            Ok(response) => {
                info!(
                    provider = response.provider,
                    confidence = response.confidence,
                    "AI response generated"
                );

                // Check if confidence is too low and we should escalate
                if response.confidence < self.escalation_threshold && response.intent.is_some() {
                    warn!(
                        confidence = response.confidence,
                        threshold = self.escalation_threshold,
                        "Low confidence — consider cloud AI escalation"
                    );
                    // Return with escalation hint
                    Ok(AiResponse {
                        message: format!(
                            "{}\n\n⚠️ Low confidence ({:.0}%). Consider using cloud AI for better accuracy.",
                            response.message,
                            response.confidence * 100.0
                        ),
                        ..response
                    })
                } else {
                    Ok(response)
                }
            }
            Err(e) => {
                warn!(error = %e, "Primary AI provider failed, trying fallback");
                // Try fallback
                if let Some(fallback) = &self.fallback {
                    fallback.process(request)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Check if primary provider is available
    pub fn is_available(&self) -> bool {
        self.primary.is_available()
    }

    /// Get the primary provider name
    pub fn provider_name(&self) -> &str {
        self.primary.name()
    }

    /// Whether the current primary is local
    pub fn is_local(&self) -> bool {
        self.primary.is_local()
    }

    /// Check for sensitive keywords
    fn contains_sensitive(&self, input: &str) -> bool {
        let lower = input.to_lowercase();
        self.sensitive_keywords
            .iter()
            .any(|kw| lower.contains(&kw.to_lowercase()))
    }

    /// Whether cloud escalation requires user consent
    pub fn requires_consent(&self) -> bool {
        self.require_consent
    }
}

// ─── HTTP Helpers (sync, minimal) ──────────────────────────

/// Simple GET with timeout (no external HTTP crate needed)
fn ureq_get_with_timeout(url: &str, timeout: Duration) -> Result<String, AgentError> {
    use std::io::Read;
    use std::net::TcpStream;

    let parsed = parse_url(url)?;
    let addr = format!("{}:{}", parsed.host, parsed.port);

    let stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| AgentError::ConnectionError(format!("invalid address: {}", e)))?,
        timeout,
    )
    .map_err(|e| AgentError::ConnectionError(format!("connect failed: {}", e)))?;

    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        parsed.path, parsed.host
    );

    use std::io::Write;
    let mut stream = stream;
    stream
        .write_all(request.as_bytes())
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;

    extract_body(&response)
}

/// POST JSON with timeout
fn ureq_post_json_with_timeout(
    url: &str,
    body: &serde_json::Value,
    timeout: Duration,
) -> Result<String, AgentError> {
    post_json_with_headers(url, body, &[], timeout)
}

/// POST JSON with Bearer auth
fn ureq_post_json_with_auth(
    url: &str,
    body: &serde_json::Value,
    api_key: &str,
    timeout: Duration,
) -> Result<String, AgentError> {
    let headers = vec![format!("Authorization: Bearer {}", api_key)];
    post_json_with_headers(url, body, &headers, timeout)
}

/// POST JSON with Anthropic auth
fn ureq_post_json_with_anthropic_auth(
    url: &str,
    body: &serde_json::Value,
    api_key: &str,
    timeout: Duration,
) -> Result<String, AgentError> {
    let headers = vec![
        format!("x-api-key: {}", api_key),
        "anthropic-version: 2023-06-01".to_string(),
    ];
    post_json_with_headers(url, body, &headers, timeout)
}

/// POST JSON with custom headers
fn post_json_with_headers(
    url: &str,
    body: &serde_json::Value,
    extra_headers: &[String],
    timeout: Duration,
) -> Result<String, AgentError> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let parsed = parse_url(url)?;
    let addr = format!("{}:{}", parsed.host, parsed.port);
    let body_str =
        serde_json::to_string(body).map_err(|e| AgentError::SerializationError(e.to_string()))?;

    let stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| AgentError::ConnectionError(format!("invalid address: {}", e)))?,
        timeout,
    )
    .map_err(|e| AgentError::ConnectionError(format!("connect failed: {}", e)))?;

    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;

    let mut headers = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        parsed.path,
        parsed.host,
        body_str.len()
    );
    for h in extra_headers {
        headers.push_str(h);
        headers.push_str("\r\n");
    }
    headers.push_str("Connection: close\r\n\r\n");
    headers.push_str(&body_str);

    let mut stream = stream;
    stream
        .write_all(headers.as_bytes())
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| AgentError::ConnectionError(e.to_string()))?;

    extract_body(&response)
}

struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl, AgentError> {
    let url = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let (host_port, path) = if let Some(idx) = url.find('/') {
        (&url[..idx], &url[idx..])
    } else {
        (url, "/")
    };

    let (host, port) = if let Some(idx) = host_port.find(':') {
        let h = &host_port[..idx];
        let p: u16 = host_port[idx + 1..]
            .parse()
            .map_err(|_| AgentError::InvalidParameter("invalid port".into()))?;
        (h.to_string(), p)
    } else {
        (host_port.to_string(), 80)
    };

    Ok(ParsedUrl {
        host,
        port,
        path: path.to_string(),
    })
}

fn extract_body(response: &str) -> Result<String, AgentError> {
    if let Some(idx) = response.find("\r\n\r\n") {
        Ok(response[idx + 4..].to_string())
    } else {
        Ok(response.to_string())
    }
}

/// Parse a cloud AI JSON response
fn parse_cloud_response(content: &str, provider: &str) -> Result<AiResponse, AgentError> {
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
        }),
        Err(_) => Ok(AiResponse {
            message: content.to_string(),
            intent: None,
            confidence: 0.5,
            provider: provider.to_string(),
            is_local: false,
        }),
    }
}

// ─── Quick Actions ─────────────────────────────────────────

/// Pre-defined quick actions for button-based UI (elderly-friendly)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickAction {
    /// Button label
    pub label: String,
    /// Icon name
    pub icon: String,
    /// The command to execute
    pub command: String,
    /// Capability required
    pub capability: String,
    /// Whether confirmation is needed
    pub needs_confirmation: bool,
}

/// Get default quick actions
pub fn default_quick_actions() -> Vec<QuickAction> {
    vec![
        QuickAction {
            label: "Server Status".to_string(),
            icon: "monitor".to_string(),
            command: "status".to_string(),
            capability: "status_query".to_string(),
            needs_confirmation: false,
        },
        QuickAction {
            label: "Check Disk".to_string(),
            icon: "hard_drive".to_string(),
            command: "df -h".to_string(),
            capability: "system_info".to_string(),
            needs_confirmation: false,
        },
        QuickAction {
            label: "Check Memory".to_string(),
            icon: "memory".to_string(),
            command: "free -h".to_string(),
            capability: "system_info".to_string(),
            needs_confirmation: false,
        },
        QuickAction {
            label: "View Logs".to_string(),
            icon: "description".to_string(),
            command: "tail -50 /var/log/syslog".to_string(),
            capability: "log_read".to_string(),
            needs_confirmation: false,
        },
        QuickAction {
            label: "CPU Usage".to_string(),
            icon: "speed".to_string(),
            command: "top -bn1 | head -20".to_string(),
            capability: "system_info".to_string(),
            needs_confirmation: false,
        },
        QuickAction {
            label: "Running Services".to_string(),
            icon: "apps".to_string(),
            command: "systemctl list-units --type=service --state=running".to_string(),
            capability: "status_query".to_string(),
            needs_confirmation: false,
        },
        QuickAction {
            label: "Network Info".to_string(),
            icon: "wifi".to_string(),
            command: "ip addr show".to_string(),
            capability: "network_scan".to_string(),
            needs_confirmation: false,
        },
        QuickAction {
            label: "Docker Containers".to_string(),
            icon: "inventory_2".to_string(),
            command: "docker ps".to_string(),
            capability: "docker_manage".to_string(),
            needs_confirmation: false,
        },
    ]
}

// ─── Tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_provider_status() {
        let provider = NoneProvider::new();
        let request = AiRequest {
            user_input: "status".to_string(),
            available_capabilities: vec!["status_query".to_string()],
            peer_role: "owner".to_string(),
            system_context: None,
            history: vec![],
        };

        let response = provider.process(&request).unwrap();
        assert!(response.intent.is_some());
        assert_eq!(response.intent.unwrap().capability, "status_query");
        assert!(response.is_local);
    }

    #[test]
    fn test_none_provider_restart() {
        let provider = NoneProvider::new();
        let request = AiRequest {
            user_input: "restart nginx".to_string(),
            available_capabilities: vec!["shell_exec".to_string()],
            peer_role: "owner".to_string(),
            system_context: None,
            history: vec![],
        };

        let response = provider.process(&request).unwrap();
        assert!(response.intent.is_some());
        let intent = response.intent.unwrap();
        assert_eq!(intent.capability, "shell_exec");
        assert!(intent.command.contains("nginx"));
        assert!(intent.needs_confirmation);
    }

    #[test]
    fn test_none_provider_unknown() {
        let provider = NoneProvider::new();
        let request = AiRequest {
            user_input: "whats the meaning of life".to_string(),
            available_capabilities: vec![],
            peer_role: "viewer".to_string(),
            system_context: None,
            history: vec![],
        };

        let response = provider.process(&request).unwrap();
        assert!(response.intent.is_none());
        assert_eq!(response.confidence, 0.0);
    }

    #[test]
    fn test_none_provider_korean_commands() {
        let provider = NoneProvider::new();

        let request = AiRequest {
            user_input: "상태".to_string(),
            available_capabilities: vec!["status_query".to_string()],
            peer_role: "owner".to_string(),
            system_context: None,
            history: vec![],
        };
        let response = provider.process(&request).unwrap();
        assert!(response.intent.is_some());
        assert_eq!(response.intent.unwrap().capability, "status_query");

        let request = AiRequest {
            user_input: "디스크".to_string(),
            available_capabilities: vec!["system_info".to_string()],
            peer_role: "owner".to_string(),
            system_context: None,
            history: vec![],
        };
        let response = provider.process(&request).unwrap();
        assert!(response.intent.is_some());
    }

    #[test]
    fn test_quick_actions() {
        let actions = default_quick_actions();
        assert!(!actions.is_empty());
        assert!(actions.iter().any(|a| a.label == "Server Status"));
        assert!(actions.iter().any(|a| a.label == "Check Disk"));
        // All actions should have a capability
        for action in &actions {
            assert!(!action.capability.is_empty());
        }
    }

    #[test]
    fn test_ollama_prompt_building() {
        let provider = OllamaProvider::new("http://localhost:11434", "llama3.2:3b", 5000);
        let request = AiRequest {
            user_input: "restart nginx".to_string(),
            available_capabilities: vec!["shell_exec".to_string(), "status_query".to_string()],
            peer_role: "admin".to_string(),
            system_context: Some("CPU: 45%, Memory: 72%".to_string()),
            history: vec![ChatMessage {
                role: ChatRole::User,
                content: "check status".to_string(),
                timestamp: "2026-02-27T10:00:00Z".to_string(),
            }],
        };

        let prompt = provider.build_prompt(&request);
        assert!(prompt.contains("shell_exec"));
        assert!(prompt.contains("admin"));
        assert!(prompt.contains("restart nginx"));
        assert!(prompt.contains("CPU: 45%"));
    }

    #[test]
    fn test_ollama_parse_valid_json() {
        let provider = OllamaProvider::new("http://localhost:11434", "llama3.2:3b", 5000);
        let json = r#"{"message": "Restarting nginx...", "intent": {"capability": "shell_exec", "command": "systemctl restart nginx", "args": [], "needs_confirmation": true}, "confidence": 0.95}"#;

        let response = provider.parse_response(json).unwrap();
        assert_eq!(response.message, "Restarting nginx...");
        assert!(response.intent.is_some());
        assert_eq!(response.confidence, 0.95);
        assert!(response.is_local);
    }

    #[test]
    fn test_ollama_parse_invalid_json() {
        let provider = OllamaProvider::new("http://localhost:11434", "llama3.2:3b", 5000);
        let text = "I don't understand that command.";

        let response = provider.parse_response(text).unwrap();
        assert_eq!(response.message, text);
        assert!(response.intent.is_none());
        assert_eq!(response.confidence, 0.3);
    }

    #[test]
    fn test_sensitive_keyword_detection() {
        let config = crate::config::AiConfig::default();
        let manager = AiManager::from_config(&config);
        assert!(manager.contains_sensitive("show me the password file"));
        assert!(manager.contains_sensitive("read private_key.pem"));
        assert!(!manager.contains_sensitive("check disk space"));
    }

    #[test]
    fn test_ai_manager_none_provider() {
        let config = crate::config::AiConfig {
            primary: "none".to_string(),
            ..Default::default()
        };
        let manager = AiManager::from_config(&config);

        assert!(manager.is_available());
        assert_eq!(manager.provider_name(), "none");
        assert!(manager.is_local());

        let request = AiRequest {
            user_input: "status".to_string(),
            available_capabilities: vec!["status_query".to_string()],
            peer_role: "owner".to_string(),
            system_context: None,
            history: vec![],
        };

        let response = manager.process(&request).unwrap();
        assert!(response.intent.is_some());
    }

    #[test]
    fn test_chat_message_serialization() {
        let msg = ChatMessage {
            role: ChatRole::User,
            content: "hello".to_string(),
            timestamp: "2026-02-27T10:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("User"));
        assert!(json.contains("hello"));

        let parsed: ChatMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.role, ChatRole::User);
    }

    #[test]
    fn test_parse_cloud_response_valid() {
        let json = r#"{"message": "Done!", "intent": null, "confidence": 0.9}"#;
        let response = parse_cloud_response(json, "openai").unwrap();
        assert_eq!(response.message, "Done!");
        assert!(response.intent.is_none());
        assert!(!response.is_local);
    }

    #[test]
    fn test_parse_url() {
        let parsed = parse_url("http://localhost:11434/api/generate").unwrap();
        assert_eq!(parsed.host, "localhost");
        assert_eq!(parsed.port, 11434);
        assert_eq!(parsed.path, "/api/generate");
    }
}

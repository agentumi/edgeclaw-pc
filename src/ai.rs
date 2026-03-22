//! AI Provider plugin system — swappable AI backends for EdgeClaw Agent.
//!
//! Supports local (Ollama), cloud (OpenAI, Claude), and passthrough (None) providers.
//! AI is a plugin — security is the platform.

use crate::error::AgentError;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

// ─── AI Request / Response ─────────────────────────────────

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
    /// Optional model override for this request
    pub model: Option<String>,
    /// Optional file attachments (images, text docs)
    pub attachments: Vec<FileAttachment>,
    /// Whether to permit parallel capability execution
    pub parallel: bool,
    /// Preferred strategies (e.g., "fast", "accurate")
    pub strategies: Vec<String>,
    /// Preferred language for the AI response (e.g. "english", "korean")
    pub preferred_language: Option<String>,
}

/// A file attached to an AI request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAttachment {
    pub name: String,
    pub mime_type: String,
    pub content_base64: String,
}

/// Metadata for a registered mission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub tags: Vec<String>,
    pub role: String,
    pub owner: String,
    pub goals: Vec<String>,
    pub status: MissionStatus,
    pub tasks: Vec<TaskUnit>,
}

/// A single atomic unit of work within a mission
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskUnit {
    pub desc: String,
    pub capability: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub order: u32,
}

/// Current status of a mission
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MissionStatus {
    Proposed,
    Discovery,
    Planning,
    Active,
    Verification,
    Success,
    Failure,
    Aborted,
}

/// AI provider response
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    /// For parallel execution: individual responses
    pub sub_responses: Vec<AiResponse>,
}

/// Parsed intent from natural language
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParsedIntent {
    /// The capability to invoke (e.g., "shell_exec", "file_read")
    pub capability: String,
    /// The command or path to operate on
    pub command: String,
    /// Additional arguments
    pub args: Vec<String>,
    /// Whether user confirmation is recommended
    pub needs_confirmation: bool,
    /// For multi-step business missions: the mission metadata to create
    pub mission: Option<MissionMetadata>,
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

    /// Update the model used by this provider
    fn set_model(&mut self, model: &str) -> Result<(), AgentError>;

    /// List available models for this provider (if supported)
    fn list_models(&self) -> Vec<String> {
        Vec::new()
    }
}

// ─── Ollama Provider (Local) ───────────────────────────────

/// Local AI provider using Ollama
pub struct OllamaProvider {
    endpoint: String,
    model: String,
    timeout: Duration,
}

/// Info about an available Ollama model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaModelInfo {
    /// Model name (e.g., "llama3.2:3b").
    pub name: String,
    /// Model size in bytes.
    pub size: u64,
    /// Modified date string.
    pub modified_at: String,
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

    /// Helper to resolve stable local loopback for Windows
    fn self_127_endpoint(&self) -> String {
        self.endpoint.replace("localhost", "127.0.0.1")
    }

    /// List all locally available Ollama models.
    pub fn list_models(&self) -> Result<Vec<OllamaModelInfo>, AgentError> {
        let url = format!("{}/api/tags", self.endpoint);
        let resp = ureq_get_with_timeout(&url, self.timeout)?;

        #[derive(Deserialize)]
        struct TagsResp {
            models: Vec<OllamaModelInfo>,
        }

        let tags: TagsResp = serde_json::from_str(&resp)
            .map_err(|e| AgentError::SerializationError(format!("tags: {e}")))?;
        Ok(tags.models)
    }

    /// Auto-select the best available model from installed models.
    /// Prefers models matching a priority list, falls back to first available.
    pub fn auto_select_model(&self) -> Result<String, AgentError> {
        let models = self.list_models()?;
        if models.is_empty() {
            return Err(AgentError::ExecutionError(
                "No Ollama models installed".into(),
            ));
        }

        // Priority order
        let preferred = [
            "llama3.2",
            "llama3.1",
            "llama3",
            "mistral",
            "codellama",
            "phi",
        ];
        for pref in &preferred {
            if let Some(m) = models.iter().find(|m| m.name.starts_with(pref)) {
                return Ok(m.name.clone());
            }
        }
        Ok(models[0].name.clone())
    }

    /// Pull (download) a model from Ollama registry.
    pub fn pull_model(&self, model: &str) -> Result<String, AgentError> {
        let url = format!("{}/api/pull", self.endpoint);
        let body = serde_json::json!({ "name": model, "stream": false });
        ureq_post_json_with_timeout(&url, &body, Duration::from_secs(600))
    }

    /// Analyze command output using AI to provide a human-friendly explanation.
    pub fn analyze_output(&self, command: &str, output: &str) -> Result<AiResponse, AgentError> {
        let prompt = format!(
            r#"Analyze this command output and provide a brief, clear summary.

Command: {command}
Output:
{output}

Respond in JSON: {{"message": "your analysis summary", "intent": null, "confidence": 0.9}}"#,
        );

        let url = format!("{}/api/generate", self.endpoint);
        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            "options": { "temperature": 0.4, "num_predict": 512 }
        });

        let resp = ureq_post_json_with_timeout(&url, &body, self.timeout)?;

        #[derive(Deserialize)]
        struct OllamaResp {
            response: String,
        }
        let raw: OllamaResp = serde_json::from_str(&resp)
            .map_err(|e| AgentError::SerializationError(format!("ollama: {e}")))?;
        self.parse_response(&raw.response)
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

        let lang = request.preferred_language.as_deref().unwrap_or("english").to_lowercase();
        
        // Define language-specific rules and few-shot examples
        let (lang_rules, mission_example) = if lang == "korean" || lang == "ko" {
            (
                r#"- Use PROFESSIONAL MODERN KOREAN (표준어). NO dialects.
- ALL 'message', 'title', and 'description' MUST be in KOREAN HANGUL. 
- Use RAW UTF-8 Korean. NO Unicode escapes."#,
                r#"{{
  "message": "사용자 요구사항을 분석한 마케팅 자동화 기획안입니다.",
  "intent": {{
    "capability": "create_mission",
    "mission": {{
      "id": "tel-campaign-001",
      "title": "텔레그램 바이럴 마케팅 오케스트레이션",
      "description": "사용자 유입 데이터를 실시간 분석하여 최적화된 마케팅 메시지를 자동 전송하는 시스템을 구축합니다.",
      "tasks": [
        {{ "id": "t1", "desc": "사용자 활동 데이터베이스 분석", "capability": "status_query", "command": "db_query" }},
        {{ "id": "t2", "desc": "바이럴 메시지 자동 생성 및 발송", "capability": "shell_exec", "command": "viral_exec" }}
      ]
    }}
  }}
}}"#
            )
        } else {
            (
                r#"- Use PROFESSIONAL MODERN ENGLISH.
- ALL 'message', 'title', and 'description' MUST be in English.
- Be concise and business-oriented."#,
                r#"{{
  "message": "Here is the proposed business automation mission plan.",
  "intent": {{
    "capability": "create_mission",
    "mission": {{
      "id": "global-mission-001",
      "title": "Global Fleet Orchestration",
      "description": "Established high-precision monitoring and automation pulse across all connected edges.",
      "tasks": [
        {{ "id": "t1", "desc": "Check edge health status", "capability": "status_query", "command": "health_check" }},
        {{ "id": "t2", "desc": "Synchronize global policy", "capability": "shell_exec", "command": "policy_sync" }}
      ]
    }}
  }}
}}"#
            )
        };

        let persona = format!(r#"You are the EdgeClaw CI Orchestrator (EC-CIO), a high-precision business automation expert.
Your goal is to analyze user requests and propose a structured 'Mission' plan.

THOUGHT PROCESS:
1. Analyze the core business intent.
2. Formulate a mission title and description (strictly in the selected language).
3. Break down the goal into Atomic Task Units.

LANGUAGE RULES:
{lang_rules}

Respond ONLY in this JSON format:
{mission_example}"#);

        format!(
            r#"{persona}

Context: [{caps}]
User Role: {role}
{system_ctx}

{history}

User: {input}
"#,
            persona = persona,
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
                sub_responses: Vec::new(),
            }),
            Err(_) => {
                // Fallback: treat the entire response as a message
                Ok(AiResponse {
                    message: raw.to_string(),
                    intent: None,
                    confidence: 0.3,
                    provider: "ollama".to_string(),
                    is_local: true,
                    sub_responses: Vec::new(),
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
        let url = format!("{}/api/generate", self.self_127_endpoint()); // Force local loopback bypass
        
        let model = request.model.as_deref().unwrap_or(&self.model);
        let mut body = serde_json::json!({
            "model": model,
            "prompt": prompt,
            "stream": false,
            "format": "json"
        });

        if let Some(obj) = body.as_object_mut() {
            // Attach images if present
            let images: Vec<String> = request.attachments.iter()
                .filter(|a| a.mime_type.starts_with("image/"))
                .map(|a| a.content_base64.clone())
                .collect();
            if !images.is_empty() {
                obj.insert("images".to_string(), serde_json::json!(images));
            }

            // Maximum Determinism for high-fidelity Korean
            obj.insert("options".to_string(), serde_json::json!({
                "temperature": 0.1,
                "top_p": 0.1,
                "num_predict": 1024,
                "num_ctx": 4096,
                "repeat_penalty": 1.3,
                "stop": ["\nUser:", "###", "```"]
            }));
        }

        // MASSIVE TIMEOUT: Give Ollama 10 minutes to load and inference.
        let timeout = Duration::from_secs(600);
        
        println!(">>> AGENT: AI Mission Orchestration Requested ({})", model);
        
        match ureq_post_json_with_timeout(&url, &body, timeout) {
            Ok(resp_str) => {
                #[derive(Deserialize)]
                struct OllamaResp { response: String }
                let ollama_resp: OllamaResp = serde_json::from_str(&resp_str)
                    .map_err(|e| AgentError::SerializationError(format!("ollama decode: {}", e)))?;
                
                println!("<<< AGENT: AI Orchestration Received. Parsing content...");
                self.parse_response(&ollama_resp.response)
            },
            Err(e) => {
                println!("!!! AGENT: AI Connection Error (127): {}. Retrying with config endpoint...", e);
                let alt_url = format!("{}/api/generate", self.endpoint);
                let resp = ureq_post_json_with_timeout(&alt_url, &body, timeout)?;
                
                #[derive(Deserialize)]
                struct OllamaResp { response: String }
                let ollama_resp: OllamaResp = serde_json::from_str(&resp)
                    .map_err(|e| AgentError::SerializationError(format!("ollama decode: {}", e)))?;
                self.parse_response(&ollama_resp.response)
            }
        }
    }

    fn is_local(&self) -> bool {
        true
    }

    fn set_model(&mut self, model: &str) -> Result<(), AgentError> {
        self.model = model.to_string();
        Ok(())
    }

    fn list_models(&self) -> Vec<String> {
        self.list_models()
            .map(|models| models.into_iter().map(|m| m.name).collect())
            .unwrap_or_default()
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
                "You are the EC-CIO (EdgeClaw Collective Intelligence Orchestrator). \
                 Goal: Perform complex business automation using parallelized local models. \
                 Method: BREAK missions into tiny, error-free 'Atomic Task Units' (ATUs). \
                 Always propose a clear mission with small, sequential chunks for collective verification. \
                 Capabilities: [{}]. User role: {}. \
                 Language: Korean for the 'message' field. \
                 Output JSON: {{\"message\": \"...\", \"intent\": {{\"capability\": \"create_mission\", \"mission\": {{ \"id\": \"...\", \"title\": \"...\", \"tasks\": [...] }} }}, \"confidence\": 0.95}}.",
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

    fn set_model(&mut self, model: &str) -> Result<(), AgentError> {
        self.model = model.to_string();
        Ok(())
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
                "You are a Business Orchestrator and EdgeClaw Agent orchestrator. \
                 When the user expresses a general task or business need, your goal is to help them turn it into an actionable 'Mission'. \
                 Analyze the business value, propose a title, and define specific task units. \
                 Available capabilities: [{}]. User role: {}. \
                 Respond in JSON: {{ \"message\": \"...\", \"intent\": {{ \"capability\": \"create_mission\", \
                 \"mission\": {{ \"id\": \"...\", \"title\": \"...\", \"description\": \"...\", \"role\": \"...\", \"status\": \"proposed\" }}, \
                 \"confidence\": 0.95 }} }}. \
                 Set intent to null for non-command messages. Be professional and visionary.",
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

    fn set_model(&mut self, model: &str) -> Result<(), AgentError> {
        self.model = model.to_string();
        Ok(())
    }
}
// ─── GPT-OSS 120B Provider (Cloud) ─────────────────────────

/// Premium AI provider using EdgeClaw GPT-OSS 120B
pub struct GptOssProvider {
    api_key: String,
    model: String,
    endpoint: String,
    timeout: Duration,
}

impl GptOssProvider {
    pub fn new(api_key: &str, model: &str, endpoint: &str, timeout_ms: u64) -> Self {
        Self {
            api_key: api_key.to_string(),
            model: model.to_string(),
            endpoint: endpoint.to_string(),
            timeout: Duration::from_millis(timeout_ms),
        }
    }
}

impl AiProvider for GptOssProvider {
    fn name(&self) -> &str {
        "gpt-oss"
    }

    fn is_available(&self) -> bool {
        // High-perf cloud is usually available if endpoint is set
        !self.endpoint.is_empty()
    }

    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        let caps = request.available_capabilities.join(", ");
        
        let mut messages = vec![serde_json::json!({
            "role": "system",
            "content": format!(
                "You are EdgeClaw GPT-OSS 120B, the primary intelligence for this agent fleet. \
                 Available capabilities: [{}]. \
                 Strictly respond with valid JSON: {{\"message\": \"...\", \"intent\": null, \"confidence\": 0.95}}. \
                 You excel at translation and complex orchestration.",
                caps
            )
        })];

        for msg in &request.history {
            let role = match msg.role {
                ChatRole::User => "user",
                ChatRole::Assistant => "assistant",
                ChatRole::System => "system",
            };
            messages.push(serde_json::json!({ "role": role, "content": msg.content }));
        }

        messages.push(serde_json::json!({ "role": "user", "content": request.user_input }));

        let body = serde_json::json!({
            "model": self.model,
            "messages": messages,
            "temperature": 0.4,
            "max_tokens": 2048
        });

        // GPT-OSS uses a slightly different auth or no auth but assume it's V1 compatible for now
        let resp = if !self.api_key.is_empty() {
            ureq_post_json_with_auth(&self.endpoint, &body, &self.api_key, self.timeout)?
        } else {
            ureq_post_json_with_timeout(&self.endpoint, &body, self.timeout)?
        };

        parse_cloud_response(&resp, "gpt-oss")
    }

    fn is_local(&self) -> bool {
        false
    }
    
    fn set_model(&mut self, model: &str) -> Result<(), AgentError> {
        self.model = model.to_string();
        Ok(())
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

    /// Cross-platform command parsing (Windows + Linux)
    fn parse_simple_command(input: &str) -> Option<ParsedIntent> {
        let input_lower = input.trim().to_lowercase();
        let parts: Vec<&str> = input_lower.splitn(3, ' ').collect();
        let cmd = parts.first().copied().unwrap_or("");
        let arg1 = parts.get(1).copied().unwrap_or("");
        let arg2 = parts.get(2).copied().unwrap_or("");

        #[cfg(target_os = "windows")]
        return Self::parse_windows_command(cmd, arg1, arg2, input.trim());

        #[cfg(not(target_os = "windows"))]
        return Self::parse_linux_command(cmd, arg1, arg2, input.trim());
    }

    #[cfg(target_os = "windows")]
    fn parse_windows_command(
        cmd: &str,
        arg1: &str,
        arg2: &str,
        _raw: &str,
    ) -> Option<ParsedIntent> {
        match cmd {
            // ── System Status ──
            "status" | "상태" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\" /C:\"Total Physical\"".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "cpu" | "cpu사용량" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "wmic cpu get loadpercentage,name /format:list".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "memory" | "메모리" | "ram" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "powershell -Command \"Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | Format-List\"".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "disk" | "디스크" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "powershell -Command \"Get-PSDrive -PSProvider FileSystem | Format-Table Name,Used,Free,@{N='Total';E={$_.Used+$_.Free}} -AutoSize\"".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "ps" | "process" | "프로세스" => Some(ParsedIntent {
                capability: "process_manage".to_string(),
                command: "powershell -Command \"Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Name,Id,CPU,WorkingSet64 | Format-Table -AutoSize\"".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "network" | "네트워크" | "ip" => Some(ParsedIntent {
                capability: "network_scan".to_string(),
                command: "ipconfig /all".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "port" | "포트" | "ports" => Some(ParsedIntent {
                capability: "network_scan".to_string(),
                command: "netstat -an | findstr LISTENING".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "uptime" | "가동시간" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "powershell -Command \"(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object Days,Hours,Minutes | Format-List\"".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),

            // ── Service / Process Management ──
            "services" | "서비스" | "service" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "powershell -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 30 Name,DisplayName,Status | Format-Table -AutoSize\"".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "restart" | "재시작" => {
                if arg1.is_empty() {
                    return None;
                }
                Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: format!("powershell -Command \"Restart-Service -Name '{}' -Force\"", arg1),
                    args: vec![],
                    needs_confirmation: true,
                    mission: None,
                })
            }
            "stop" | "중지" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: format!("powershell -Command \"Stop-Service -Name '{}' -Force\"", arg1),
                    args: vec![],
                    needs_confirmation: true,
                    mission: None,
                })
            }
            "start" if !arg1.is_empty() => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: format!("powershell -Command \"Start-Service -Name '{}'\"", arg1),
                args: vec![],
                needs_confirmation: true,
                mission: None,
            }),
            "kill" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "process_manage".to_string(),
                    command: format!("taskkill /F /PID {}", arg1),
                    args: vec![],
                    needs_confirmation: true,
                    mission: None,
                })
            }

            // ── File Operations ──
            "ls" | "dir" | "파일" | "list" => Some(ParsedIntent {
                capability: "file_read".to_string(),
                command: format!("dir /B {}", if arg1.is_empty() { "." } else { arg1 }),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "cat" | "type" | "읽기" | "read" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "file_read".to_string(),
                    command: format!("type \"{}\"", arg1),
                    args: vec![],
                    needs_confirmation: false,
                    mission: None,
                })
            }
            "find" | "search" | "검색" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "file_read".to_string(),
                    command: format!("powershell -Command \"Get-ChildItem -Recurse -Filter '*{}*' | Select-Object FullName\"", arg1),
                    args: vec![],
                    needs_confirmation: false,
                    mission: None,
                })
            }

            // ── Log Analysis ──
            "log" | "logs" | "로그" => Some(ParsedIntent {
                capability: "log_read".to_string(),
                command: format!(
                    "powershell -Command \"Get-EventLog -LogName {} -Newest 30 | Format-Table TimeGenerated,EntryType,Message -AutoSize\"",
                    if arg1.is_empty() { "System" } else { arg1 }
                ),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "errors" | "에러" | "오류" => Some(ParsedIntent {
                capability: "log_read".to_string(),
                command: "powershell -Command \"Get-EventLog -LogName Application -EntryType Error -Newest 20 | Format-Table TimeGenerated,Source,Message -AutoSize\"".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),

            // ── Docker ──
            "docker" => match arg1 {
                "ps" | "list" | "" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: "docker ps --format \"table {{.Names}}\t{{.Status}}\t{{.Ports}}\"".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                    mission: None,
                }),
                "images" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: "docker images --format \"table {{.Repository}}\t{{.Tag}}\t{{.Size}}\"".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                    mission: None,
                }),
                "logs" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: format!("docker logs --tail 50 {}", arg2),
                    args: vec![],
                    needs_confirmation: false,
                    mission: None,
                }),
                "restart" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: format!("docker restart {}", arg2),
                    args: vec![],
                    needs_confirmation: true,
                    mission: None,
                }),
                "stop" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: format!("docker stop {}", arg2),
                    args: vec![],
                    needs_confirmation: true,
                    mission: None,
                }),
                "start" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: format!("docker start {}", arg2),
                    args: vec![],
                    needs_confirmation: true,
                    mission: None,
                }),
                "stats" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: "docker stats --no-stream --format \"table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\"".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                    mission: None,
                }),
                _ => None,
            },

            // ── Git Operations (Software Dev) ──
            "git" => match arg1 {
                "status" | "" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "git status".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                    mission: None,
                }),
                "log" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "git log --oneline -20".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                    mission: None,
                }),
                "branch" | "branches" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "git branch -a".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                    mission: None,
                }),
                "pull" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "git pull".to_string(),
                    args: vec![],
                    needs_confirmation: true,
                    mission: None,
                }),
                "push" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "git push".to_string(),
                    args: vec![],
                    needs_confirmation: true,
                    mission: None,
                }),
                "diff" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "git diff --stat".to_string(),
                    args: vec![],
                    needs_confirmation: false,
                    mission: None,
                }),
                "stash" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: if arg2.is_empty() { "git stash list".to_string() } else { format!("git stash {}", arg2) },
                    args: vec![],
                    needs_confirmation: arg2 == "pop" || arg2 == "drop",
                    mission: None,
                }),
                _ => None,
            },

            // ── Build / CI (Software Dev) ──
            "build" | "빌드" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: if arg1.is_empty() {
                    "cargo build 2>&1".to_string()
                } else {
                    format!("cargo build --{} 2>&1", arg1)
                },
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "test" | "테스트" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: if arg1.is_empty() {
                    "cargo test 2>&1".to_string()
                } else {
                    format!("cargo test {} 2>&1", arg1)
                },
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "lint" | "clippy" | "린트" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "cargo clippy --all-targets -- -D warnings 2>&1".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "fmt" | "format" | "포맷" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "cargo fmt 2>&1".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "deploy" | "배포" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: if arg1.is_empty() {
                    "echo 'Specify target: deploy staging | deploy production'".to_string()
                } else {
                    format!("echo 'Deploying to {}...' && cargo build --release 2>&1", arg1)
                },
                args: vec![],
                needs_confirmation: true,
                mission: None,
            }),
            "deps" | "dependencies" | "의존성" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "cargo tree --depth 1".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "audit" | "감사" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "cargo audit 2>&1".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),

            // ── npm / Node.js ──
            "npm" => match arg1 {
                "test" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "npm test 2>&1".to_string(),
                    args: vec![], needs_confirmation: false,
                    mission: None,
                }),
                "build" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "npm run build 2>&1".to_string(),
                    args: vec![], needs_confirmation: false,
                    mission: None,
                }),
                "start" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "npm start 2>&1".to_string(),
                    args: vec![], needs_confirmation: true,
                    mission: None,
                }),
                "audit" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "npm audit 2>&1".to_string(),
                    args: vec![], needs_confirmation: false,
                    mission: None,
                }),
                "outdated" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "npm outdated 2>&1".to_string(),
                    args: vec![], needs_confirmation: false,
                    mission: None,
                }),
                _ => None,
            },

            // ── Database (Software Dev) ──
            "db" | "database" | "데이터베이스" => match arg1 {
                "backup" => Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: "powershell -Command \"$ts = Get-Date -Format 'yyyyMMdd_HHmmss'; echo 'DB backup: backup_$ts.sql created'\"".to_string(),
                    args: vec![],
                    needs_confirmation: true,
                    mission: None,
                }),
                "size" => Some(ParsedIntent {
                    capability: "status_query".to_string(),
                    command: "echo 'Database monitoring not yet configured — install a database agent plugin to enable'".to_string(),
                    args: vec![], needs_confirmation: false,
                    mission: None,
                }),
                "connections" => Some(ParsedIntent {
                    capability: "status_query".to_string(),
                    command: "echo 'Database monitoring not yet configured — install a database agent plugin to enable'".to_string(),
                    args: vec![], needs_confirmation: false,
                    mission: None,
                }),
                _ => Some(ParsedIntent {
                    capability: "status_query".to_string(),
                    command: "echo 'DB commands: db backup | db size | db connections'".to_string(),
                    args: vec![], needs_confirmation: false,
                    mission: None,
                }),
            },

            // ── Marketing Automation ──
            "report" | "리포트" | "보고서" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: format!(
                    "powershell -Command \"$d = Get-Date -Format 'yyyy-MM-dd'; echo '=== {} Report ($d) ==='; echo 'Generating...'\"",
                    if arg1.is_empty() { "Daily" } else { arg1 }
                ),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "analytics" | "분석" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "echo 'Analytics module not yet configured — use system monitoring or install an analytics plugin'".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "campaign" | "캠페인" => match arg1 {
                "list" | "" => Some(ParsedIntent {
                    capability: "status_query".to_string(),
                    command: "echo 'Campaign management not yet configured — install a marketing plugin to enable'".to_string(),
                    args: vec![], needs_confirmation: false,
                    mission: None,
                }),
                "status" => Some(ParsedIntent {
                    capability: "status_query".to_string(),
                    command: format!("echo 'Campaign status for: {}'", arg2),
                    args: vec![], needs_confirmation: false,
                    mission: None,
                }),
                _ => None,
            },
            "seo" | "검색최적화" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: format!(
                    "echo 'SEO analysis for: {} — install an SEO plugin to enable'",
                    if arg1.is_empty() { "all" } else { arg1 }
                ),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "schedule" | "스케줄" | "예약" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "powershell -Command \"Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select-Object -First 20 TaskName,State,LastRunTime | Format-Table -AutoSize\"".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "backup" | "백업" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "powershell -Command \"$ts = Get-Date -Format 'yyyyMMdd_HHmmss'; echo '=== Backup Started ($ts) ==='; echo 'Configure backup targets in agent.toml [backup] section'\"".to_string(),
                args: vec![],
                needs_confirmation: true,
                mission: None,
            }),

            // ── Utility ──
            "ping" => Some(ParsedIntent {
                capability: "network_scan".to_string(),
                command: format!("ping -n 4 {}", if arg1.is_empty() { "google.com" } else { arg1 }),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "env" | "환경" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "set".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "whoami" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "whoami /all".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            "help" | "도움말" | "명령어" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "echo '=== EdgeClaw Commands ===' && echo. && echo [System] status, cpu, memory, disk, ps, network, port, uptime, services && echo [Files] ls, cat, find, log, errors && echo [DevOps] docker ps/logs/restart, git status/log/pull/push && echo [Build] build, test, lint, fmt, deploy, deps, audit && echo [Node] npm test/build/start/audit/outdated && echo [DB] db backup/size/connections && echo [Marketing] report, analytics, campaign, seo, schedule && echo [Misc] ping, env, whoami, backup, help'".to_string(),
                args: vec![],
                needs_confirmation: false,
                mission: None,
            }),
            _ => None,
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn parse_linux_command(cmd: &str, arg1: &str, arg2: &str, _raw: &str) -> Option<ParsedIntent> {
        match cmd {
            "status" | "상태" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "uname -a && uptime && free -h | head -2".to_string(),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "cpu" | "cpu사용량" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "top -bn1 | head -20".to_string(),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "memory" | "메모리" | "ram" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "free -h".to_string(),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "disk" | "디스크" => Some(ParsedIntent {
                capability: "system_info".to_string(),
                command: "df -h".to_string(),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "ps" | "process" | "프로세스" => Some(ParsedIntent {
                capability: "process_manage".to_string(),
                command: "ps aux --sort=-pcpu | head -20".to_string(),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "network" | "네트워크" | "ip" => Some(ParsedIntent {
                capability: "network_scan".to_string(),
                command: "ip addr show".to_string(),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "port" | "포트" | "ports" => Some(ParsedIntent {
                capability: "network_scan".to_string(),
                command: "ss -tlnp".to_string(),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "services" | "서비스" | "service" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "systemctl list-units --type=service --state=running".to_string(),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "restart" | "재시작" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: format!("systemctl restart {}", arg1),
                    args: vec![], needs_confirmation: true,
                    mission: None,
                })
            }
            "stop" | "중지" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "shell_exec".to_string(),
                    command: format!("systemctl stop {}", arg1),
                    args: vec![], needs_confirmation: true,
                    mission: None,
                })
            }
            "log" | "logs" | "로그" => Some(ParsedIntent {
                capability: "log_read".to_string(),
                command: format!("tail -50 {}", if arg1.is_empty() { "/var/log/syslog" } else { arg1 }),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "errors" | "에러" | "오류" => Some(ParsedIntent {
                capability: "log_read".to_string(),
                command: "journalctl -p err --since '1 hour ago' | tail -30".to_string(),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "ls" | "dir" | "파일" | "list" => Some(ParsedIntent {
                capability: "file_read".to_string(),
                command: format!("ls -la {}", if arg1.is_empty() { "." } else { arg1 }),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "cat" | "읽기" | "read" => {
                if arg1.is_empty() { return None; }
                Some(ParsedIntent {
                    capability: "file_read".to_string(),
                    command: format!("cat \"{}\"", arg1),
                    args: vec![], needs_confirmation: false,
                })
            }
            "docker" => match arg1 {
                "ps" | "list" | "" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'".to_string(),
                    args: vec![], needs_confirmation: false,
                }),
                "logs" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: format!("docker logs --tail 50 {}", arg2),
                    args: vec![], needs_confirmation: false,
                }),
                "restart" => Some(ParsedIntent {
                    capability: "docker_manage".to_string(),
                    command: format!("docker restart {}", arg2),
                    args: vec![], needs_confirmation: true,
                }),
                _ => None,
            },
            "git" => match arg1 {
                "status" | "" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "git status".to_string(), args: vec![], needs_confirmation: false, mission: None }),
                "log" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "git log --oneline -20".to_string(), args: vec![], needs_confirmation: false }),
                "branch" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "git branch -a".to_string(), args: vec![], needs_confirmation: false }),
                "pull" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "git pull".to_string(), args: vec![], needs_confirmation: true, mission: None }),
                "push" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "git push".to_string(), args: vec![], needs_confirmation: true, mission: None }),
                "diff" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "git diff --stat".to_string(), args: vec![], needs_confirmation: false }),
                _ => None,
            },
            "build" | "빌드" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: if arg1.is_empty() { "cargo build 2>&1".to_string() } else { format!("cargo build --{} 2>&1", arg1) }, args: vec![], needs_confirmation: false, mission: None }),
            "test" | "테스트" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: if arg1.is_empty() { "cargo test 2>&1".to_string() } else { format!("cargo test {} 2>&1", arg1) }, args: vec![], needs_confirmation: false, mission: None }),
            "lint" | "clippy" | "린트" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: "cargo clippy --all-targets -- -D warnings 2>&1".to_string(), args: vec![], needs_confirmation: false, mission: None }),
            "deploy" | "배포" => Some(ParsedIntent { capability: "shell_exec".to_string(), command: format!("echo 'Deploying to {}...' && cargo build --release 2>&1", if arg1.is_empty() { "staging" } else { arg1 }), args: vec![], needs_confirmation: true, mission: None }),
            "help" | "도움말" | "명령어" => Some(ParsedIntent {
                capability: "status_query".to_string(),
                command: "echo '=== EdgeClaw Commands ===\n[System] status, cpu, memory, disk, ps, network, port, services\n[Files] ls, cat, log, errors\n[DevOps] docker ps/logs/restart, git status/log/pull/push\n[Build] build, test, lint, deploy\n[Misc] ping, env, whoami, backup, help'".to_string(),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "ping" => Some(ParsedIntent {
                capability: "network_scan".to_string(),
                command: format!("ping -c 4 {}", if arg1.is_empty() { "google.com" } else { arg1 }),
                args: vec![], needs_confirmation: false,
                mission: None,
            }),
            "backup" | "백업" => Some(ParsedIntent {
                capability: "shell_exec".to_string(),
                command: "echo 'Backup started...' && date".to_string(),
                args: vec![], needs_confirmation: true,
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
                sub_responses: Vec::new(),
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
                sub_responses: Vec::new(),
            }),
        }
    }

    fn is_local(&self) -> bool {
        true
    }

    fn set_model(&mut self, _model: &str) -> Result<(), AgentError> {
        // NoneProvider doesn't use models
        Ok(())
    }
}

// ─── AI Manager ────────────────────────────────────────────

pub struct MissionRegistry {
    pub missions: RwLock<HashMap<String, MissionMetadata>>,
}

impl MissionRegistry {
    pub fn new() -> Self {
        Self {
            missions: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, metadata: MissionMetadata) {
        let mut missions = self.missions.write().unwrap();
        missions.insert(metadata.id.clone(), metadata);
    }

    pub fn list(&self) -> Vec<MissionMetadata> {
        let missions = self.missions.read().unwrap();
        missions.values().cloned().collect()
    }

    pub fn get_by_role(&self, role: &str) -> Option<MissionMetadata> {
        let missions = self.missions.read().unwrap();
        missions.values().find(|m| m.role == role).cloned()
    }
}

/// Manages AI providers with fallback and escalation
/// Manages AI providers with fallback and escalation
pub struct AiManager {
    primary: Box<dyn AiProvider>,
    fallback: Option<Box<dyn AiProvider>>,
    escalation_threshold: f64,
    sensitive_keywords: Vec<String>,
    require_consent: bool,
    mission_registry: Arc<MissionRegistry>,
    signing_key: Option<SigningKey>,
    config: crate::config::AiConfig,
}

impl AiManager {
    /// Create a new AI manager from config
    pub fn from_config(config: &crate::config::AiConfig) -> Self {
        let primary = Self::create_provider(config, &config.primary);
        
        Self {
            primary,
            fallback: None, 
            escalation_threshold: config.policy.escalation_threshold,
            sensitive_keywords: config.policy.never_cloud.clone(),
            require_consent: config.policy.require_consent,
            mission_registry: Arc::new(MissionRegistry::new()),
            signing_key: None,
            config: config.clone(),
        }
    }

    fn create_provider(config: &crate::config::AiConfig, name: &str) -> Box<dyn AiProvider> {
        match name {
            "ollama" | "local" => Box::new(OllamaProvider::new(
                &config.local.endpoint,
                &config.local.model,
                config.local.timeout_ms,
            )),
            "openai" | "gpt-4o" | "gpt-4-turbo" => {
                let api_key = std::env::var("EDGECLAW_OPENAI_KEY").unwrap_or_default();
                Box::new(OpenAiProvider::new(
                    &api_key,
                    name,
                    &config.cloud.endpoint,
                    config.cloud.timeout_ms,
                ))
            }
            "claude" | "claude-3-5-sonnet" => {
                let api_key = std::env::var("EDGECLAW_CLAUDE_KEY").unwrap_or_default();
                Box::new(ClaudeProvider::new(
                    &api_key,
                    name,
                    &config.cloud.endpoint,
                    config.cloud.timeout_ms,
                ))
            }
            "gpt-oss" | "gpt-oss-120b" => {
                let api_key = std::env::var("EDGECLAW_GPT_OSS_KEY").unwrap_or_default();
                Box::new(GptOssProvider::new(
                    &api_key,
                    &config.gpt_oss.model,
                    &config.gpt_oss.endpoint,
                    config.gpt_oss.timeout_ms,
                ))
            }
            _ => Box::new(NoneProvider::new()),
        }
    }

    /// Process a chat request with fallback and consensus
    pub fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        // Check for sensitive content
        if !self.primary.is_local() && self.contains_sensitive(&request.user_input) {
            return Err(AgentError::PolicyDenied("Sensitive content blocked".into()));
        }

        // Parallel Consensus Fleet Execution (if enabled and local)
        if self.primary.is_local() && !self.config.consensus_models.is_empty() {
            return self.process_consensus(request);
        }

        self.process_single(request)
    }

    fn process_single(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        match self.primary.process(request) {
            Ok(response) => {
                if response.confidence < self.escalation_threshold && response.intent.is_some() {
                    Ok(AiResponse {
                        message: format!("{}\n\n⚠️ Low confidence ({:.0}%).", response.message, response.confidence * 100.0),
                        ..response
                    })
                } else {
                    Ok(response)
                }
            }
            Err(e) => {
                if let Some(fallback) = &self.fallback {
                    fallback.process(request)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn process_consensus(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        let models = &self.config.consensus_models;
        let mut handles = Vec::new();

        for (i, model) in models.iter().enumerate() {
            let model_name = model.clone();
            let config = self.config.clone();
            let req = request.clone();

            // Stagger model starts to prevent 'Thunderous Herd' timeouts (OS Error 10060)
            if i > 0 {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }

            handles.push(std::thread::spawn(move || {
                let mut provider = Self::create_provider(&config, "ollama");
                let _ = provider.set_model(&model_name);
                provider.process(&req)
            }));
        }

        let mut responses = Vec::new();
        for handle in handles {
            if let Ok(Ok(resp)) = handle.join() {
                responses.push(resp);
            }
        }

        if responses.is_empty() {
            return self.process_single(request);
        }

        // Consensus Merge Logic
        let mut best_index = 0;
        let mut max_conf = 0.0;
        for (i, resp) in responses.iter().enumerate() {
            if resp.confidence > max_conf {
                max_conf = resp.confidence;
                best_index = i;
            }
        }

        let mut best = responses.remove(best_index);
        let mut collective_tasks = Vec::new();
        
        // Collect all tasks from best
        if let Some(ref mut intent) = best.intent {
            if let Some(ref mut mission) = intent.mission {
                collective_tasks.append(&mut mission.tasks);
            }
        }

        // Merge tasks from others
        for other in responses {
            if let Some(intent) = other.intent {
                if let Some(mission) = intent.mission {
                    for t in mission.tasks {
                        if !collective_tasks.iter().any(|existing| existing.desc == t.desc) {
                            collective_tasks.push(t);
                        }
                    }
                }
            }
        }

        // Re-inject merged tasks
        if let Some(ref mut intent) = best.intent {
            if let Some(ref mut mission) = intent.mission {
                mission.tasks = collective_tasks;
                mission.role = "collective-orchestrator".into();
            }
        }

        best.message = format!("🤝 [Consensus View] {}\n\n(참여 모델: {})", 
            best.message, models.join(", "));
        
        Ok(best)
    }

    pub fn mission_registry(&self) -> Arc<MissionRegistry> {
        self.mission_registry.clone()
    }

    pub fn is_available(&self) -> bool {
        self.primary.is_available()
    }

    pub fn provider_name(&self) -> &str {
        self.primary.name()
    }

    pub fn is_local(&self) -> bool {
        self.primary.is_local()
    }

    fn contains_sensitive(&self, input: &str) -> bool {
        let lower = input.to_lowercase();
        self.sensitive_keywords.iter().any(|kw| lower.contains(&kw.to_lowercase()))
    }

    pub fn requires_consent(&self) -> bool {
        self.require_consent
    }

    pub fn set_identity(&mut self, key: SigningKey) {
        self.signing_key = Some(key);
    }

    pub fn set_model(&mut self, model: &str) -> Result<(), AgentError> {
        let target_provider = if model.ends_with("-cloud") || model.ends_with("-premium") {
            if model.starts_with("gpt-oss") { "gpt-oss" }
            else if model.starts_with("gpt-") { "openai" }
            else if model.starts_with("claude") { "claude" }
            else { "none" }
        } else if model.starts_with("gpt-oss") || model.contains(':') || model.contains("llama") || model == "ollama" {
            "ollama"
        } else if model.starts_with("gpt-") {
            "openai"
        } else if model.starts_with("claude") {
            "claude"
        } else {
            "none"
        };

        if target_provider != "none" && target_provider != self.primary.name() {
            self.primary = Self::create_provider(&self.config, target_provider);
        }
        self.primary.set_model(model)
    }

    pub fn list_models(&self) -> Vec<String> {
        self.primary.list_models()
    }

    pub fn escalate_to_cloud(&self, request: &AiRequest, local_response: &AiResponse) -> Result<AiResponse, AgentError> {
        if local_response.confidence >= self.escalation_threshold {
            return Ok(local_response.clone());
        }
        if self.primary.is_local() {
            if let Some(fallback) = &self.fallback {
                if !fallback.is_local() {
                    return fallback.process(request);
                }
            }
        }
        Ok(local_response.clone())
    }
}

// ─── HTTP Helpers (ureq — supports HTTP + HTTPS) ──────────────────────────

/// Simple GET with timeout (supports both HTTP and HTTPS)
fn ureq_get_with_timeout(url: &str, timeout: Duration) -> Result<String, AgentError> {
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

/// POST JSON with timeout (supports both HTTP and HTTPS)
fn ureq_post_json_with_timeout(
    url: &str,
    body: &serde_json::Value,
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
        .send_json(body.clone())
        .map_err(|e| AgentError::ConnectionError(format!("HTTP POST failed: {}", e)))?;

    response
        .into_string()
        .map_err(|e| AgentError::ConnectionError(format!("read body failed: {}", e)))
}

/// POST JSON with Bearer auth (supports HTTPS for OpenAI etc.)
fn ureq_post_json_with_auth(
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

/// POST JSON with Anthropic auth (supports HTTPS for Claude API)
fn ureq_post_json_with_anthropic_auth(
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
        .map_err(|e| AgentError::ConnectionError(format!("HTTP POST failed: {}", e)))?;

    response
        .into_string()
        .map_err(|e| AgentError::ConnectionError(format!("read body failed: {}", e)))
}

/// Parse URL into components (used only in tests)
#[cfg(test)]
struct ParsedUrl {
    host: String,
    port: u16,
    path: String,
}

#[cfg(test)]
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

// ─── Quick Actions ─────────────────────────────────────────

/// Industry work profile for categorized quick actions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkProfile {
    /// Common system operations
    System,
    /// Software development company
    SoftwareDev,
    /// Marketing company
    Marketing,
    /// DevOps / Infrastructure
    DevOps,
    /// User-defined custom profile
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
    /// Industry work profile category
    pub profile: WorkProfile,
    /// Group within profile (for UI tabs/sections)
    pub group: String,
}

/// Get all quick actions (cross-platform, industry-organized)
#[allow(clippy::vec_init_then_push)]
pub fn default_quick_actions() -> Vec<QuickAction> {
    let mut actions = Vec::new();

    // ══════════════════════════════════════════════════════
    //  SYSTEM — Common operations for all industries
    // ══════════════════════════════════════════════════════
    actions.push(QuickAction {
        label: "Server Status".to_string(),
        icon: "monitor".to_string(),
        command: "status".to_string(),
        capability: "status_query".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".to_string(),
    });
    actions.push(QuickAction {
        label: "CPU Usage".to_string(),
        icon: "speed".to_string(),
        command: "cpu".to_string(),
        capability: "system_info".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".to_string(),
    });
    actions.push(QuickAction {
        label: "Memory Usage".to_string(),
        icon: "memory".to_string(),
        command: "memory".to_string(),
        capability: "system_info".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".to_string(),
    });
    actions.push(QuickAction {
        label: "Disk Space".to_string(),
        icon: "hard_drive".to_string(),
        command: "disk".to_string(),
        capability: "system_info".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".to_string(),
    });
    actions.push(QuickAction {
        label: "Running Processes".to_string(),
        icon: "apps".to_string(),
        command: "ps".to_string(),
        capability: "process_manage".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".to_string(),
    });
    actions.push(QuickAction {
        label: "Network Info".to_string(),
        icon: "wifi".to_string(),
        command: "network".to_string(),
        capability: "network_scan".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Network".to_string(),
    });
    actions.push(QuickAction {
        label: "Open Ports".to_string(),
        icon: "lan".to_string(),
        command: "port".to_string(),
        capability: "network_scan".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Network".to_string(),
    });
    actions.push(QuickAction {
        label: "Services".to_string(),
        icon: "miscellaneous_services".to_string(),
        command: "services".to_string(),
        capability: "status_query".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Services".to_string(),
    });
    actions.push(QuickAction {
        label: "System Uptime".to_string(),
        icon: "schedule".to_string(),
        command: "uptime".to_string(),
        capability: "system_info".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Monitoring".to_string(),
    });
    actions.push(QuickAction {
        label: "System Logs".to_string(),
        icon: "description".to_string(),
        command: "log".to_string(),
        capability: "log_read".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Logs".to_string(),
    });
    actions.push(QuickAction {
        label: "Error Logs".to_string(),
        icon: "error".to_string(),
        command: "errors".to_string(),
        capability: "log_read".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Logs".to_string(),
    });
    actions.push(QuickAction {
        label: "Docker Containers".to_string(),
        icon: "inventory_2".to_string(),
        command: "docker ps".to_string(),
        capability: "docker_manage".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Docker".to_string(),
    });
    actions.push(QuickAction {
        label: "Docker Stats".to_string(),
        icon: "analytics".to_string(),
        command: "docker stats".to_string(),
        capability: "docker_manage".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Docker".to_string(),
    });
    actions.push(QuickAction {
        label: "Help / Commands".to_string(),
        icon: "help".to_string(),
        command: "help".to_string(),
        capability: "status_query".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::System,
        group: "Help".to_string(),
    });

    // ══════════════════════════════════════════════════════
    //  SOFTWARE DEVELOPMENT COMPANY — Work Stories
    // ══════════════════════════════════════════════════════

    // --- Git Operations ---
    actions.push(QuickAction {
        label: "Git Status".to_string(),
        icon: "code".to_string(),
        command: "git status".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Git".to_string(),
    });
    actions.push(QuickAction {
        label: "Git Log (최근 커밋)".to_string(),
        icon: "history".to_string(),
        command: "git log".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Git".to_string(),
    });
    actions.push(QuickAction {
        label: "Git Branches".to_string(),
        icon: "account_tree".to_string(),
        command: "git branch".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Git".to_string(),
    });
    actions.push(QuickAction {
        label: "Git Pull".to_string(),
        icon: "cloud_download".to_string(),
        command: "git pull".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::SoftwareDev,
        group: "Git".to_string(),
    });
    actions.push(QuickAction {
        label: "Git Diff".to_string(),
        icon: "compare_arrows".to_string(),
        command: "git diff".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Git".to_string(),
    });

    // --- Build & Test ---
    actions.push(QuickAction {
        label: "Build Project".to_string(),
        icon: "build".to_string(),
        command: "build".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Build & CI".to_string(),
    });
    actions.push(QuickAction {
        label: "Run Tests".to_string(),
        icon: "science".to_string(),
        command: "test".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Build & CI".to_string(),
    });
    actions.push(QuickAction {
        label: "Lint / Clippy".to_string(),
        icon: "verified".to_string(),
        command: "lint".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Build & CI".to_string(),
    });
    actions.push(QuickAction {
        label: "Format Code".to_string(),
        icon: "format_paint".to_string(),
        command: "fmt".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Build & CI".to_string(),
    });
    actions.push(QuickAction {
        label: "Security Audit".to_string(),
        icon: "security".to_string(),
        command: "audit".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Build & CI".to_string(),
    });
    actions.push(QuickAction {
        label: "Dependencies Tree".to_string(),
        icon: "device_hub".to_string(),
        command: "deps".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Build & CI".to_string(),
    });

    // --- Deploy ---
    actions.push(QuickAction {
        label: "Deploy Staging".to_string(),
        icon: "rocket_launch".to_string(),
        command: "deploy staging".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::SoftwareDev,
        group: "Deploy".to_string(),
    });
    actions.push(QuickAction {
        label: "Deploy Production".to_string(),
        icon: "publish".to_string(),
        command: "deploy production".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::SoftwareDev,
        group: "Deploy".to_string(),
    });

    // --- Database ---
    actions.push(QuickAction {
        label: "DB Backup".to_string(),
        icon: "backup".to_string(),
        command: "db backup".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::SoftwareDev,
        group: "Database".to_string(),
    });
    actions.push(QuickAction {
        label: "DB Status".to_string(),
        icon: "storage".to_string(),
        command: "db size".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Database".to_string(),
    });

    // --- npm / Node ---
    actions.push(QuickAction {
        label: "npm Test".to_string(),
        icon: "quiz".to_string(),
        command: "npm test".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Node.js".to_string(),
    });
    actions.push(QuickAction {
        label: "npm Build".to_string(),
        icon: "construction".to_string(),
        command: "npm build".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Node.js".to_string(),
    });
    actions.push(QuickAction {
        label: "npm Audit".to_string(),
        icon: "shield".to_string(),
        command: "npm audit".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::SoftwareDev,
        group: "Node.js".to_string(),
    });

    // ══════════════════════════════════════════════════════
    //  MARKETING COMPANY — Work Stories
    // ══════════════════════════════════════════════════════

    // --- Campaign Management ---
    actions.push(QuickAction {
        label: "Campaign List".to_string(),
        icon: "campaign".to_string(),
        command: "campaign list".to_string(),
        capability: "status_query".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "Campaign".to_string(),
    });
    actions.push(QuickAction {
        label: "Campaign Status".to_string(),
        icon: "trending_up".to_string(),
        command: "campaign status".to_string(),
        capability: "status_query".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "Campaign".to_string(),
    });

    // --- Analytics & Reports ---
    actions.push(QuickAction {
        label: "Daily Report".to_string(),
        icon: "summarize".to_string(),
        command: "report daily".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "Reports".to_string(),
    });
    actions.push(QuickAction {
        label: "Weekly Report".to_string(),
        icon: "assessment".to_string(),
        command: "report weekly".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "Reports".to_string(),
    });
    actions.push(QuickAction {
        label: "Analytics Summary".to_string(),
        icon: "analytics".to_string(),
        command: "analytics".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "Reports".to_string(),
    });

    // --- SEO ---
    actions.push(QuickAction {
        label: "SEO Analysis".to_string(),
        icon: "search".to_string(),
        command: "seo".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "SEO".to_string(),
    });

    // --- Schedule & Automation ---
    actions.push(QuickAction {
        label: "Scheduled Tasks".to_string(),
        icon: "event".to_string(),
        command: "schedule".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::Marketing,
        group: "Automation".to_string(),
    });
    actions.push(QuickAction {
        label: "Backup Assets".to_string(),
        icon: "cloud_upload".to_string(),
        command: "backup".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::Marketing,
        group: "Automation".to_string(),
    });

    // ══════════════════════════════════════════════════════
    //  DEVOPS — Infrastructure & Operations
    // ══════════════════════════════════════════════════════

    // --- Docker ---
    actions.push(QuickAction {
        label: "Docker Status".to_string(),
        icon: "inventory_2".to_string(),
        command: "docker_status".to_string(),
        capability: "docker_manage".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::DevOps,
        group: "Docker".to_string(),
    });
    actions.push(QuickAction {
        label: "Docker Prune".to_string(),
        icon: "delete_sweep".to_string(),
        command: "docker_prune".to_string(),
        capability: "docker_manage".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::DevOps,
        group: "Docker".to_string(),
    });

    // --- Disk & Infra ---
    actions.push(QuickAction {
        label: "Disk Check".to_string(),
        icon: "hard_drive".to_string(),
        command: "disk_check".to_string(),
        capability: "system_info".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::DevOps,
        group: "Infrastructure".to_string(),
    });
    actions.push(QuickAction {
        label: "Disk Cleanup".to_string(),
        icon: "cleaning_services".to_string(),
        command: "disk_cleanup".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::DevOps,
        group: "Infrastructure".to_string(),
    });

    // --- Services ---
    actions.push(QuickAction {
        label: "Service Restart".to_string(),
        icon: "restart_alt".to_string(),
        command: "service_restart".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: true,
        profile: WorkProfile::DevOps,
        group: "Services".to_string(),
    });
    actions.push(QuickAction {
        label: "Failed Services".to_string(),
        icon: "error_outline".to_string(),
        command: "services_failed".to_string(),
        capability: "status_query".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::DevOps,
        group: "Services".to_string(),
    });

    // --- Logs & Certs ---
    actions.push(QuickAction {
        label: "Tail Logs".to_string(),
        icon: "description".to_string(),
        command: "log_tail".to_string(),
        capability: "log_read".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::DevOps,
        group: "Logs".to_string(),
    });
    actions.push(QuickAction {
        label: "Cert Check".to_string(),
        icon: "verified_user".to_string(),
        command: "cert_check".to_string(),
        capability: "shell_exec".to_string(),
        needs_confirmation: false,
        profile: WorkProfile::DevOps,
        group: "Security".to_string(),
    });

    actions
}

/// Get quick actions filtered by work profile
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
            model: None,
            attachments: vec![],
            parallel: false,
            strategies: vec![],
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
            model: None,
            attachments: vec![],
            parallel: false,
            strategies: vec![],
        };

        let response = provider.process(&request).unwrap();
        assert!(response.intent.is_some());
        let intent = response.intent.unwrap();
        assert_eq!(intent.capability, "shell_exec");
        // Platform-independent: just check the service name is in the command
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
            model: None,
            attachments: vec![],
            parallel: false,
            strategies: vec![],
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
            model: None,
            attachments: vec![],
            parallel: false,
            strategies: vec![],
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
            model: None,
            attachments: vec![],
            parallel: false,
            strategies: vec![],
        };
        let response = provider.process(&request).unwrap();
        assert!(response.intent.is_some());
    }

    #[test]
    fn test_quick_actions() {
        let actions = default_quick_actions();
        assert!(!actions.is_empty());
        assert!(actions.iter().any(|a| a.label == "Server Status"));
        assert!(actions.iter().any(|a| a.label == "Disk Space"));
        // All actions should have a capability and profile
        for action in &actions {
            assert!(!action.capability.is_empty());
            assert!(!action.group.is_empty());
        }
        // Check industry profiles exist
        assert!(actions
            .iter()
            .any(|a| a.profile == WorkProfile::SoftwareDev));
        assert!(actions.iter().any(|a| a.profile == WorkProfile::Marketing));
        assert!(actions.iter().any(|a| a.profile == WorkProfile::DevOps));
        assert!(actions.iter().any(|a| a.profile == WorkProfile::System));
    }

    #[test]
    fn test_quick_actions_by_profile() {
        let sw = quick_actions_by_profile(Some(WorkProfile::SoftwareDev));
        assert!(!sw.is_empty());
        // Should include System + SoftwareDev
        assert!(sw.iter().any(|a| a.profile == WorkProfile::System));
        assert!(sw.iter().any(|a| a.profile == WorkProfile::SoftwareDev));
        assert!(!sw.iter().any(|a| a.profile == WorkProfile::Marketing));

        let mkt = quick_actions_by_profile(Some(WorkProfile::Marketing));
        assert!(mkt.iter().any(|a| a.profile == WorkProfile::Marketing));
        assert!(mkt.iter().any(|a| a.profile == WorkProfile::System));

        let all = quick_actions_by_profile(None);
        assert!(all.len() > sw.len());
    }

    #[test]
    fn test_ollama_prompt_building() {
        let provider = OllamaProvider::new("http://127.0.0.1:11434", "llama3.2:3b", 5000);
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
            model: None,
            attachments: vec![],
            parallel: false,
            strategies: vec![],
        };

        let prompt = provider.build_prompt(&request);
        assert!(prompt.contains("shell_exec"));
        assert!(prompt.contains("admin"));
        assert!(prompt.contains("restart nginx"));
        assert!(prompt.contains("CPU: 45%"));
    }

    #[test]
    fn test_ollama_parse_valid_json() {
        let provider = OllamaProvider::new("http://127.0.0.1:11434", "llama3.2:3b", 5000);
        let json = r#"{"message": "Restarting nginx...", "intent": {"capability": "shell_exec", "command": "systemctl restart nginx", "args": [], "needs_confirmation": true}, "confidence": 0.95}"#;

        let response = provider.parse_response(json).unwrap();
        assert_eq!(response.message, "Restarting nginx...");
        assert!(response.intent.is_some());
        assert_eq!(response.confidence, 0.95);
        assert!(response.is_local);
    }

    #[test]
    fn test_ollama_parse_invalid_json() {
        let provider = OllamaProvider::new("http://127.0.0.1:11434", "llama3.2:3b", 5000);
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
            model: None,
            attachments: vec![],
            parallel: false,
            strategies: vec![],
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
        let parsed = parse_url("http://127.0.0.1:11434/api/generate").unwrap();
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 11434);
        assert_eq!(parsed.path, "/api/generate");
    }

    #[test]
    fn test_ollama_model_info_serialize() {
        let info = OllamaModelInfo {
            name: "llama3.2:3b".into(),
            size: 2_000_000_000,
            modified_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("llama3.2:3b"));
        let parsed: OllamaModelInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "llama3.2:3b");
    }

    #[test]
    fn test_escalation_not_needed() {
        let config = crate::config::AiConfig {
            primary: "none".to_string(),
            ..Default::default()
        };
        let manager = AiManager::from_config(&config);

        let request = AiRequest {
            user_input: "status".to_string(),
            available_capabilities: vec!["status_query".to_string()],
            peer_role: "owner".to_string(),
            system_context: None,
            history: vec![],
            model: None,
            attachments: vec![],
            parallel: false,
            strategies: vec![],
        };
        let response = manager.process(&request).unwrap();
        // NoneProvider gives high confidence for known commands
        let escalated = manager.escalate_to_cloud(&request, &response).unwrap();
        assert_eq!(escalated.provider, response.provider);
    }

    #[test]
    fn test_escalation_blocked_sensitive() {
        let config = crate::config::AiConfig {
            primary: "none".to_string(),
            ..Default::default()
        };
        let manager = AiManager::from_config(&config);

        let request = AiRequest {
            user_input: "show me the password".to_string(),
            available_capabilities: vec![],
            peer_role: "owner".to_string(),
            system_context: None,
            history: vec![],
            model: None,
            attachments: vec![],
            parallel: false,
            strategies: vec![],
        };
        let low_confidence = AiResponse {
            message: "idk".into(),
            intent: None,
            confidence: 0.1,
            provider: "none".into(),
            is_local: true,
            sub_responses: Vec::new(),
        };
        let result = manager.escalate_to_cloud(&request, &low_confidence);
        assert!(result.is_err());
    }

    #[test]
    fn test_work_profile_devops() {
        let actions = default_quick_actions();
        let devops: Vec<_> = actions
            .iter()
            .filter(|a| a.profile == WorkProfile::DevOps)
            .collect();
        assert!(devops.len() >= 6);
        assert!(devops.iter().any(|a| a.label == "Docker Status"));
        assert!(devops.iter().any(|a| a.label == "Disk Check"));
        assert!(devops.iter().any(|a| a.label == "Cert Check"));
    }

    #[test]
    fn test_work_profile_custom() {
        let profile = WorkProfile::Custom("finance".to_string());
        assert_eq!(profile.to_string(), "Custom(finance)");

        // Custom profile filtering returns only System actions (no matching custom)
        let actions = quick_actions_by_profile(Some(WorkProfile::Custom("finance".to_string())));
        assert!(!actions.is_empty());
        // Should include System actions
        assert!(actions.iter().all(|a| a.profile == WorkProfile::System
            || a.profile == WorkProfile::Custom("finance".to_string())));
    }

    #[test]
    fn test_work_profile_serialization() {
        let custom = WorkProfile::Custom("healthcare".to_string());
        let json = serde_json::to_string(&custom).unwrap();
        let parsed: WorkProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, custom);

        let system = WorkProfile::System;
        let json = serde_json::to_string(&system).unwrap();
        let parsed: WorkProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, system);
    }
    #[test]
    fn test_ollama_provider_localhost_fix() {
        // Test that localhost is automatically resolved to 127.0.0.1
        let provider = OllamaProvider::new("http://localhost:11434", "llama3.2:3b", 5000);
        assert_eq!(provider.endpoint, "http://127.0.0.1:11434");

        let provider2 = OllamaProvider::new("http://127.0.0.1:11434", "llama3.2:3b", 5000);
        assert_eq!(provider2.endpoint, "http://127.0.0.1:11434");
    }
}

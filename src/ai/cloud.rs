use super::{
    parse_cloud_response, ureq_post_json_with_anthropic_auth, ureq_post_json_with_auth,
    ureq_post_json_with_timeout, AiProvider, AiRequest, AiResponse, ChatRole,
};
use crate::error::AgentError;
use serde::Deserialize;
use std::time::Duration;

// ─── OpenAI Provider ───────────────────────────────────────

pub struct OpenAiProvider {
    pub api_key: String,
    pub model: String,
    pub endpoint: String,
    pub timeout: Duration,
}

impl OpenAiProvider {
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
                 Goal: Perform complex business automation. Capabilities: [{}]. User role: {}. \
                 Language: Korean for the 'message' field.",
                caps, request.peer_role
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
            "max_tokens": 1024,
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
            .map_err(|e| AgentError::SerializationError(format!("openai: {e}")))?;

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

// ─── Claude Provider ───────────────────────────────────────

pub struct ClaudeProvider {
    pub api_key: String,
    pub model: String,
    pub endpoint: String,
    pub timeout: Duration,
}

impl ClaudeProvider {
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
                ChatRole::System => "user",
            };
            messages.push(serde_json::json!({ "role": role, "content": msg.content }));
        }
        messages.push(serde_json::json!({ "role": "user", "content": request.user_input }));

        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 1024,
            "system": format!("You are a Business Orchestrator. Capabilities: [{}].", caps),
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
            .map_err(|e| AgentError::SerializationError(format!("claude: {e}")))?;

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

// ─── GPT-OSS 120B Provider ─────────────────────────────────

pub struct GptOssProvider {
    pub api_key: String,
    pub model: String,
    pub endpoint: String,
    pub timeout: Duration,
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
        !self.endpoint.is_empty()
    }
    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        let caps = request.available_capabilities.join(", ");
        let mut messages = vec![serde_json::json!({
            "role": "system",
            "content": format!("You are EdgeClaw GPT-OSS 120B. Capabilities: [{}].", caps)
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

        let body = serde_json::json!({ "model": self.model, "messages": messages });

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

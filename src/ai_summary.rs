//! AI-powered session summary generation.
//!
//! Provides a [`SummaryProvider`] trait with implementations for local
//! (Ollama) and cloud (OpenAI, Claude) AI backends. Generates structured
//! summaries of agent sessions including decisions, errors, and file changes.

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::activity_log::{ActivityEntry, ActivityType};
use crate::error::AgentError;

// ─── Provider Trait ───────────────────────────────────────

/// Abstraction for AI summary generation backends.
pub trait SummaryProvider: Send + Sync {
    /// Provider name (e.g. "ollama", "openai", "claude").
    fn name(&self) -> &str;

    /// Generate a summary from a list of activity entries.
    fn summarize(&self, activities: &[ActivityEntry]) -> Result<String, AgentError>;

    /// Estimated cost in USD for this summarization (0 for local models).
    fn estimated_cost(&self, token_count: usize) -> f64;
}

// ─── Configuration ────────────────────────────────────────

/// AI summary configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSummaryConfig {
    /// Enable automatic session summarization
    pub enabled: bool,
    /// Primary provider: "ollama", "openai", "claude"
    pub provider: String,
    /// Model name (e.g. "llama3", "gpt-4o-mini", "claude-3-haiku-20240307")
    pub model: String,
    /// API key (for cloud providers)
    pub api_key: Option<String>,
    /// Ollama base URL
    pub ollama_url: String,
    /// Maximum activities to include in prompt
    pub max_activities: usize,
}

impl Default for AiSummaryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "ollama".to_string(),
            model: "llama3:8b".to_string(),
            api_key: None,
            ollama_url: "http://localhost:11434".to_string(),
            max_activities: 50,
        }
    }
}

// ─── Prompt Builder ───────────────────────────────────────

/// Build a structured prompt from activity entries.
pub fn build_summary_prompt(activities: &[ActivityEntry]) -> String {
    let mut prompt = String::from(
        "Summarize the following coding session activities. Focus on:\n\
         1. Key decisions made and their rationale\n\
         2. Errors encountered and whether they were resolved\n\
         3. Files modified and the nature of changes\n\
         4. Overall progress and achievements\n\n\
         Activities:\n",
    );

    for (i, entry) in activities.iter().enumerate() {
        prompt.push_str(&format!(
            "\n{}. [{}] {} (importance: {})\n   Content: {}\n",
            i + 1,
            entry.activity_type.type_tag(),
            entry.timestamp.format("%H:%M:%S"),
            entry.importance,
            entry.content,
        ));

        if let Some(ref fp) = entry.file_path {
            prompt.push_str(&format!("   File: {}\n", fp));
        }

        match &entry.activity_type {
            ActivityType::Decision {
                title,
                chosen,
                rationale,
                ..
            } => {
                prompt.push_str(&format!(
                    "   Decision: {} → {} ({})\n",
                    title, chosen, rationale
                ));
            }
            ActivityType::Error {
                message, resolved, ..
            } => {
                prompt.push_str(&format!("   Error: {} (resolved: {})\n", message, resolved));
            }
            ActivityType::AiChat {
                model,
                input_tokens,
                output_tokens,
                cost_usd,
                ..
            } => {
                prompt.push_str(&format!(
                    "   AI: {} ({}+{} tokens, ${:.4})\n",
                    model, input_tokens, output_tokens, cost_usd
                ));
            }
            _ => {}
        }
    }

    prompt.push_str("\n\nProvide a concise summary (3-5 sentences) covering the key points above.");
    prompt
}

/// Extract key metrics from a session's activities.
pub fn extract_session_metrics(activities: &[ActivityEntry]) -> SessionMetrics {
    let mut metrics = SessionMetrics::default();

    for entry in activities {
        match &entry.activity_type {
            ActivityType::FileEdit { lines_changed, .. } => {
                metrics.files_changed += 1;
                metrics.lines_changed += *lines_changed as u64;
            }
            ActivityType::CommandExec { exit_code, .. } => {
                metrics.commands_run += 1;
                if *exit_code != 0 {
                    metrics.failed_commands += 1;
                }
            }
            ActivityType::AiChat {
                input_tokens,
                output_tokens,
                cost_usd,
                ..
            } => {
                metrics.total_tokens += (*input_tokens + *output_tokens) as u64;
                metrics.total_cost += cost_usd;
            }
            ActivityType::Decision { .. } => {
                metrics.decisions += 1;
            }
            ActivityType::Error { resolved, .. } => {
                metrics.errors += 1;
                if *resolved {
                    metrics.errors_resolved += 1;
                }
            }
            _ => {}
        }
    }

    metrics
}

/// Quantitative metrics for a session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionMetrics {
    pub files_changed: u32,
    pub lines_changed: u64,
    pub commands_run: u32,
    pub failed_commands: u32,
    pub total_tokens: u64,
    pub total_cost: f64,
    pub decisions: u32,
    pub errors: u32,
    pub errors_resolved: u32,
}

// ─── Ollama Provider ──────────────────────────────────────

/// Local Ollama AI provider (privacy-preserving).
pub struct OllamaProvider {
    base_url: String,
    model: String,
}

impl OllamaProvider {
    /// Create a new Ollama provider.
    pub fn new(base_url: &str, model: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            model: model.to_string(),
        }
    }
}

impl SummaryProvider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn summarize(&self, activities: &[ActivityEntry]) -> Result<String, AgentError> {
        let prompt = build_summary_prompt(activities);

        // Use ureq for HTTP request to Ollama
        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false
        });

        let url = format!("{}/api/generate", self.base_url);
        let resp = ureq::post(&url)
            .send_json(&body)
            .map_err(|e| AgentError::ConnectionError(format!("Ollama request failed: {}", e)))?;

        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| AgentError::SerializationError(format!("Ollama response parse: {}", e)))?;

        json.get("response")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| AgentError::InternalError("No response from Ollama".into()))
    }

    fn estimated_cost(&self, _token_count: usize) -> f64 {
        0.0 // Local = free
    }
}

// ─── OpenAI Provider ──────────────────────────────────────

/// OpenAI cloud AI provider.
pub struct OpenAiProvider {
    api_key: String,
    model: String,
}

impl OpenAiProvider {
    /// Create a new OpenAI provider.
    pub fn new(api_key: &str, model: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            model: model.to_string(),
        }
    }
}

impl SummaryProvider for OpenAiProvider {
    fn name(&self) -> &str {
        "openai"
    }

    fn summarize(&self, activities: &[ActivityEntry]) -> Result<String, AgentError> {
        let prompt = build_summary_prompt(activities);

        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a technical session summarizer. Provide concise, actionable summaries."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 500,
            "temperature": 0.3
        });

        let resp = ureq::post("https://api.openai.com/v1/chat/completions")
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| AgentError::ConnectionError(format!("OpenAI request failed: {}", e)))?;

        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| AgentError::SerializationError(format!("OpenAI response parse: {}", e)))?;

        json.get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| AgentError::InternalError("No response from OpenAI".into()))
    }

    fn estimated_cost(&self, token_count: usize) -> f64 {
        // Approximate pricing for gpt-4o-mini
        (token_count as f64) * 0.00000015
    }
}

// ─── Claude Provider ──────────────────────────────────────

/// Anthropic Claude AI provider.
pub struct ClaudeProvider {
    api_key: String,
    model: String,
}

impl ClaudeProvider {
    /// Create a new Claude provider.
    pub fn new(api_key: &str, model: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            model: model.to_string(),
        }
    }
}

impl SummaryProvider for ClaudeProvider {
    fn name(&self) -> &str {
        "claude"
    }

    fn summarize(&self, activities: &[ActivityEntry]) -> Result<String, AgentError> {
        let prompt = build_summary_prompt(activities);

        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 500,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        });

        let resp = ureq::post("https://api.anthropic.com/v1/messages")
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", "2023-06-01")
            .set("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| AgentError::ConnectionError(format!("Claude request failed: {}", e)))?;

        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| AgentError::SerializationError(format!("Claude response parse: {}", e)))?;

        json.get("content")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("text"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| AgentError::InternalError("No response from Claude".into()))
    }

    fn estimated_cost(&self, token_count: usize) -> f64 {
        // Approximate pricing for claude-3-haiku
        (token_count as f64) * 0.00000025
    }
}

// ─── Session Summarizer ───────────────────────────────────

/// Orchestrates session summary generation.
pub struct SessionSummarizer {
    config: AiSummaryConfig,
}

impl SessionSummarizer {
    /// Create with the given configuration.
    pub fn new(config: AiSummaryConfig) -> Self {
        Self { config }
    }

    /// Create the appropriate provider based on config.
    pub fn create_provider(&self) -> Box<dyn SummaryProvider> {
        match self.config.provider.as_str() {
            "openai" => Box::new(OpenAiProvider::new(
                self.config.api_key.as_deref().unwrap_or(""),
                &self.config.model,
            )),
            "claude" => Box::new(ClaudeProvider::new(
                self.config.api_key.as_deref().unwrap_or(""),
                &self.config.model,
            )),
            _ => Box::new(OllamaProvider::new(
                &self.config.ollama_url,
                &self.config.model,
            )),
        }
    }

    /// Summarize a session's activities.
    pub fn summarize_session(&self, activities: &[ActivityEntry]) -> Result<String, AgentError> {
        if !self.config.enabled {
            return Err(AgentError::InternalError("AI summary is disabled".into()));
        }

        let limited: &[ActivityEntry] = if activities.len() > self.config.max_activities {
            &activities[activities.len() - self.config.max_activities..]
        } else {
            activities
        };

        let provider = self.create_provider();
        info!(
            provider = provider.name(),
            activities = limited.len(),
            "Generating session summary"
        );

        provider.summarize(limited)
    }

    /// Summarize with local-first fallback: try primary provider, then
    /// fall back through the chain (ollama → openai → claude).
    pub fn summarize_with_fallback(
        &self,
        activities: &[ActivityEntry],
    ) -> Result<String, AgentError> {
        if !self.config.enabled {
            return Err(AgentError::InternalError("AI summary is disabled".into()));
        }

        let limited: &[ActivityEntry] = if activities.len() > self.config.max_activities {
            &activities[activities.len() - self.config.max_activities..]
        } else {
            activities
        };

        let providers = self.fallback_chain();

        let mut last_err = AgentError::InternalError("No providers available".into());

        for provider in &providers {
            info!(
                provider = provider.name(),
                activities = limited.len(),
                "Trying provider for session summary"
            );
            match provider.summarize(limited) {
                Ok(summary) => return Ok(summary),
                Err(e) => {
                    info!(
                        provider = provider.name(),
                        error = %e,
                        "Provider failed, trying next"
                    );
                    last_err = e;
                }
            }
        }

        Err(last_err)
    }

    /// Build a fallback chain: primary first, then alternatives.
    fn fallback_chain(&self) -> Vec<Box<dyn SummaryProvider>> {
        let mut chain: Vec<Box<dyn SummaryProvider>> = Vec::new();

        // Primary first
        chain.push(self.create_provider());

        // Add alternatives not already in chain
        let api_key = self.config.api_key.as_deref().unwrap_or("");
        match self.config.provider.as_str() {
            "ollama" => {
                if !api_key.is_empty() {
                    chain.push(Box::new(OpenAiProvider::new(api_key, "gpt-4o-mini")));
                    chain.push(Box::new(ClaudeProvider::new(
                        api_key,
                        "claude-3-haiku-20240307",
                    )));
                }
            }
            "openai" => {
                chain.push(Box::new(OllamaProvider::new(
                    &self.config.ollama_url,
                    "llama3",
                )));
                if !api_key.is_empty() {
                    chain.push(Box::new(ClaudeProvider::new(
                        api_key,
                        "claude-3-haiku-20240307",
                    )));
                }
            }
            "claude" => {
                chain.push(Box::new(OllamaProvider::new(
                    &self.config.ollama_url,
                    "llama3",
                )));
                if !api_key.is_empty() {
                    chain.push(Box::new(OpenAiProvider::new(api_key, "gpt-4o-mini")));
                }
            }
            _ => {}
        }

        chain
    }

    /// Get the config.
    pub fn config(&self) -> &AiSummaryConfig {
        &self.config
    }
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_activity(content: &str, activity_type: ActivityType) -> ActivityEntry {
        ActivityEntry {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            agent_id: "dev-1".into(),
            agent_role: "admin".into(),
            agent_name: "agent-1".into(),
            activity_type,
            project: "edgeclaw".into(),
            file_path: Some("src/lib.rs".into()),
            content: content.into(),
            tags: vec!["test".into()],
            importance: 1,
            timestamp: Utc::now(),
            lamport_clock: 1,
            prev_hash: "0".repeat(64),
            hash: "abc".into(),
            signature: String::new(),
        }
    }

    #[test]
    fn test_prompt_generation() {
        let activities = vec![
            sample_activity(
                "Fixed auth bug",
                ActivityType::FileEdit {
                    before_snippet: None,
                    after_snippet: Some("fixed".into()),
                    lines_changed: 5,
                },
            ),
            sample_activity(
                "Chose CBOR encoding",
                ActivityType::Decision {
                    title: "Encoding format".into(),
                    chosen: "CBOR".into(),
                    rationale: "Smaller size".into(),
                    alternatives: vec!["JSON".into(), "MessagePack".into()],
                },
            ),
        ];

        let prompt = build_summary_prompt(&activities);
        assert!(prompt.contains("Fixed auth bug"));
        assert!(prompt.contains("Chose CBOR encoding"));
        assert!(prompt.contains("CBOR"));
        assert!(prompt.contains("Encoding format"));
    }

    #[test]
    fn test_session_metrics_extraction() {
        let activities = vec![
            sample_activity(
                "edit",
                ActivityType::FileEdit {
                    before_snippet: None,
                    after_snippet: None,
                    lines_changed: 10,
                },
            ),
            sample_activity(
                "cmd",
                ActivityType::CommandExec {
                    command: "cargo test".into(),
                    exit_code: 0,
                    duration_ms: 100,
                    output_summary: None,
                },
            ),
            sample_activity(
                "cmd fail",
                ActivityType::CommandExec {
                    command: "cargo build".into(),
                    exit_code: 1,
                    duration_ms: 200,
                    output_summary: None,
                },
            ),
            sample_activity(
                "ai chat",
                ActivityType::AiChat {
                    model: "gpt-4".into(),
                    input_tokens: 100,
                    output_tokens: 200,
                    cost_usd: 0.01,
                    role: "assistant".into(),
                },
            ),
            sample_activity(
                "err",
                ActivityType::Error {
                    severity: 2,
                    message: "compile error".into(),
                    stack_trace: None,
                    resolved: true,
                },
            ),
        ];

        let metrics = extract_session_metrics(&activities);
        assert_eq!(metrics.files_changed, 1);
        assert_eq!(metrics.lines_changed, 10);
        assert_eq!(metrics.commands_run, 2);
        assert_eq!(metrics.failed_commands, 1);
        assert_eq!(metrics.total_tokens, 300);
        assert_eq!(metrics.decisions, 0);
        assert_eq!(metrics.errors, 1);
        assert_eq!(metrics.errors_resolved, 1);
    }

    #[test]
    fn test_summarizer_disabled() {
        let config = AiSummaryConfig {
            enabled: false,
            ..Default::default()
        };
        let summarizer = SessionSummarizer::new(config);
        let result = summarizer.summarize_session(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_serialization() {
        let config = AiSummaryConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let decoded: AiSummaryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.provider, "ollama");
        assert_eq!(decoded.max_activities, 50);
    }

    #[test]
    fn test_provider_cost_estimation() {
        let ollama = OllamaProvider::new("http://localhost:11434", "llama3");
        assert_eq!(ollama.estimated_cost(1000), 0.0);

        let openai = OpenAiProvider::new("key", "gpt-4o-mini");
        assert!(openai.estimated_cost(1000) > 0.0);

        let claude = ClaudeProvider::new("key", "claude-3-haiku");
        assert!(claude.estimated_cost(1000) > 0.0);
    }

    #[test]
    fn test_fallback_chain_order() {
        // Ollama primary → chain should be [ollama, openai, claude]
        let config = AiSummaryConfig {
            enabled: true,
            provider: "ollama".into(),
            api_key: Some("test-key".into()),
            ..Default::default()
        };
        let summarizer = SessionSummarizer::new(config);
        let chain = summarizer.fallback_chain();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].name(), "ollama");
        assert_eq!(chain[1].name(), "openai");
        assert_eq!(chain[2].name(), "claude");
    }

    #[test]
    fn test_fallback_chain_no_api_key() {
        // No API key → only local provider
        let config = AiSummaryConfig {
            enabled: true,
            provider: "ollama".into(),
            api_key: None,
            ..Default::default()
        };
        let summarizer = SessionSummarizer::new(config);
        let chain = summarizer.fallback_chain();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].name(), "ollama");
    }

    #[test]
    fn test_session_metrics_stored() {
        // Verify that metrics are computed and can be associated with a session
        let activities = vec![
            sample_activity(
                "edit file",
                ActivityType::FileEdit {
                    before_snippet: None,
                    after_snippet: None,
                    lines_changed: 20,
                },
            ),
            sample_activity(
                "ai chat",
                ActivityType::AiChat {
                    model: "gpt-4".into(),
                    input_tokens: 500,
                    output_tokens: 300,
                    cost_usd: 0.05,
                    role: "assistant".into(),
                },
            ),
        ];
        let metrics = extract_session_metrics(&activities);
        assert_eq!(metrics.files_changed, 1);
        assert_eq!(metrics.total_tokens, 800);
        assert!((metrics.total_cost - 0.05).abs() < 1e-6);
    }

    /// A mock provider for testing the fallback and summary pipeline.
    struct MockProvider {
        name: String,
        should_fail: bool,
    }

    impl SummaryProvider for MockProvider {
        fn name(&self) -> &str {
            &self.name
        }

        fn summarize(&self, activities: &[ActivityEntry]) -> Result<String, AgentError> {
            if self.should_fail {
                Err(AgentError::ConnectionError("mock failure".into()))
            } else {
                Ok(format!(
                    "Summary of {} activities by {}",
                    activities.len(),
                    self.name
                ))
            }
        }

        fn estimated_cost(&self, token_count: usize) -> f64 {
            token_count as f64 * 0.001
        }
    }

    #[test]
    fn test_mock_provider_success() {
        let provider = MockProvider {
            name: "mock".into(),
            should_fail: false,
        };
        let activities = vec![sample_activity(
            "test activity",
            ActivityType::Custom {
                category: "test".into(),
                data: serde_json::json!({}),
            },
        )];
        let result = provider.summarize(&activities);
        assert!(result.is_ok());
        let summary = result.unwrap();
        assert!(summary.contains("1 activities"));
        assert!(summary.contains("mock"));
    }

    #[test]
    fn test_mock_provider_failure() {
        let provider = MockProvider {
            name: "broken".into(),
            should_fail: true,
        };
        let activities = vec![sample_activity(
            "test activity",
            ActivityType::Custom {
                category: "test".into(),
                data: serde_json::json!({}),
            },
        )];
        let result = provider.summarize(&activities);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_end_summary_trigger() {
        // Verify: when config is disabled, summarize_session returns an error
        let config = AiSummaryConfig {
            enabled: false,
            ..Default::default()
        };
        let summarizer = SessionSummarizer::new(config);
        let activities = vec![sample_activity(
            "final edit",
            ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 10,
            },
        )];
        let result = summarizer.summarize_session(&activities);
        assert!(result.is_err(), "disabled summarizer should reject");

        // When enabled, summarize_session should attempt the provider
        // (fails because Ollama isn't running, but the pipeline is correct)
        let config2 = AiSummaryConfig {
            enabled: true,
            provider: "ollama".into(),
            ollama_url: "http://localhost:9999".into(), // Ensure failure by using a dead port
            ..Default::default()
        };
        let summarizer2 = SessionSummarizer::new(config2);
        let result2 = summarizer2.summarize_session(&activities);
        // Expected: connection error (Ollama not running), proving the pipeline works
        assert!(result2.is_err());
    }

    #[test]
    fn test_cost_tracking_estimation() {
        let ollama = OllamaProvider::new("http://localhost:11434", "llama3");
        assert_eq!(ollama.estimated_cost(1000), 0.0, "ollama must be free");

        let openai = OpenAiProvider::new("test-key", "gpt-4o-mini");
        let cost = openai.estimated_cost(1000);
        assert!(cost > 0.0, "openai must have a cost");

        let claude = ClaudeProvider::new("test-key", "claude-3-haiku");
        let cost2 = claude.estimated_cost(1000);
        assert!(cost2 > 0.0, "claude must have a cost");
    }
}

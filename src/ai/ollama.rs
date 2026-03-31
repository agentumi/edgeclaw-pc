use super::{
    ureq_get_with_timeout, AiProvider, AiRequest, AiResponse, MissionMetadata, ParsedIntent,
};
use crate::error::AgentError;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Local AI provider using Ollama
pub struct OllamaProvider {
    pub endpoint: String,
    pub model: String,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaModelInfo {
    pub name: String,
    pub size: u64,
    pub modified_at: String,
}

impl OllamaProvider {
    pub fn new(endpoint: &str, model: &str, timeout_ms: u64) -> Self {
        // Automatically resolve localhost to 127.0.0.1 for Windows stability
        let resolved_endpoint = endpoint.replace("localhost", "127.0.0.1");
        Self {
            endpoint: resolved_endpoint,
            model: model.to_string(),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    pub fn list_models(&self) -> Result<Vec<OllamaModelInfo>, AgentError> {
        let url = format!("{}/api/tags", self.endpoint);
        let resp_str = ureq_get_with_timeout(&url, self.timeout)?;

        #[derive(Deserialize)]
        struct TagsResp {
            models: Vec<OllamaModelInfo>,
        }

        let tags: TagsResp = serde_json::from_str(&resp_str)
            .map_err(|e| AgentError::AiError(format!("Failed to parse models: {}", e)))?;
        Ok(tags.models)
    }

    /// Fixed: Parse the Ollama specific response wrapper and extract core mission data
    fn parse_response(&self, raw: &str) -> Result<AiResponse, AgentError> {
        // Step 1: Parse the Ollama API wrapper first
        #[derive(Deserialize)]
        struct OllamaWrapper {
            response: String,
        }

        let ai_content = match serde_json::from_str::<OllamaWrapper>(raw) {
            Ok(wrapper) => wrapper.response,
            Err(_) => raw.to_string(),
        };

        // Step 2: Extract JSON from the content
        let json_str = if let Some(start) = ai_content.find('{') {
            if let Some(end) = ai_content.rfind('}') {
                &ai_content[start..=end]
            } else {
                &ai_content
            }
        } else {
            &ai_content
        };

        #[derive(Deserialize)]
        struct RawResponse {
            message: Option<String>,
            intent: Option<ParsedIntent>,
            confidence: Option<f64>,
        }

        match serde_json::from_str::<RawResponse>(json_str) {
            Ok(mut parsed) => {
                // Step 3: Deep Discovery
                if parsed.intent.is_none() {
                    if let Some(ref msg) = parsed.message {
                        if let Some(s) = msg.find('{') {
                            if let Some(e) = msg.rfind('}') {
                                if e > s {
                                    let inner_json = &msg[s..=e];
                                    if let Ok(inner_intent) =
                                        serde_json::from_str::<ParsedIntent>(inner_json)
                                    {
                                        parsed.intent = Some(inner_intent);
                                    } else if let Ok(inner_mission) =
                                        serde_json::from_str::<MissionMetadata>(inner_json)
                                    {
                                        parsed.intent = Some(ParsedIntent {
                                            capability: "create_mission".to_string(),
                                            mission: Some(inner_mission),
                                            ..Default::default()
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                Ok(AiResponse {
                    message: parsed.message.unwrap_or_else(|| ai_content.to_string()),
                    intent: parsed.intent,
                    confidence: parsed.confidence.unwrap_or(0.5),
                    provider: "ollama".to_string(),
                    is_local: true,
                    sub_responses: Vec::new(),
                })
            }
            Err(_) => Ok(AiResponse {
                message: ai_content.to_string(),
                intent: None,
                confidence: 0.3,
                provider: "ollama".to_string(),
                is_local: true,
                sub_responses: Vec::new(),
            }),
        }
    }
}

impl AiProvider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }
    fn is_available(&self) -> bool {
        let url = format!("{}/api/tags", self.endpoint);
        ureq_get_with_timeout(&url, Duration::from_millis(500)).is_ok()
    }

    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        let url = format!("{}/api/generate", self.endpoint);
        let prompt = super::prompt::build_prompt(request);

        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            "format": "json"
        });

        let resp_str = super::ureq_post_json_with_timeout(&url, &body, self.timeout)?;
        self.parse_response(&resp_str)
    }

    fn is_local(&self) -> bool {
        true
    }
    fn set_model(&mut self, model: &str) -> Result<(), AgentError> {
        self.model = model.to_string();
        Ok(())
    }

    fn list_models(&self) -> Vec<String> {
        match self.list_models() {
            Ok(models) => models.into_iter().map(|m| m.name).collect(),
            Err(_) => Vec::new(),
        }
    }
}

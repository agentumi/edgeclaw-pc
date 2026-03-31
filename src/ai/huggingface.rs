// No direct serde imports needed since we use serde_json::json! macro or other providers
use super::{parse_cloud_response, ureq_post_json_with_auth, AiProvider, AiRequest, AiResponse};
use crate::error::AgentError;
use std::time::Duration;

/// HuggingFace Inference API Provider
pub struct HuggingFaceProvider {
    pub endpoint: String,
    pub model: String,
    pub api_key: String,
    pub timeout: Duration,
}

impl HuggingFaceProvider {
    pub fn new(model: &str, api_key: &str, timeout_ms: u64) -> Self {
        Self {
            endpoint: format!("https://api-inference.huggingface.co/models/{}", model),
            model: model.to_string(),
            api_key: api_key.to_string(),
            timeout: Duration::from_millis(timeout_ms),
        }
    }
}

impl AiProvider for HuggingFaceProvider {
    fn name(&self) -> &str {
        "huggingface"
    }
    fn is_available(&self) -> bool {
        !self.api_key.is_empty()
    }
    fn is_local(&self) -> bool {
        false
    }

    fn set_model(&mut self, model: &str) -> Result<(), AgentError> {
        self.model = model.to_string();
        self.endpoint = format!("https://api-inference.huggingface.co/models/{}", model);
        Ok(())
    }

    fn list_models(&self) -> Vec<String> {
        vec![
            "mistralai/Mistral-7B-v0.1".into(),
            "meta-llama/Llama-2-7b-hf".into(),
            "gpt2".into(),
        ]
    }

    fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        // Build prompt from history + current input
        let prompt = if request.history.is_empty() {
            request.user_input.clone()
        } else {
            let mut p = String::new();
            for msg in &request.history {
                p.push_str(&format!("{}: {}\n", msg.role, msg.content));
            }
            p.push_str(&format!("User: {}\nAssistant: ", request.user_input));
            p
        };

        let body = serde_json::json!({
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 1024,
                "return_full_text": false,
                "temperature": 0.7,
            }
        });

        let response_str =
            ureq_post_json_with_auth(&self.endpoint, &body, &self.api_key, self.timeout)?;

        // HuggingFace usually returns: [{"generated_text": "..."}] OR {"error": "..."}
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&response_str) {
            if let Some(arr) = json_val.as_array() {
                if let Some(first) = arr.first() {
                    if let Some(text) = first.get("generated_text") {
                        let content = text.as_str().unwrap_or(&response_str);
                        return parse_cloud_response(content, "huggingface");
                    }
                }
            } else if let Some(error) = json_val.get("error") {
                return Err(AgentError::ConnectionError(format!(
                    "HuggingFace API Error: {}",
                    error
                )));
            }
        }

        parse_cloud_response(&response_str, "huggingface")
    }
}

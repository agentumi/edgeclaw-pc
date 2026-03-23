use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use ed25519_dalek::SigningKey;
use crate::error::AgentError;
use super::{AiProvider, AiRequest, AiResponse, MissionMetadata, NoneProvider};

// ─── Mission Registry ──────────────────────────────────────

pub struct MissionRegistry {
    pub missions: RwLock<HashMap<String, MissionMetadata>>,
}

impl MissionRegistry {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        let m_path = std::path::PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default())
            .join(".edgeclaw_data")
            .join("missions.json");
            
        if m_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&m_path) {
                if let Ok(missions) = serde_json::from_str::<HashMap<String, super::MissionMetadata>>(&data) {
                    map = missions;
                    println!("[V2.4] Mission Registry Restored: {} active missions loaded.", map.len());
                }
            }
        }
        
        Self {
            missions: RwLock::new(map),
        }
    }

    pub fn register(&self, metadata: MissionMetadata) {
        let mut missions = self.missions.write().unwrap();
        missions.insert(metadata.id.clone(), metadata);
    }
    pub fn list(&self) -> Vec<MissionMetadata> {
        self.missions.read().unwrap().values().cloned().collect()
    }
    pub fn get_by_role(&self, role: &str) -> Option<MissionMetadata> {
        let missions = self.missions.read().unwrap();
        missions.values().find(|m| m.role == role).cloned()
    }
}

// ─── AI Manager ────────────────────────────────────────────

pub struct AiManager {
    primary: Box<dyn AiProvider>,
    #[allow(dead_code)]
    fallback: Option<Box<dyn AiProvider>>,
    #[allow(dead_code)]
    escalation_threshold: f64,
    #[allow(dead_code)]
    sensitive_keywords: Vec<String>,
    require_consent: bool,
    mission_registry: Arc<MissionRegistry>,
    signing_key: Option<SigningKey>,
    config: crate::config::AiConfig,
}

impl AiManager {
    pub fn from_config(config: &crate::config::AiConfig) -> Self {
        let primary = Self::create_provider(config, &config.primary);
        let registry = Arc::new(MissionRegistry::new());
        
        Self {
            primary,
            fallback: None,
            escalation_threshold: config.policy.escalation_threshold,
            sensitive_keywords: config.policy.never_cloud.clone(),
            require_consent: config.policy.require_consent,
            mission_registry: registry,
            signing_key: None,
            config: config.clone(),
        }
    }

    fn create_provider(config: &crate::config::AiConfig, name: &str) -> Box<dyn AiProvider> {
        match name {
            "ollama" | "local" => Box::new(super::ollama::OllamaProvider::new(
                &config.local.endpoint,
                &config.local.model,
                std::cmp::max(config.local.timeout_ms, 600_000), // Force min 10 minutes timeout for slow local models
            )),
            "openai" | "gpt-4o" => {
                let key = std::env::var("EDGECLAW_OPENAI_KEY").unwrap_or_default();
                Box::new(super::cloud::OpenAiProvider::new(&key, name, &config.cloud.endpoint, config.cloud.timeout_ms))
            }
            "claude" => {
                let key = std::env::var("EDGECLAW_CLAUDE_KEY").unwrap_or_default();
                Box::new(super::cloud::ClaudeProvider::new(&key, name, &config.cloud.endpoint, config.cloud.timeout_ms))
            }
            "gpt-oss" => {
                let key = std::env::var("EDGECLAW_GPT_OSS_KEY").unwrap_or_default();
                Box::new(super::cloud::GptOssProvider::new(&key, &config.gpt_oss.model, &config.gpt_oss.endpoint, config.gpt_oss.timeout_ms))
            }
            "huggingface" | "hf" => {
                let key = config.huggingface.api_key.clone().unwrap_or_else(|| std::env::var("EDGECLAW_HF_KEY").unwrap_or_default());
                Box::new(super::huggingface::HuggingFaceProvider::new(&config.huggingface.model, &key, config.huggingface.timeout_ms))
            }
            _ => Box::new(NoneProvider::new()),
        }
    }
    pub fn process(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        // 1. Get response from either single provider or consensus 🧩
        let mut response = if self.primary.is_local() && !self.config.consensus_models.is_empty() {
            self.process_consensus(request)?
        } else {
            self.process_single(request)?
        };

        // 2. V2.4 Deep Sniffing for missions in 'message' field (Resilience for local models) 👃
        if response.intent.as_ref().and_then(|i| i.mission.as_ref()).is_none() {
             println!("[V2.4] No mission in primary intent. Scanning response text for embedded JSON...");
             let mut cursor = 0;
             while let Some(start) = response.message[cursor..].find('{') {
                 let start_abs = cursor + start;
                 // Try to find the matching '}' for this '{' (Basic balancing or just use rfind for largest block)
                 if let Some(end) = response.message[start_abs..].rfind('}') {
                     let end_abs = start_abs + end;
                     let candidate = &response.message[start_abs..=end_abs];
                     
                     if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(candidate) {
                         let mission_val = if let Some(m) = parsed.get("mission") {
                             Some(m.clone())
                         } else if let Some(m) = parsed.get("intent").and_then(|i| i.get("mission")) {
                             Some(m.clone())
                         } else if parsed.get("id").is_some() && parsed.get("tasks").is_some() {
                             Some(parsed.clone())
                         } else {
                             None
                         };

                         if let Some(m_val) = mission_val {
                             if let Ok(mut m) = serde_json::from_value::<super::MissionMetadata>(m_val) {
                                 println!("[V2.4] Successfully sniffed mission: {}", m.id);
                                 // Initialize created_at if not already set
                                 if m.created_at.is_empty() {
                                     m.created_at = chrono::Utc::now().to_rfc3339();
                                 }
                                 if let Some(ref mut intent) = response.intent {
                                     intent.mission = Some(m);
                                 } else {
                                     response.intent = Some(super::ParsedIntent {
                                         mission: Some(m),
                                         ..Default::default()
                                     });
                                 }
                                 break; // Mission found
                             }
                         }
                     }
                 }
                 cursor += start + 1;
                 if cursor >= response.message.len() { break; }
             }
        }

        // 3. V2.4 Universal Auto-Register ANY Mission 🛡️
        if let Some(ref mut intent) = response.intent {
            if let Some(ref mut mission) = intent.mission {
                // Ensure ID is never empty
                if mission.id.is_empty() {
                    mission.id = format!("msn-{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("gen"));
                }
                
                println!("[V2.4] Registering Active Mission: {}", mission.id);

                if let Ok(mut lock) = self.mission_registry.missions.write() {
                    lock.insert(mission.id.clone(), mission.clone());
                    
                    // Direct persistence to ~/.edgeclaw_data/missions.json
                    let m_path = std::path::PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default()).join(".edgeclaw_data").join("missions.json");
                    if let Ok(data) = serde_json::to_string_pretty(&*lock) {
                        let _ = std::fs::write(&m_path, data);
                    }
                }
            }
        }
        
        Ok(response)
    }

    fn process_single(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        self.primary.process(request)
    }

    fn process_consensus(&self, request: &AiRequest) -> Result<AiResponse, AgentError> {
        use super::ensemble::*;

        let domain = DomainDetector::detect_domain(&request.user_input);
        let expert_roles = DomainDetector::get_expert_roles(domain);

        println!("[Fleet Ensemble] Domain detected: '{}', assigning {} expert roles", domain, expert_roles.len());

        // Collect expert responses by cycling through consensus_models with different expert prompts
        let consensus_models = &self.config.consensus_models;
        let mut expert_responses: Vec<ExpertResponse> = Vec::new();

        for (idx, role) in expert_roles.iter().enumerate() {
            // Pick a model for this role (round-robin through available consensus models)
            let model_name = if consensus_models.is_empty() {
                self.config.local.model.clone()
            } else {
                consensus_models[idx % consensus_models.len()].clone()
            };

            let expert_prompt = role.expert_system_prompt(&format!(
                "Domain: {}, User request: {}",
                domain, request.user_input
            ));

            // Build a modified request with the expert system prompt injected
            let mut expert_request = request.clone();
            expert_request.system_context = Some(format!(
                "{}\n\n---\n\n{}",
                expert_prompt,
                request.system_context.as_deref().unwrap_or("")
            ));
            expert_request.model = Some(model_name.clone());

            let start = std::time::Instant::now();
            let result = self.process_single(&expert_request);
            let latency = start.elapsed().as_millis() as u64;

            match result {
                Ok(response) => {
                    let hallucination_score = MissionQualityEvaluator::detect_hallucination(&response.message);

                    println!(
                        "[Fleet Ensemble] {} ({}) → confidence: {:.2}, hallucination: {:.2}, latency: {}ms",
                        role.label(), model_name, response.confidence, hallucination_score, latency
                    );

                    expert_responses.push(ExpertResponse {
                        role: role.label().to_string(),
                        model: model_name,
                        response,
                        latency_ms: latency,
                        hallucination_score,
                    });
                }
                Err(e) => {
                    println!("[Fleet Ensemble] {} ({}) failed: {}", role.label(), model_name, e);
                    // Continue with other models — don't abort the whole ensemble
                }
            }
        }

        // If all models failed, fall back to single provider
        if expert_responses.is_empty() {
            println!("[Fleet Ensemble] All expert models failed, falling back to single provider");
            return self.process_single(request);
        }

        // Select best response via consensus algorithm
        let consensus_level = ConsensusAlgorithm::calculate_consensus_level(&expert_responses);
        let best_idx = ConsensusAlgorithm::select_best(&expert_responses).unwrap_or(0);
        let best_response = &expert_responses[best_idx];

        println!(
            "[Fleet Ensemble] Consensus level: {:.2}, selected: {} ({})",
            consensus_level,
            best_response.role,
            best_response.model
        );

        // If mission quality is available, evaluate it
        if let Some(ref intent) = best_response.response.intent {
            if let Some(ref mission) = intent.mission {
                let quality = MissionQualityEvaluator::evaluate(mission);
                println!("[Fleet Ensemble] Mission quality score: {:.2}", quality);
            }
        }

        // Build final response with sub_responses from all experts
        let sub_responses: Vec<AiResponse> = expert_responses.iter()
            .map(|er| {
                let mut r = er.response.clone();
                r.provider = format!("{} ({})", er.role, er.model);
                r
            })
            .collect();

        let mut final_response = best_response.response.clone();
        final_response.confidence = consensus_level;
        final_response.sub_responses = sub_responses;

        Ok(final_response)
    }

    pub fn mission_registry(&self) -> Arc<MissionRegistry> { self.mission_registry.clone() }

    /// V2.4 Find the currently active/in-progress mission
    pub fn active_mission(&self) -> Option<super::MissionMetadata> {
        let lock = self.mission_registry.missions.read().unwrap_or_else(|e| e.into_inner());
        // Prioritize Active > Planning > Discovery
        let active = lock.values().find(|m| m.status == super::MissionStatus::Active).cloned();
        if active.is_some() { return active; }
        
        let planning = lock.values().find(|m| m.status == super::MissionStatus::Planning).cloned();
        if planning.is_some() { return planning; }
        
        let discovery = lock.values().find(|m| m.status == super::MissionStatus::Discovery).cloned();
        if discovery.is_some() { return discovery; }

        lock.values().find(|m| {
            m.status != super::MissionStatus::Proposed && 
            m.status != super::MissionStatus::Success && 
            m.status != super::MissionStatus::Failure && 
            m.status != super::MissionStatus::Aborted
        }).cloned()
    }
    pub fn is_available(&self) -> bool { self.primary.is_available() }
    pub fn provider_name(&self) -> &str { self.primary.name() }
    pub fn is_local(&self) -> bool { self.primary.is_local() }
    pub fn set_model(&mut self, model: &str) -> Result<(), AgentError> { self.primary.set_model(model) }
    pub fn list_models(&self) -> Vec<String> { self.primary.list_models() }

    pub fn requires_consent(&self) -> bool { self.require_consent }
    pub fn set_identity(&mut self, key: SigningKey) { self.signing_key = Some(key); }
}

// NoneProvider has been moved to src/ai/none_provider.rs

pub mod ai;
pub mod audit;
pub mod config;
pub mod ecnp;
pub mod error;
pub mod executor;
pub mod identity;
pub mod peer;
pub mod policy;
pub mod protocol;
pub mod security;
pub mod server;
pub mod session;
pub mod system;
pub mod webui;

use std::sync::Mutex;

use crate::ai::{AiManager, AiRequest, AiResponse, ChatMessage, ChatRole};
use crate::audit::AuditManager;
use crate::config::AgentConfig;
use crate::ecnp::{EcnpCodec, EcnpMessage};
use crate::error::AgentError;
use crate::executor::{ExecRequest, ExecResponse, Executor};
use crate::identity::{DeviceIdentity, IdentityManager};
use crate::peer::{PeerInfo, PeerManager};
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::protocol::MessageType;
use crate::session::{SessionInfo, SessionManager};
use crate::system::SystemInfo;

/// The main agent engine — orchestrates all subsystems
pub struct AgentEngine {
    config: AgentConfig,
    identity_manager: Mutex<IdentityManager>,
    session_manager: Mutex<SessionManager>,
    peer_manager: Mutex<PeerManager>,
    policy_engine: PolicyEngine,
    executor: Executor,
    ai_manager: AiManager,
    audit_manager: AuditManager,
    chat_history: Mutex<Vec<ChatMessage>>,
    start_time: chrono::DateTime<chrono::Utc>,
}

impl AgentEngine {
    /// Create a new engine with the given config
    pub fn new(config: AgentConfig) -> Self {
        let executor = Executor::new(
            config.execution.max_concurrent,
            config.execution.default_timeout_secs,
            config.execution.max_timeout_secs,
            config.execution.allowed_paths.clone(),
        );
        let ai_manager = AiManager::from_config(&config.ai);

        Self {
            config,
            identity_manager: Mutex::new(IdentityManager::new()),
            session_manager: Mutex::new(SessionManager::new()),
            peer_manager: Mutex::new(PeerManager::new(50)),
            policy_engine: PolicyEngine::new(),
            executor,
            ai_manager,
            audit_manager: AuditManager::new(),
            chat_history: Mutex::new(Vec::new()),
            start_time: chrono::Utc::now(),
        }
    }

    // ─── Identity ──────────────────────────────────────────

    /// Generate a new device identity
    pub fn generate_identity(&self) -> Result<DeviceIdentity, AgentError> {
        let mut mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        mgr.generate_identity(&self.config.agent.device_name)
    }

    /// Get current device identity
    pub fn get_identity(&self) -> Result<DeviceIdentity, AgentError> {
        let mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        mgr.get_identity().cloned()
    }

    // ─── Peers ─────────────────────────────────────────────

    /// Register a peer connection
    pub fn add_peer(
        &self,
        peer_id: &str,
        device_name: &str,
        device_type: &str,
        address: &str,
        role: &str,
    ) -> Result<PeerInfo, AgentError> {
        let mut mgr = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
        mgr.add_peer(peer_id, device_name, device_type, address, role)
    }

    /// List all peers
    pub fn get_peers(&self) -> Vec<PeerInfo> {
        let mgr = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
        mgr.list_peers()
    }

    /// Get number of connected peers
    pub fn connected_count(&self) -> usize {
        let mgr = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
        mgr.connected_count()
    }

    /// Remove a peer
    pub fn remove_peer(&self, peer_id: &str) -> bool {
        let mut mgr = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
        mgr.remove_peer(peer_id)
    }

    // ─── Sessions ──────────────────────────────────────────

    /// Create an encrypted session with a peer
    pub fn create_session(
        &self,
        peer_id: &str,
        remote_public: &[u8; 32],
    ) -> Result<SessionInfo, AgentError> {
        let id_mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let secret = id_mgr.get_secret_key()?;
        drop(id_mgr);

        let mut sess_mgr = self
            .session_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sess_mgr.create_session(peer_id, &secret, remote_public)
    }

    /// Encrypt a message in a session
    pub fn encrypt_message(
        &self,
        session_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        let mut mgr = self
            .session_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        mgr.encrypt(session_id, plaintext)
    }

    /// Decrypt a message in a session
    pub fn decrypt_message(
        &self,
        session_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        let mut mgr = self
            .session_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        mgr.decrypt(session_id, ciphertext)
    }

    // ─── Policy ────────────────────────────────────────────

    /// Evaluate a capability request
    pub fn evaluate_capability(
        &self,
        capability: &str,
        role: &str,
    ) -> Result<PolicyDecision, AgentError> {
        self.policy_engine.evaluate(capability, role)
    }

    /// Check if capability requires sandbox
    pub fn requires_sandbox(&self, capability: &str) -> bool {
        self.policy_engine.requires_sandbox(capability)
    }

    // ─── Execution ─────────────────────────────────────────

    /// Execute a command after policy check
    pub async fn execute_command(
        &self,
        peer_id: &str,
        request: ExecRequest,
    ) -> Result<ExecResponse, AgentError> {
        // Lookup peer role (scope-limited to drop MutexGuard before await)
        let role = {
            let mgr = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
            mgr.get_peer_role(peer_id)
                .ok_or_else(|| AgentError::NotFound(format!("peer not found: {peer_id}")))?
        };

        // Policy check
        let decision = self.policy_engine.evaluate(&request.action, &role)?;
        if !decision.allowed {
            // Audit the denial
            let device_id = self
                .get_identity()
                .map(|id| id.device_id)
                .unwrap_or_else(|_| "unknown".to_string());
            self.audit_manager.log(
                &device_id,
                &role,
                &request.action,
                &request.command,
                "denied",
                Some(&decision.reason),
            );
            return Err(AgentError::PolicyDenied(decision.reason));
        }

        // Execute
        let result = self.executor.execute(request.clone()).await;

        // Audit the execution
        let device_id = self
            .get_identity()
            .map(|id| id.device_id)
            .unwrap_or_else(|_| "unknown".to_string());
        match &result {
            Ok(resp) => {
                self.audit_manager.log(
                    &device_id,
                    &role,
                    &request.action,
                    &request.command,
                    if resp.success { "success" } else { "failed" },
                    None,
                );
            }
            Err(e) => {
                self.audit_manager.log(
                    &device_id,
                    &role,
                    &request.action,
                    &request.command,
                    "error",
                    Some(&e.to_string()),
                );
            }
        }

        result
    }

    // ─── System ────────────────────────────────────────────

    /// Get system information
    pub fn get_system_info(&self) -> SystemInfo {
        system::collect_system_info()
    }

    /// Get detected capabilities
    pub fn get_capabilities(&self) -> Vec<String> {
        system::detect_capabilities()
    }

    /// Get agent uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        (chrono::Utc::now() - self.start_time).num_seconds() as u64
    }

    // ─── Protocol ──────────────────────────────────────────

    /// Create an ECM (Edge Capability Manifest)
    pub fn create_ecm(&self) -> Result<String, AgentError> {
        let id_mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let identity = id_mgr.get_identity()?;
        let caps = self.get_capabilities();
        protocol::create_ecm(
            &identity.device_id,
            &identity.device_name,
            &identity.platform,
            &caps,
        )
    }

    /// Create a heartbeat message
    pub fn create_heartbeat(&self) -> Result<String, AgentError> {
        let id_mgr = self
            .identity_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let identity = id_mgr.get_identity()?;
        let sys = self.get_system_info();
        protocol::create_heartbeat(
            &identity.device_id,
            self.uptime_secs(),
            sys.cpu_usage,
            sys.memory_usage_percent,
            self.connected_count() as u32,
        )
    }

    /// Encode data into ECNP frame
    pub fn encode_ecnp(
        &self,
        msg_type: MessageType,
        payload: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        EcnpCodec::encode(msg_type, payload)
    }

    /// Decode an ECNP frame
    pub fn decode_ecnp(&self, data: &[u8]) -> Result<EcnpMessage, AgentError> {
        EcnpCodec::decode(data)
    }

    /// Get config reference
    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    // ─── AI Chat ───────────────────────────────────────────

    /// Process a chat message through the AI provider
    pub fn chat(&self, peer_id: &str, user_input: &str) -> Result<AiResponse, AgentError> {
        let role = {
            let mgr = self.peer_manager.lock().unwrap_or_else(|e| e.into_inner());
            mgr.get_peer_role(peer_id)
                .unwrap_or_else(|| "viewer".to_string())
        };

        let history = {
            let h = self.chat_history.lock().unwrap_or_else(|e| e.into_inner());
            h.clone()
        };

        let sys_info = self.get_system_info();
        let system_context = Some(format!(
            "CPU: {:.1}%, Memory: {:.1}%, Uptime: {}s",
            sys_info.cpu_usage,
            sys_info.memory_usage_percent,
            self.uptime_secs()
        ));

        let request = AiRequest {
            user_input: user_input.to_string(),
            available_capabilities: self.get_capabilities(),
            peer_role: role.clone(),
            system_context,
            history,
        };

        let response = self.ai_manager.process(&request)?;

        // Add to conversation history
        {
            let mut h = self.chat_history.lock().unwrap_or_else(|e| e.into_inner());
            h.push(ChatMessage {
                role: ChatRole::User,
                content: user_input.to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
            h.push(ChatMessage {
                role: ChatRole::Assistant,
                content: response.message.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            });

            // Keep last 20 messages
            if h.len() > 20 {
                let drain_to = h.len() - 20;
                h.drain(..drain_to);
            }
        }

        // Audit the AI interaction
        let device_id = self
            .get_identity()
            .map(|id| id.device_id)
            .unwrap_or_else(|_| "unknown".to_string());
        self.audit_manager.log(
            &device_id,
            &role,
            "ai_chat",
            user_input,
            &response.provider,
            Some(&format!("confidence: {:.2}", response.confidence)),
        );

        Ok(response)
    }

    /// Execute a chat-driven command (after AI parses intent)
    pub async fn chat_execute(
        &self,
        peer_id: &str,
        user_input: &str,
    ) -> Result<(AiResponse, Option<ExecResponse>), AgentError> {
        let ai_response = self.chat(peer_id, user_input)?;

        if let Some(ref intent) = ai_response.intent {
            // Build execution request from intent
            let request = ExecRequest {
                execution_id: uuid::Uuid::new_v4().to_string(),
                action: intent.capability.clone(),
                command: intent.command.clone(),
                args: intent.args.clone(),
                timeout_secs: 30,
                working_dir: None,
            };

            match self.execute_command(peer_id, request).await {
                Ok(exec_result) => Ok((ai_response, Some(exec_result))),
                Err(e) => {
                    // Return AI response + error info
                    Ok((
                        AiResponse {
                            message: format!(
                                "{}\n\n❌ Execution failed: {}",
                                ai_response.message, e
                            ),
                            ..ai_response
                        },
                        None,
                    ))
                }
            }
        } else {
            Ok((ai_response, None))
        }
    }

    /// Get quick actions available for the given role
    pub fn get_quick_actions(&self, role: &str) -> Vec<ai::QuickAction> {
        ai::default_quick_actions()
            .into_iter()
            .filter(|a| {
                self.policy_engine
                    .evaluate(&a.capability, role)
                    .map(|d| d.allowed)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Get AI provider status
    pub fn ai_status(&self) -> serde_json::Value {
        serde_json::json!({
            "provider": self.ai_manager.provider_name(),
            "available": self.ai_manager.is_available(),
            "local": self.ai_manager.is_local(),
            "requires_consent": self.ai_manager.requires_consent(),
        })
    }

    // ─── Audit ─────────────────────────────────────────────

    /// Get audit log entries
    pub fn get_audit_log(&self, count: usize) -> Vec<audit::AuditEntry> {
        self.audit_manager.last_entries(count)
    }

    /// Verify audit chain integrity
    pub fn verify_audit_chain(&self) -> Result<bool, String> {
        self.audit_manager.verify()
    }

    /// Export full audit log as JSON
    pub fn export_audit_log(&self) -> Result<String, serde_json::Error> {
        self.audit_manager.export()
    }

    /// Get audit entry count
    pub fn audit_count(&self) -> usize {
        self.audit_manager.count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> AgentEngine {
        AgentEngine::new(AgentConfig::default())
    }

    #[test]
    fn test_create_engine() {
        let engine = test_engine();
        assert_eq!(engine.config().agent.listen_port, 8443);
    }

    #[test]
    fn test_identity_lifecycle() {
        let engine = test_engine();
        assert!(engine.get_identity().is_err());
        let id = engine.generate_identity().unwrap();
        assert!(!id.device_id.is_empty());
        let id2 = engine.get_identity().unwrap();
        assert_eq!(id.device_id, id2.device_id);
    }

    #[test]
    fn test_peer_management() {
        let engine = test_engine();
        engine
            .add_peer("p1", "iPhone", "mobile", "10.0.0.1", "admin")
            .unwrap();
        assert_eq!(engine.get_peers().len(), 1);
        assert_eq!(engine.connected_count(), 1);
        assert!(engine.remove_peer("p1"));
        assert_eq!(engine.get_peers().len(), 0);
    }

    #[test]
    fn test_session_and_encryption() {
        let engine = test_engine();
        engine.generate_identity().unwrap();

        let peer_key: [u8; 32] = [
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 64,
        ];
        let session = engine.create_session("peer-1", &peer_key).unwrap();
        assert_eq!(session.state, "active");

        let encrypted = engine
            .encrypt_message(&session.session_id, b"test data")
            .unwrap();
        let decrypted = engine
            .decrypt_message(&session.session_id, &encrypted)
            .unwrap();
        assert_eq!(decrypted, b"test data");
    }

    #[test]
    fn test_policy_evaluation() {
        let engine = test_engine();
        let d = engine
            .evaluate_capability("status_query", "viewer")
            .unwrap();
        assert!(d.allowed);

        let d = engine.evaluate_capability("shell_exec", "viewer").unwrap();
        assert!(!d.allowed);

        let d = engine.evaluate_capability("shell_exec", "owner").unwrap();
        assert!(d.allowed);
    }

    #[test]
    fn test_ecnp_encode_decode() {
        let engine = test_engine();
        let encoded = engine.encode_ecnp(MessageType::Heartbeat, b"ping").unwrap();
        let decoded = engine.decode_ecnp(&encoded).unwrap();
        assert_eq!(decoded.msg_type, MessageType::Heartbeat as u8);
        assert_eq!(decoded.payload, b"ping");
    }

    #[test]
    fn test_system_info() {
        let engine = test_engine();
        let info = engine.get_system_info();
        assert!(info.cpu_count > 0);
        assert!(info.total_memory_mb > 0);
    }

    #[test]
    fn test_capabilities_detection() {
        let engine = test_engine();
        let caps = engine.get_capabilities();
        assert!(caps.contains(&"status_query".to_string()));
        assert!(caps.len() >= 10);
    }

    #[test]
    fn test_uptime() {
        let engine = test_engine();
        assert!(engine.uptime_secs() < 2);
    }

    #[tokio::test]
    async fn test_execute_with_policy_check() {
        let engine = test_engine();
        engine.generate_identity().unwrap();
        engine
            .add_peer("ctrl-1", "Controller", "mobile", "10.0.0.1", "owner")
            .unwrap();

        let request = ExecRequest {
            execution_id: "exec-001".to_string(),
            action: "shell_exec".to_string(),
            command: "echo policy_pass".to_string(),
            args: vec![],
            timeout_secs: 5,
            working_dir: None,
        };

        let result = engine.execute_command("ctrl-1", request).await.unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("policy_pass"));
    }

    #[tokio::test]
    async fn test_execute_policy_denied() {
        let engine = test_engine();
        engine
            .add_peer("ctrl-2", "Viewer", "mobile", "10.0.0.2", "viewer")
            .unwrap();

        let request = ExecRequest {
            execution_id: "exec-002".to_string(),
            action: "shell_exec".to_string(),
            command: "echo should_fail".to_string(),
            args: vec![],
            timeout_secs: 5,
            working_dir: None,
        };

        let result = engine.execute_command("ctrl-2", request).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AgentError::PolicyDenied(_)));
    }
}

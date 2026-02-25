pub mod config;
pub mod ecnp;
pub mod error;
pub mod executor;
pub mod identity;
pub mod peer;
pub mod policy;
pub mod protocol;
pub mod server;
pub mod session;
pub mod system;

use std::sync::Mutex;

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

        Self {
            config,
            identity_manager: Mutex::new(IdentityManager::new()),
            session_manager: Mutex::new(SessionManager::new()),
            peer_manager: Mutex::new(PeerManager::new(50)),
            policy_engine: PolicyEngine::new(),
            executor,
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
            return Err(AgentError::PolicyDenied(decision.reason));
        }

        // Execute
        self.executor.execute(request).await
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

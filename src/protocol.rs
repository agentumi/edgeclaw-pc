//! ECNP message types and protocol structures.
//!
//! Defines `MessageType` variants (ECM, EAP, Heartbeat, Error, Ack)
//! and message payload structures for EdgeClaw Network Protocol v1.1.

use crate::error::AgentError;

/// ECNP v1.1 message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum MessageType {
    Handshake = 0x01,
    Data = 0x02,
    Control = 0x03,
    Heartbeat = 0x04,
    Error = 0x05,
    Auth = 0x06,
    Telemetry = 0x07,
    PolicyUpdate = 0x08,
}

impl TryFrom<u8> for MessageType {
    type Error = AgentError;
    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            0x01 => Ok(MessageType::Handshake),
            0x02 => Ok(MessageType::Data),
            0x03 => Ok(MessageType::Control),
            0x04 => Ok(MessageType::Heartbeat),
            0x05 => Ok(MessageType::Error),
            0x06 => Ok(MessageType::Auth),
            0x07 => Ok(MessageType::Telemetry),
            0x08 => Ok(MessageType::PolicyUpdate),
            _ => Err(AgentError::InvalidParameter(format!(
                "unknown message type: 0x{value:02x}"
            ))),
        }
    }
}

/// ECM — Edge Capability Manifest
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EcmPayload {
    pub device_id: String,
    pub device_name: String,
    pub platform: String,
    pub agent_version: String,
    pub capabilities: Vec<String>,
    pub timestamp: String,
}

/// EAP — Edge Automation Profile action
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EapAction {
    pub action: String,
    pub params: serde_json::Value,
}

/// EAP — Edge Automation Profile
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EapPayload {
    pub profile_id: String,
    pub name: String,
    pub description: String,
    pub trigger: String,
    pub actions: Vec<EapAction>,
    pub created_by: String,
    pub timestamp: String,
}

/// Heartbeat message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HeartbeatPayload {
    pub device_id: String,
    pub uptime_secs: u64,
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub active_sessions: u32,
    pub timestamp: String,
}

/// Execution result message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecutionResult {
    pub execution_id: String,
    pub action: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub timestamp: String,
}

/// Create an ECM JSON payload
pub fn create_ecm(
    device_id: &str,
    device_name: &str,
    platform: &str,
    capabilities: &[String],
) -> Result<String, AgentError> {
    let payload = EcmPayload {
        device_id: device_id.to_string(),
        device_name: device_name.to_string(),
        platform: platform.to_string(),
        agent_version: "2.0.0".to_string(),
        capabilities: capabilities.to_vec(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    serde_json::to_string(&payload).map_err(AgentError::from)
}

/// Create a heartbeat JSON payload
pub fn create_heartbeat(
    device_id: &str,
    uptime_secs: u64,
    cpu_usage: f32,
    memory_usage: f32,
    active_sessions: u32,
) -> Result<String, AgentError> {
    let payload = HeartbeatPayload {
        device_id: device_id.to_string(),
        uptime_secs,
        cpu_usage,
        memory_usage,
        active_sessions,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    serde_json::to_string(&payload).map_err(AgentError::from)
}

/// Create an execution result JSON payload
pub fn create_execution_result(
    execution_id: &str,
    action: &str,
    success: bool,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
    duration_ms: u64,
) -> Result<String, AgentError> {
    let result = ExecutionResult {
        execution_id: execution_id.to_string(),
        action: action.to_string(),
        success,
        exit_code,
        stdout: stdout.to_string(),
        stderr: stderr.to_string(),
        duration_ms,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };
    serde_json::to_string(&result).map_err(AgentError::from)
}

/// Parse an ECM JSON payload
pub fn parse_ecm(json: &str) -> Result<EcmPayload, AgentError> {
    serde_json::from_str(json).map_err(AgentError::from)
}

/// Parse an EAP JSON payload
pub fn parse_eap(json: &str) -> Result<EapPayload, AgentError> {
    serde_json::from_str(json).map_err(AgentError::from)
}

/// Parse a heartbeat JSON payload
pub fn parse_heartbeat(json: &str) -> Result<HeartbeatPayload, AgentError> {
    serde_json::from_str(json).map_err(AgentError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecm_roundtrip() {
        let caps = vec!["status_query".to_string(), "shell_exec".to_string()];
        let json = create_ecm("dev-001", "my-pc", "linux-x86_64", &caps).unwrap();
        let parsed = parse_ecm(&json).unwrap();
        assert_eq!(parsed.device_id, "dev-001");
        assert_eq!(parsed.capabilities.len(), 2);
        assert_eq!(parsed.agent_version, "2.0.0");
    }

    #[test]
    fn test_heartbeat_roundtrip() {
        let json = create_heartbeat("dev-001", 3600, 25.5, 40.2, 3).unwrap();
        let parsed = parse_heartbeat(&json).unwrap();
        assert_eq!(parsed.device_id, "dev-001");
        assert_eq!(parsed.uptime_secs, 3600);
        assert!(parsed.cpu_usage > 25.0);
    }

    #[test]
    fn test_execution_result() {
        let json =
            create_execution_result("exec-001", "shell_exec", true, Some(0), "hello\n", "", 150)
                .unwrap();
        let parsed: ExecutionResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.exit_code, Some(0));
        assert_eq!(parsed.stdout, "hello\n");
    }

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::try_from(0x01).unwrap(), MessageType::Handshake);
        assert_eq!(MessageType::try_from(0x07).unwrap(), MessageType::Telemetry);
        assert!(MessageType::try_from(0xFF).is_err());
    }

    #[test]
    fn test_eap_parse() {
        let eap_json = r#"{
            "profile_id": "eap-001",
            "name": "backup",
            "description": "Daily backup",
            "trigger": "cron:0 2 * * *",
            "actions": [{"action": "shell_exec", "params": {"cmd": "tar czf /backup/data.tar.gz /data"}}],
            "created_by": "admin",
            "timestamp": "2026-02-26T00:00:00Z"
        }"#;
        let parsed = parse_eap(eap_json).unwrap();
        assert_eq!(parsed.profile_id, "eap-001");
        assert_eq!(parsed.actions.len(), 1);
        assert_eq!(parsed.actions[0].action, "shell_exec");
    }
}

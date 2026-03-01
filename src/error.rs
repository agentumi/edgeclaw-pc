//! Unified error types for the EdgeClaw Agent.
//!
//! Provides [`AgentError`] with variants covering crypto, connection,
//! policy, session, execution, serialization, and configuration errors.

use thiserror::Error;

/// Unified error type for EdgeClaw Agent
#[derive(Error, Debug)]
pub enum AgentError {
    #[error("crypto error: {0}")]
    CryptoError(String),

    #[error("connection error: {0}")]
    ConnectionError(String),

    #[error("policy denied: {0}")]
    PolicyDenied(String),

    #[error("invalid capability: {0}")]
    InvalidCapability(String),

    #[error("session expired")]
    SessionExpired,

    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("timeout after {0}s")]
    Timeout(u64),

    #[error("execution error: {0}")]
    ExecutionError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("io error: {0}")]
    IoError(String),

    #[error("config error: {0}")]
    ConfigError(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("authentication error: {0}")]
    AuthenticationError(String),

    #[error("internal error: {0}")]
    InternalError(String),
}

impl From<serde_json::Error> for AgentError {
    fn from(e: serde_json::Error) -> Self {
        AgentError::SerializationError(e.to_string())
    }
}

impl From<std::io::Error> for AgentError {
    fn from(e: std::io::Error) -> Self {
        AgentError::IoError(e.to_string())
    }
}

impl From<toml::de::Error> for AgentError {
    fn from(e: toml::de::Error) -> Self {
        AgentError::ConfigError(e.to_string())
    }
}

impl From<aes_gcm::Error> for AgentError {
    fn from(_e: aes_gcm::Error) -> Self {
        AgentError::CryptoError("AES-GCM operation failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let e = AgentError::PolicyDenied("shell_exec requires owner role".into());
        assert!(e.to_string().contains("policy denied"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let agent_err: AgentError = io_err.into();
        assert!(matches!(agent_err, AgentError::IoError(_)));
    }

    #[test]
    fn test_all_error_display() {
        let cases: Vec<AgentError> = vec![
            AgentError::CryptoError("bad key".into()),
            AgentError::ConnectionError("refused".into()),
            AgentError::PolicyDenied("no".into()),
            AgentError::InvalidCapability("foo".into()),
            AgentError::SessionExpired,
            AgentError::InvalidParameter("x".into()),
            AgentError::Timeout(30),
            AgentError::ExecutionError("fail".into()),
            AgentError::SerializationError("json".into()),
            AgentError::IoError("disk".into()),
            AgentError::ConfigError("toml".into()),
            AgentError::NotFound("missing".into()),
            AgentError::AuthenticationError("auth".into()),
            AgentError::InternalError("bug".into()),
        ];
        for e in &cases {
            let msg = e.to_string();
            assert!(!msg.is_empty());
        }
        assert!(cases[0].to_string().contains("crypto"));
        assert!(cases[1].to_string().contains("connection"));
        assert!(cases[4].to_string().contains("session expired"));
        assert!(cases[6].to_string().contains("30"));
    }

    #[test]
    fn test_serde_json_error_conversion() {
        let bad_json = serde_json::from_str::<serde_json::Value>("not json");
        let agent_err: AgentError = bad_json.unwrap_err().into();
        assert!(matches!(agent_err, AgentError::SerializationError(_)));
        assert!(agent_err.to_string().contains("serialization"));
    }

    #[test]
    fn test_toml_error_conversion() {
        let bad_toml = toml::from_str::<toml::Value>("= invalid");
        let agent_err: AgentError = bad_toml.unwrap_err().into();
        assert!(matches!(agent_err, AgentError::ConfigError(_)));
    }

    #[test]
    fn test_aes_gcm_error_conversion() {
        // aes_gcm::Error is opaque but we can trigger it via From impl
        // Manually construct by using the From impl's pattern
        let e: AgentError = aes_gcm::Error.into();
        assert!(matches!(e, AgentError::CryptoError(_)));
        assert!(e.to_string().contains("AES-GCM"));
    }
}

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
}

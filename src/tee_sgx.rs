//! Intel SGX TEE backend (feature-gated stub).
//!
//! This module provides the [`SgxEnclave`] type — a placeholder for real Intel SGX
//! integration via the Intel SGX SDK. When compiled without the `sgx` feature
//! (the default), all operations return a stub error.
//!
//! Enable with: `cargo build --features sgx`

use crate::error::AgentError;
use crate::tee::{
    AttestationReport, EnclaveConfig, EnclaveState, SealPolicy, SealedData, TeePlatform,
};
use serde::{Deserialize, Serialize};

/// Intel SGX enclave wrapper.
///
/// In production, this would use `sgx_urts` and `sgx_types` to manage a real
/// enclave. The current implementation is a compile-time stub.
#[derive(Debug)]
pub struct SgxEnclave {
    config: EnclaveConfig,
    state: EnclaveState,
    enclave_id: u64,
}

/// SGX-specific error details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SgxError {
    /// SGX SDK error code.
    pub code: u32,
    /// Human-readable description.
    pub message: String,
}

impl std::fmt::Display for SgxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SGX error {}: {}", self.code, self.message)
    }
}

impl SgxEnclave {
    /// Create a new SGX enclave instance.
    ///
    /// # Errors
    /// Returns `AgentError::InternalError` if SGX is not available on this platform.
    pub fn new(config: EnclaveConfig) -> Result<Self, AgentError> {
        if config.platform != TeePlatform::IntelSgx {
            return Err(AgentError::InternalError(
                "SgxEnclave requires IntelSgx platform".into(),
            ));
        }

        Ok(Self {
            config,
            state: EnclaveState::Uninitialized,
            enclave_id: 0,
        })
    }

    /// Initialize the SGX enclave.
    ///
    /// In production: loads the signed enclave binary and creates the enclave.
    /// Stub: transitions state to Ready.
    pub fn initialize(&mut self) -> Result<(), AgentError> {
        #[cfg(feature = "sgx")]
        {
            // Real SGX initialization would go here:
            // let enclave = SgxEnclave::create(ENCLAVE_FILE, debug)?;
            // self.enclave_id = enclave.geteid();
            return Err(AgentError::InternalError(
                "SGX SDK integration not yet linked".into(),
            ));
        }

        #[cfg(not(feature = "sgx"))]
        {
            // Stub mode: simulate initialization
            self.state = EnclaveState::Ready;
            self.enclave_id = 1;
            Ok(())
        }
    }

    /// Get the enclave state.
    pub fn state(&self) -> EnclaveState {
        self.state
    }

    /// Get the SGX enclave ID (0 if not initialized).
    pub fn enclave_id(&self) -> u64 {
        self.enclave_id
    }

    /// Generate a remote attestation report.
    ///
    /// In production: performs EPID or DCAP attestation via Intel Attestation Service.
    /// Stub: returns a simulated report.
    pub fn remote_attest(&self, report_data: &[u8]) -> Result<AttestationReport, AgentError> {
        if self.state != EnclaveState::Ready {
            return Err(AgentError::InternalError("SGX enclave not ready".into()));
        }

        // Stub attestation report
        Ok(AttestationReport {
            platform: TeePlatform::IntelSgx,
            measurement: "sgx-stub-mrenclave-0000".into(),
            signer: "sgx-stub-mrsigner-0000".into(),
            product_id: self.config.num_tcs as u16,
            svn: 1,
            report_data: hex::encode(report_data),
            timestamp: chrono::Utc::now().timestamp() as u64,
            signature: "sgx-stub-signature".into(),
        })
    }

    /// Seal data to the enclave identity.
    ///
    /// In production: uses SGX sealing primitives (EGETKEY + AES-GCM).
    /// Stub: returns an error indicating SGX sealing is not available.
    pub fn seal(
        &self,
        _key: &str,
        _data: &[u8],
        _policy: SealPolicy,
    ) -> Result<SealedData, AgentError> {
        if self.state != EnclaveState::Ready {
            return Err(AgentError::InternalError("SGX enclave not ready".into()));
        }

        Err(AgentError::InternalError(
            "SGX sealing requires Intel SGX SDK (enable 'sgx' feature)".into(),
        ))
    }

    /// Unseal data from the enclave.
    pub fn unseal(&self, _key: &str) -> Result<Vec<u8>, AgentError> {
        Err(AgentError::InternalError(
            "SGX unsealing requires Intel SGX SDK (enable 'sgx' feature)".into(),
        ))
    }

    /// Destroy the enclave.
    pub fn destroy(&mut self) {
        self.state = EnclaveState::Destroyed;
        self.enclave_id = 0;
    }

    /// Check if real SGX hardware is available on this system.
    pub fn is_sgx_available() -> bool {
        // In production: check CPUID for SGX support
        // Stub: always false
        false
    }

    /// Get enclave config.
    pub fn config(&self) -> &EnclaveConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sgx_config() -> EnclaveConfig {
        EnclaveConfig {
            platform: TeePlatform::IntelSgx,
            heap_size: 1024 * 1024,
            stack_size: 256 * 1024,
            num_tcs: 8,
            debug: true,
        }
    }

    #[test]
    fn test_sgx_enclave_creation() {
        let enclave = SgxEnclave::new(sgx_config()).unwrap();
        assert_eq!(enclave.state(), EnclaveState::Uninitialized);
        assert_eq!(enclave.enclave_id(), 0);
    }

    #[test]
    fn test_sgx_wrong_platform() {
        let config = EnclaveConfig {
            platform: TeePlatform::Simulator,
            ..EnclaveConfig::default()
        };
        assert!(SgxEnclave::new(config).is_err());
    }

    #[test]
    fn test_sgx_stub_initialize() {
        let mut enclave = SgxEnclave::new(sgx_config()).unwrap();
        enclave.initialize().unwrap();
        assert_eq!(enclave.state(), EnclaveState::Ready);
        assert_eq!(enclave.enclave_id(), 1);
    }

    #[test]
    fn test_sgx_stub_attestation() {
        let mut enclave = SgxEnclave::new(sgx_config()).unwrap();
        enclave.initialize().unwrap();
        let report = enclave.remote_attest(b"challenge").unwrap();
        assert_eq!(report.platform, TeePlatform::IntelSgx);
        assert!(!report.measurement.is_empty());
    }

    #[test]
    fn test_sgx_attestation_not_ready() {
        let enclave = SgxEnclave::new(sgx_config()).unwrap();
        assert!(enclave.remote_attest(b"test").is_err());
    }

    #[test]
    fn test_sgx_seal_stub_error() {
        let mut enclave = SgxEnclave::new(sgx_config()).unwrap();
        enclave.initialize().unwrap();
        assert!(enclave.seal("key", b"data", SealPolicy::MrEnclave).is_err());
    }

    #[test]
    fn test_sgx_destroy() {
        let mut enclave = SgxEnclave::new(sgx_config()).unwrap();
        enclave.initialize().unwrap();
        enclave.destroy();
        assert_eq!(enclave.state(), EnclaveState::Destroyed);
        assert_eq!(enclave.enclave_id(), 0);
    }

    #[test]
    fn test_sgx_not_available() {
        assert!(!SgxEnclave::is_sgx_available());
    }

    #[test]
    fn test_sgx_error_display() {
        let err = SgxError {
            code: 1,
            message: "test error".into(),
        };
        assert_eq!(err.to_string(), "SGX error 1: test error");
    }
}

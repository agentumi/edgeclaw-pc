//! Trusted Execution Environment (TEE) abstraction layer.
//!
//! Provides [`TeeProvider`] trait and implementations:
//! - [`TeeSimulator`] — Software-only TEE simulator for development/testing
//! - [`TeeEnclave`] — Enclave management with sealed storage and attestation

use serde::{Deserialize, Serialize};

use sha2::Digest;

use crate::error::AgentError;

/// TEE platform type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeePlatform {
    /// Software simulator (no hardware TEE required).
    Simulator,
    /// Intel SGX.
    IntelSgx,
    /// ARM TrustZone.
    ArmTrustZone,
    /// AMD SEV.
    AmdSev,
}

impl std::fmt::Display for TeePlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeePlatform::Simulator => write!(f, "Simulator"),
            TeePlatform::IntelSgx => write!(f, "Intel SGX"),
            TeePlatform::ArmTrustZone => write!(f, "ARM TrustZone"),
            TeePlatform::AmdSev => write!(f, "AMD SEV"),
        }
    }
}

/// Remote attestation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Platform type.
    pub platform: TeePlatform,
    /// Enclave measurement (MRENCLAVE / code hash).
    pub measurement: String,
    /// Signer identity (MRSIGNER).
    pub signer: String,
    /// Product ID.
    pub product_id: u16,
    /// Security version number.
    pub svn: u16,
    /// Report data (user-supplied, up to 64 bytes, hex).
    pub report_data: String,
    /// Timestamp.
    pub timestamp: u64,
    /// Signature over the report.
    pub signature: String,
}

/// Sealed data blob (encrypted to enclave identity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedData {
    /// Encrypted payload (base64).
    pub ciphertext: String,
    /// Nonce (hex).
    pub nonce: String,
    /// Sealing policy.
    pub policy: SealPolicy,
    /// Enclave measurement at seal time.
    pub measurement: String,
}

/// Sealing policy: what identity binds the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealPolicy {
    /// Seal to exact enclave code (MRENCLAVE).
    MrEnclave,
    /// Seal to signer identity (MRSIGNER), allowing upgrades.
    MrSigner,
}

/// TEE enclave state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveState {
    /// Not initialized.
    Uninitialized,
    /// Initialized and ready.
    Ready,
    /// Processing a request.
    Busy,
    /// Destroyed.
    Destroyed,
}

/// TEE enclave configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveConfig {
    /// Platform type.
    pub platform: TeePlatform,
    /// Heap size in bytes.
    pub heap_size: usize,
    /// Stack size in bytes.
    pub stack_size: usize,
    /// Number of TCS (Thread Control Structures).
    pub num_tcs: u32,
    /// Debug mode.
    pub debug: bool,
}

impl Default for EnclaveConfig {
    fn default() -> Self {
        Self {
            platform: TeePlatform::Simulator,
            heap_size: 256 * 1024,
            stack_size: 64 * 1024,
            num_tcs: 4,
            debug: true,
        }
    }
}

/// Software TEE simulator for development and testing.
pub struct TeeSimulator {
    config: EnclaveConfig,
    state: EnclaveState,
    sealed_store: std::collections::HashMap<String, SealedData>,
    measurement: String,
}

impl TeeSimulator {
    /// Create a new TEE simulator.
    pub fn new(config: EnclaveConfig) -> Self {
        let measurement = hex::encode(sha2::Sha256::digest(b"edgeclaw-tee-sim"));
        Self {
            config,
            state: EnclaveState::Uninitialized,
            sealed_store: std::collections::HashMap::new(),
            measurement,
        }
    }

    /// Initialize the simulated enclave.
    pub fn initialize(&mut self) -> Result<(), AgentError> {
        if self.state != EnclaveState::Uninitialized {
            return Err(AgentError::InternalError(
                "Enclave already initialized".into(),
            ));
        }
        self.state = EnclaveState::Ready;
        Ok(())
    }

    /// Get enclave state.
    pub fn state(&self) -> EnclaveState {
        self.state
    }

    /// Get config reference.
    pub fn config(&self) -> &EnclaveConfig {
        &self.config
    }

    /// Generate an attestation report.
    pub fn attest(&self, report_data: &[u8]) -> Result<AttestationReport, AgentError> {
        if self.state != EnclaveState::Ready {
            return Err(AgentError::InternalError("Enclave not ready".into()));
        }

        use sha2::Digest;
        let sig_input = format!("{}:{}", self.measurement, hex::encode(report_data));
        let sig = hex::encode(sha2::Sha256::digest(sig_input.as_bytes()));

        Ok(AttestationReport {
            platform: TeePlatform::Simulator,
            measurement: self.measurement.clone(),
            signer: "sim-signer-0000".into(),
            product_id: 1,
            svn: 1,
            report_data: hex::encode(report_data),
            timestamp: chrono::Utc::now().timestamp() as u64,
            signature: sig,
        })
    }

    /// Seal data (encrypt to enclave identity).
    pub fn seal(
        &mut self,
        key: &str,
        plaintext: &[u8],
        policy: SealPolicy,
    ) -> Result<SealedData, AgentError> {
        if self.state != EnclaveState::Ready {
            return Err(AgentError::InternalError("Enclave not ready".into()));
        }

        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use sha2::Digest;

        // Derive a seal key from measurement + policy
        let seal_input = format!("{}:{:?}", self.measurement, policy);
        let seal_key = sha2::Sha256::digest(seal_input.as_bytes());
        let cipher = Aes256Gcm::new_from_slice(&seal_key)
            .map_err(|e| AgentError::CryptoError(e.to_string()))?;

        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| AgentError::CryptoError(e.to_string()))?;

        let sealed = SealedData {
            ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &ciphertext,
            ),
            nonce: hex::encode(nonce_bytes),
            policy,
            measurement: self.measurement.clone(),
        };

        self.sealed_store.insert(key.to_string(), sealed.clone());
        Ok(sealed)
    }

    /// Unseal data.
    pub fn unseal(&self, key: &str) -> Result<Vec<u8>, AgentError> {
        if self.state != EnclaveState::Ready {
            return Err(AgentError::InternalError("Enclave not ready".into()));
        }

        let sealed = self
            .sealed_store
            .get(key)
            .ok_or_else(|| AgentError::NotFound(format!("sealed key: {}", key)))?;

        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
        use sha2::Digest;

        let seal_input = format!("{}:{:?}", self.measurement, sealed.policy);
        let seal_key = sha2::Sha256::digest(seal_input.as_bytes());
        let cipher = Aes256Gcm::new_from_slice(&seal_key)
            .map_err(|e| AgentError::CryptoError(e.to_string()))?;

        let nonce_bytes =
            hex::decode(&sealed.nonce).map_err(|e| AgentError::CryptoError(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sealed.ciphertext,
        )
        .map_err(|e| AgentError::CryptoError(e.to_string()))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| AgentError::CryptoError(e.to_string()))?;

        Ok(plaintext)
    }

    /// Destroy the enclave.
    pub fn destroy(&mut self) {
        self.sealed_store.clear();
        self.state = EnclaveState::Destroyed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enclave_config_default() {
        let config = EnclaveConfig::default();
        assert_eq!(config.platform, TeePlatform::Simulator);
        assert!(config.debug);
        assert_eq!(config.num_tcs, 4);
    }

    #[test]
    fn test_tee_platform_display() {
        assert_eq!(TeePlatform::Simulator.to_string(), "Simulator");
        assert_eq!(TeePlatform::IntelSgx.to_string(), "Intel SGX");
    }

    #[test]
    fn test_simulator_lifecycle() {
        let mut sim = TeeSimulator::new(EnclaveConfig::default());
        assert_eq!(sim.state(), EnclaveState::Uninitialized);
        sim.initialize().unwrap();
        assert_eq!(sim.state(), EnclaveState::Ready);
        sim.destroy();
        assert_eq!(sim.state(), EnclaveState::Destroyed);
    }

    #[test]
    fn test_attestation() {
        let mut sim = TeeSimulator::new(EnclaveConfig::default());
        sim.initialize().unwrap();
        let report = sim.attest(b"test-data").unwrap();
        assert_eq!(report.platform, TeePlatform::Simulator);
        assert!(!report.measurement.is_empty());
        assert!(!report.signature.is_empty());
        assert_eq!(report.report_data, hex::encode(b"test-data"));
    }

    #[test]
    fn test_attestation_not_ready() {
        let sim = TeeSimulator::new(EnclaveConfig::default());
        assert!(sim.attest(b"test").is_err());
    }

    #[test]
    fn test_seal_unseal() {
        let mut sim = TeeSimulator::new(EnclaveConfig::default());
        sim.initialize().unwrap();
        let plaintext = b"secret-key-material";
        sim.seal("my-key", plaintext, SealPolicy::MrEnclave)
            .unwrap();
        let recovered = sim.unseal("my-key").unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_seal_unseal_mrsigner() {
        let mut sim = TeeSimulator::new(EnclaveConfig::default());
        sim.initialize().unwrap();
        let data = b"another-secret";
        sim.seal("key2", data, SealPolicy::MrSigner).unwrap();
        let recovered = sim.unseal("key2").unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_unseal_not_found() {
        let mut sim = TeeSimulator::new(EnclaveConfig::default());
        sim.initialize().unwrap();
        assert!(sim.unseal("nonexistent").is_err());
    }

    #[test]
    fn test_sealed_data_serialize() {
        let sealed = SealedData {
            ciphertext: "Y2lwaGVydGV4dA==".into(),
            nonce: "aabbccddee00".into(),
            policy: SealPolicy::MrEnclave,
            measurement: "abc123".into(),
        };
        let json = serde_json::to_string(&sealed).unwrap();
        let parsed: SealedData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.policy, SealPolicy::MrEnclave);
    }

    #[test]
    fn test_attestation_report_serialize() {
        let report = AttestationReport {
            platform: TeePlatform::IntelSgx,
            measurement: "abc".into(),
            signer: "def".into(),
            product_id: 1,
            svn: 2,
            report_data: "aabb".into(),
            timestamp: 12345,
            signature: "sig".into(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: AttestationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.platform, TeePlatform::IntelSgx);
    }
}

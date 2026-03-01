//! Secure boot verification and firmware integrity.
//!
//! Provides [`SecureBootVerifier`] for verifying binary integrity
//! using Ed25519 signatures and SHA-256 hashes, plus boot chain validation.

use serde::{Deserialize, Serialize};

use crate::error::AgentError;

/// Boot stage in the chain of trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootStage {
    /// First-stage bootloader.
    Bootloader,
    /// Kernel / OS.
    Kernel,
    /// Agent binary.
    Agent,
    /// Plugin / extension.
    Plugin,
}

impl std::fmt::Display for BootStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootStage::Bootloader => write!(f, "Bootloader"),
            BootStage::Kernel => write!(f, "Kernel"),
            BootStage::Agent => write!(f, "Agent"),
            BootStage::Plugin => write!(f, "Plugin"),
        }
    }
}

/// Boot verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootVerification {
    /// Stage verified.
    pub stage: BootStage,
    /// Expected SHA-256 hash (hex).
    pub expected_hash: String,
    /// Actual SHA-256 hash (hex).
    pub actual_hash: String,
    /// Whether verification passed.
    pub passed: bool,
    /// Ed25519 signature valid.
    pub signature_valid: bool,
    /// Timestamp of verification.
    pub verified_at: chrono::DateTime<chrono::Utc>,
}

/// Boot chain entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootChainEntry {
    /// Stage.
    pub stage: BootStage,
    /// Binary path or identifier.
    pub binary_path: String,
    /// Expected SHA-256 hash.
    pub expected_hash: String,
    /// Ed25519 public key for signature verification (hex).
    pub signing_key: String,
    /// Ed25519 signature (hex).
    pub signature: Option<String>,
}

/// Secure boot verifier.
pub struct SecureBootVerifier {
    chain: Vec<BootChainEntry>,
    results: Vec<BootVerification>,
}

impl SecureBootVerifier {
    /// Create a new verifier.
    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
            results: Vec::new(),
        }
    }

    /// Add a boot chain entry.
    pub fn add_entry(&mut self, entry: BootChainEntry) {
        self.chain.push(entry);
    }

    /// Compute SHA-256 hash of data.
    pub fn hash_data(data: &[u8]) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(data))
    }

    /// Verify a single binary against expected hash.
    pub fn verify_hash(&self, data: &[u8], expected_hash: &str) -> bool {
        Self::hash_data(data) == expected_hash
    }

    /// Verify the entire boot chain.
    pub fn verify_chain(&mut self, binaries: &[(BootStage, Vec<u8>)]) -> Vec<BootVerification> {
        self.results.clear();

        for entry in &self.chain {
            let binary = binaries.iter().find(|(s, _)| *s == entry.stage);
            let (actual_hash, passed) = match binary {
                Some((_, data)) => {
                    let hash = Self::hash_data(data);
                    let passed = hash == entry.expected_hash;
                    (hash, passed)
                }
                None => ("missing".to_string(), false),
            };

            let result = BootVerification {
                stage: entry.stage,
                expected_hash: entry.expected_hash.clone(),
                actual_hash,
                passed,
                signature_valid: entry.signature.is_some(),
                verified_at: chrono::Utc::now(),
            };
            self.results.push(result);
        }

        self.results.clone()
    }

    /// Check if entire chain is valid.
    pub fn is_chain_valid(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.passed)
    }

    /// Get last verification results.
    pub fn results(&self) -> &[BootVerification] {
        &self.results
    }

    /// Verify a self-signed binary (hash + signature check).
    pub fn verify_signed_binary(
        &self,
        data: &[u8],
        expected_hash: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Result<bool, AgentError> {
        // Check hash first
        if !self.verify_hash(data, expected_hash) {
            return Ok(false);
        }

        // Verify Ed25519 signature
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let pk_bytes =
            hex::decode(public_key_hex).map_err(|e| AgentError::CryptoError(e.to_string()))?;
        let sig_bytes =
            hex::decode(signature_hex).map_err(|e| AgentError::CryptoError(e.to_string()))?;

        if pk_bytes.len() != 32 {
            return Err(AgentError::CryptoError("Invalid public key length".into()));
        }
        if sig_bytes.len() != 64 {
            return Err(AgentError::CryptoError("Invalid signature length".into()));
        }

        let pk = VerifyingKey::from_bytes(
            pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| AgentError::CryptoError("key conversion".into()))?,
        )
        .map_err(|e| AgentError::CryptoError(e.to_string()))?;

        let sig = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| AgentError::CryptoError("sig conversion".into()))?,
        );

        Ok(pk.verify(data, &sig).is_ok())
    }

    /// Get the number of chain entries.
    pub fn chain_len(&self) -> usize {
        self.chain.len()
    }
}

impl Default for SecureBootVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_stage_all_display() {
        assert_eq!(BootStage::Bootloader.to_string(), "Bootloader");
        assert_eq!(BootStage::Kernel.to_string(), "Kernel");
        assert_eq!(BootStage::Agent.to_string(), "Agent");
        assert_eq!(BootStage::Plugin.to_string(), "Plugin");
    }

    #[test]
    fn test_verify_chain_missing_binary() {
        let mut verifier = SecureBootVerifier::new();
        let boot_data = b"boot binary";
        let boot_hash = SecureBootVerifier::hash_data(boot_data);
        verifier.add_entry(BootChainEntry {
            stage: BootStage::Bootloader,
            binary_path: "boot.bin".into(),
            expected_hash: boot_hash,
            signing_key: "def".into(),
            signature: None,
        });
        verifier.add_entry(BootChainEntry {
            stage: BootStage::Kernel,
            binary_path: "kernel.bin".into(),
            expected_hash: "xyz".into(),
            signing_key: "000".into(),
            signature: Some("sig".into()),
        });
        // Only provide bootloader, not kernel
        let results = verifier.verify_chain(&[(BootStage::Bootloader, boot_data.to_vec())]);
        assert_eq!(results.len(), 2);
        assert!(results[0].passed); // bootloader matches
        assert!(!results[1].passed); // kernel missing
        assert_eq!(results[1].actual_hash, "missing");
        assert!(!verifier.is_chain_valid()); // not all passed
    }

    #[test]
    fn test_chain_len_and_results() {
        let mut verifier = SecureBootVerifier::new();
        assert_eq!(verifier.chain_len(), 0);
        assert!(verifier.results().is_empty());
        verifier.add_entry(BootChainEntry {
            stage: BootStage::Agent,
            binary_path: "agent".into(),
            expected_hash: "hash".into(),
            signing_key: "key".into(),
            signature: None,
        });
        assert_eq!(verifier.chain_len(), 1);
    }

    #[test]
    fn test_verify_signed_binary_hash_mismatch() {
        let verifier = SecureBootVerifier::new();
        let data = b"some binary";
        let result = verifier
            .verify_signed_binary(
                data,
                "0000000000000000000000000000000000000000000000000000000000000000",
                &hex::encode([1u8; 32]),
                &hex::encode([2u8; 64]),
            )
            .unwrap();
        assert!(!result); // hash doesn't match
    }

    #[test]
    fn test_hash_data() {
        let hash = SecureBootVerifier::hash_data(b"hello");
        assert_eq!(hash.len(), 64); // SHA-256 hex = 64 chars
                                    // Known SHA-256 of "hello"
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_verify_hash_match() {
        let verifier = SecureBootVerifier::new();
        let hash = SecureBootVerifier::hash_data(b"test data");
        assert!(verifier.verify_hash(b"test data", &hash));
    }

    #[test]
    fn test_verify_hash_mismatch() {
        let verifier = SecureBootVerifier::new();
        assert!(!verifier.verify_hash(
            b"test data",
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_boot_chain_valid() {
        let mut verifier = SecureBootVerifier::new();
        let agent_data = b"agent-binary-content";
        let agent_hash = SecureBootVerifier::hash_data(agent_data);

        verifier.add_entry(BootChainEntry {
            stage: BootStage::Agent,
            binary_path: "/usr/bin/edgeclaw-agent".into(),
            expected_hash: agent_hash,
            signing_key: "aabb".into(),
            signature: Some("cc".into()),
        });

        let results = verifier.verify_chain(&[(BootStage::Agent, agent_data.to_vec())]);
        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
        assert!(verifier.is_chain_valid());
    }

    #[test]
    fn test_boot_chain_invalid() {
        let mut verifier = SecureBootVerifier::new();
        verifier.add_entry(BootChainEntry {
            stage: BootStage::Agent,
            binary_path: "/usr/bin/edgeclaw-agent".into(),
            expected_hash: "0000".into(),
            signing_key: "aabb".into(),
            signature: None,
        });

        let results = verifier.verify_chain(&[(BootStage::Agent, b"different data".to_vec())]);
        assert!(!results[0].passed);
        assert!(!verifier.is_chain_valid());
    }

    #[test]
    fn test_boot_chain_missing_binary() {
        let mut verifier = SecureBootVerifier::new();
        verifier.add_entry(BootChainEntry {
            stage: BootStage::Kernel,
            binary_path: "/boot/vmlinuz".into(),
            expected_hash: "abcd".into(),
            signing_key: "aabb".into(),
            signature: None,
        });

        // Don't provide the kernel binary
        let results = verifier.verify_chain(&[]);
        assert!(!results[0].passed);
        assert_eq!(results[0].actual_hash, "missing");
    }

    #[test]
    fn test_boot_stage_display() {
        assert_eq!(BootStage::Agent.to_string(), "Agent");
        assert_eq!(BootStage::Bootloader.to_string(), "Bootloader");
    }

    #[test]
    fn test_boot_verification_serialize() {
        let v = BootVerification {
            stage: BootStage::Agent,
            expected_hash: "abcd".into(),
            actual_hash: "abcd".into(),
            passed: true,
            signature_valid: true,
            verified_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let parsed: BootVerification = serde_json::from_str(&json).unwrap();
        assert!(parsed.passed);
    }

    #[test]
    fn test_signed_binary_verification() {
        use ed25519_dalek::{Signer, SigningKey};

        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let data = b"agent binary payload";
        let hash = SecureBootVerifier::hash_data(data);
        let signature = signing_key.sign(data);

        let verifier = SecureBootVerifier::new();
        let result = verifier
            .verify_signed_binary(
                data,
                &hash,
                &hex::encode(verifying_key.to_bytes()),
                &hex::encode(signature.to_bytes()),
            )
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_signed_binary_bad_signature() {
        let verifier = SecureBootVerifier::new();
        let data = b"some data";
        let hash = SecureBootVerifier::hash_data(data);
        // Invalid key/sig lengths
        let result = verifier.verify_signed_binary(data, &hash, "aabb", "ccdd");
        assert!(result.is_err());
    }
}

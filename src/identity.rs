use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::AgentError;

/// Device identity information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub device_name: String,
    pub public_key_hex: String,
    pub fingerprint: String,
    pub created_at: String,
    pub platform: String,
}

/// Manages Ed25519 signing + X25519 key exchange identity
pub struct IdentityManager {
    signing_key: Option<SigningKey>,
    x25519_secret: Option<StaticSecret>,
    identity: Option<DeviceIdentity>,
}

impl Default for IdentityManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityManager {
    pub fn new() -> Self {
        Self {
            signing_key: None,
            x25519_secret: None,
            identity: None,
        }
    }

    /// Generate a new device identity
    pub fn generate_identity(&mut self, device_name: &str) -> Result<DeviceIdentity, AgentError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let public_key_bytes = verifying_key.to_bytes();

        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = PublicKey::from(&x25519_secret);

        let device_id = uuid::Uuid::new_v4().to_string();
        let public_key_hex = hex::encode(public_key_bytes);

        let mut hasher = Sha256::new();
        hasher.update(public_key_bytes);
        hasher.update(x25519_public.as_bytes());
        let hash = hasher.finalize();
        let fingerprint = hex::encode(&hash[..8]);

        let platform = get_platform();

        let identity = DeviceIdentity {
            device_id,
            device_name: device_name.to_string(),
            public_key_hex,
            fingerprint,
            created_at: chrono::Utc::now().to_rfc3339(),
            platform,
        };

        self.signing_key = Some(signing_key);
        self.x25519_secret = Some(x25519_secret);
        self.identity = Some(identity.clone());

        Ok(identity)
    }

    /// Get the current identity
    pub fn get_identity(&self) -> Result<&DeviceIdentity, AgentError> {
        self.identity
            .as_ref()
            .ok_or(AgentError::InternalError("identity not generated".into()))
    }

    /// Get X25519 secret key bytes for session creation
    pub fn get_secret_key(&self) -> Result<[u8; 32], AgentError> {
        let secret = self
            .x25519_secret
            .as_ref()
            .ok_or(AgentError::InternalError("keys not generated".into()))?;
        Ok(secret.to_bytes())
    }

    /// Get X25519 public key bytes
    pub fn get_public_key(&self) -> Result<[u8; 32], AgentError> {
        let secret = self
            .x25519_secret
            .as_ref()
            .ok_or(AgentError::InternalError("keys not generated".into()))?;
        let public = PublicKey::from(secret);
        Ok(*public.as_bytes())
    }

    /// Sign data with Ed25519
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, AgentError> {
        use ed25519_dalek::Signer;
        let key = self.signing_key.as_ref().ok_or(AgentError::InternalError(
            "signing key not available".into(),
        ))?;
        let signature = key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

/// Detect the current platform string
fn get_platform() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    format!("{os}-{arch}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let mut mgr = IdentityManager::new();
        let identity = mgr.generate_identity("test-pc").unwrap();
        assert!(!identity.device_id.is_empty());
        assert_eq!(identity.device_name, "test-pc");
        assert_eq!(identity.public_key_hex.len(), 64);
        assert_eq!(identity.fingerprint.len(), 16);
        assert!(!identity.platform.is_empty());
    }

    #[test]
    fn test_get_keys() {
        let mut mgr = IdentityManager::new();
        mgr.generate_identity("test").unwrap();
        let secret = mgr.get_secret_key().unwrap();
        let public = mgr.get_public_key().unwrap();
        assert_ne!(secret, [0u8; 32]);
        assert_ne!(public, [0u8; 32]);
    }

    #[test]
    fn test_sign_data() {
        let mut mgr = IdentityManager::new();
        mgr.generate_identity("test").unwrap();
        let sig = mgr.sign(b"hello world").unwrap();
        assert_eq!(sig.len(), 64); // Ed25519 signature is 64 bytes
    }

    #[test]
    fn test_identity_before_generate() {
        let mgr = IdentityManager::new();
        assert!(mgr.get_identity().is_err());
        assert!(mgr.get_secret_key().is_err());
    }

    #[test]
    fn test_platform_detection() {
        let platform = get_platform();
        assert!(platform.contains('-'));
        // Should contain os-arch pattern
    }
}

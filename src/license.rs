//! License verification — tier enforcement and agent limits.
//!
//! Provides [`License`] for Ed25519-signed license validation with
//! tier-based feature gating (Free, Pro, Enterprise) and agent count limits.

use crate::error::AgentError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// License tiers
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    /// Free tier — limited features
    #[default]
    Free,
    /// Pro tier — WebSocket, Dashboard, more agents
    Pro,
    /// Enterprise tier — unlimited agents, full features
    Enterprise,
}

impl std::fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Free => write!(f, "free"),
            Self::Pro => write!(f, "pro"),
            Self::Enterprise => write!(f, "enterprise"),
        }
    }
}

/// License data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub tier: LicenseTier,
    pub max_agents: usize,
    pub issued_to: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Ed25519 signature of the license data (hex)
    pub signature: String,
}

impl Default for License {
    fn default() -> Self {
        Self::free()
    }
}

impl License {
    /// Create a free-tier license (no expiry limitation, 1 agent)
    pub fn free() -> Self {
        let now = Utc::now();
        Self {
            tier: LicenseTier::Free,
            max_agents: 1,
            issued_to: "community".to_string(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(365 * 100), // 100 years
            signature: String::new(),
        }
    }

    /// Check if the license has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if a new agent can be registered given current count
    pub fn can_register_agent(&self, current_count: usize) -> bool {
        if self.is_expired() {
            warn!("license expired, falling back to free tier limits");
            return current_count < 1;
        }
        current_count < self.max_agents
    }

    /// Check if a feature is available in the current tier
    pub fn has_feature(&self, feature: &str) -> bool {
        if self.is_expired() {
            return Self::tier_has_feature(&LicenseTier::Free, feature);
        }
        Self::tier_has_feature(&self.tier, feature)
    }

    /// Check if a specific tier has the given feature
    fn tier_has_feature(tier: &LicenseTier, feature: &str) -> bool {
        match tier {
            LicenseTier::Free => matches!(
                feature,
                "basic_chat" | "local_commands" | "single_agent" | "audit_log"
            ),
            LicenseTier::Pro => {
                Self::tier_has_feature(&LicenseTier::Free, feature)
                    || matches!(
                        feature,
                        "websocket"
                            | "dashboard"
                            | "multi_agent"
                            | "cloud_ai"
                            | "prometheus"
                            | "ota_updates"
                    )
            }
            LicenseTier::Enterprise => true, // All features
        }
    }

    /// Verify the license signature using Ed25519
    pub fn verify_signature(&self, public_key_hex: &str) -> Result<bool, AgentError> {
        if self.signature.is_empty() {
            // Free licenses don't require signatures
            if self.tier == LicenseTier::Free {
                return Ok(true);
            }
            return Err(AgentError::AuthenticationError(
                "missing license signature".into(),
            ));
        }

        let public_key_bytes = hex::decode(public_key_hex)
            .map_err(|e| AgentError::CryptoError(format!("invalid public key hex: {e}")))?;

        if public_key_bytes.len() != 32 {
            return Err(AgentError::CryptoError("invalid public key length".into()));
        }

        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| AgentError::CryptoError(format!("invalid signature hex: {e}")))?;

        if sig_bytes.len() != 64 {
            return Err(AgentError::CryptoError("invalid signature length".into()));
        }

        use ed25519_dalek::{Signature, VerifyingKey};
        let vk_bytes: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| AgentError::CryptoError("key conversion failed".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|e| AgentError::CryptoError(format!("invalid key: {e}")))?;

        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AgentError::CryptoError("sig conversion failed".into()))?;
        let signature = Signature::from_bytes(&sig_array);

        // Construct the signed data (JSON without signature field)
        let signed_data = format!(
            "{}:{}:{}:{}:{}",
            self.tier, self.max_agents, self.issued_to, self.issued_at, self.expires_at
        );

        use ed25519_dalek::Verifier;
        match verifying_key.verify(signed_data.as_bytes(), &signature) {
            Ok(_) => {
                info!(tier = %self.tier, "license signature verified");
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    /// Get the effective tier (downgrades to Free if expired)
    pub fn effective_tier(&self) -> LicenseTier {
        if self.is_expired() {
            LicenseTier::Free
        } else {
            self.tier.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_free_license() {
        let lic = License::free();
        assert_eq!(lic.tier, LicenseTier::Free);
        assert_eq!(lic.max_agents, 1);
        assert!(!lic.is_expired());
    }

    #[test]
    fn test_agent_limit_free() {
        let lic = License::free();
        assert!(lic.can_register_agent(0));
        assert!(!lic.can_register_agent(1));
    }

    #[test]
    fn test_agent_limit_pro() {
        let now = Utc::now();
        let lic = License {
            tier: LicenseTier::Pro,
            max_agents: 10,
            issued_to: "test".to_string(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(365),
            signature: String::new(),
        };
        assert!(lic.can_register_agent(9));
        assert!(!lic.can_register_agent(10));
    }

    #[test]
    fn test_expired_license() {
        let now = Utc::now();
        let lic = License {
            tier: LicenseTier::Pro,
            max_agents: 10,
            issued_to: "test".to_string(),
            issued_at: now - chrono::Duration::days(365),
            expires_at: now - chrono::Duration::days(1),
            signature: String::new(),
        };
        assert!(lic.is_expired());
        assert_eq!(lic.effective_tier(), LicenseTier::Free);
        assert!(!lic.can_register_agent(1)); // Falls back to Free limit
    }

    #[test]
    fn test_features_free() {
        let lic = License::free();
        assert!(lic.has_feature("basic_chat"));
        assert!(lic.has_feature("local_commands"));
        assert!(!lic.has_feature("websocket"));
        assert!(!lic.has_feature("dashboard"));
        assert!(!lic.has_feature("multi_agent"));
    }

    #[test]
    fn test_features_pro() {
        let now = Utc::now();
        let lic = License {
            tier: LicenseTier::Pro,
            max_agents: 10,
            issued_to: "test".to_string(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(365),
            signature: String::new(),
        };
        assert!(lic.has_feature("basic_chat"));
        assert!(lic.has_feature("websocket"));
        assert!(lic.has_feature("dashboard"));
        assert!(lic.has_feature("multi_agent"));
        assert!(!lic.has_feature("custom_plugins"));
    }

    #[test]
    fn test_features_enterprise() {
        let now = Utc::now();
        let lic = License {
            tier: LicenseTier::Enterprise,
            max_agents: 1000,
            issued_to: "corp".to_string(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(365),
            signature: String::new(),
        };
        assert!(lic.has_feature("anything_goes"));
        assert!(lic.has_feature("custom_plugins"));
    }

    #[test]
    fn test_free_license_no_sig_ok() {
        let lic = License::free();
        let result = lic.verify_signature("00".repeat(32).as_str());
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_tier_display() {
        assert_eq!(LicenseTier::Free.to_string(), "free");
        assert_eq!(LicenseTier::Pro.to_string(), "pro");
        assert_eq!(LicenseTier::Enterprise.to_string(), "enterprise");
    }

    #[test]
    fn test_default_license() {
        let lic = License::default();
        assert_eq!(lic.tier, LicenseTier::Free);
    }

    #[test]
    fn test_license_serialization() {
        let lic = License::free();
        let json = serde_json::to_string(&lic).unwrap();
        assert!(json.contains("\"free\""));

        let deserialized: License = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.tier, LicenseTier::Free);
    }

    #[test]
    fn test_verify_signature_missing_for_pro() {
        let now = Utc::now();
        let lic = License {
            tier: LicenseTier::Pro,
            max_agents: 10,
            issued_to: "test".into(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(365),
            signature: String::new(), // missing!
        };
        let result = lic.verify_signature(&"00".repeat(32));
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_bad_pubkey_hex() {
        let now = Utc::now();
        let lic = License {
            tier: LicenseTier::Pro,
            max_agents: 10,
            issued_to: "test".into(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(365),
            signature: "aa".repeat(64),
        };
        let result = lic.verify_signature("zzzz_not_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_wrong_key_length() {
        let now = Utc::now();
        let lic = License {
            tier: LicenseTier::Pro,
            max_agents: 10,
            issued_to: "test".into(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(365),
            signature: "aa".repeat(64),
        };
        // 16 bytes instead of 32
        let result = lic.verify_signature(&"aa".repeat(16));
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_wrong_sig_length() {
        let now = Utc::now();
        let lic = License {
            tier: LicenseTier::Pro,
            max_agents: 10,
            issued_to: "test".into(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(365),
            signature: "aa".repeat(10), // too short (should be 64 bytes)
        };
        let result = lic.verify_signature(&"00".repeat(32));
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_invalid_signature() {
        let now = Utc::now();
        let lic = License {
            tier: LicenseTier::Pro,
            max_agents: 10,
            issued_to: "test".into(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(365),
            signature: "00".repeat(64),
        };
        // Valid key length but wrong key — signature won't verify
        // Need a valid Ed25519 public key (32 bytes)
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let result = lic.verify_signature(&pk_hex);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // signature is all zeros, won't match
    }

    #[test]
    fn test_license_tier_default() {
        assert_eq!(LicenseTier::default(), LicenseTier::Free);
    }

    #[test]
    fn test_expired_license_feature_downgrade() {
        let now = Utc::now();
        let lic = License {
            tier: LicenseTier::Enterprise,
            max_agents: 1000,
            issued_to: "expired-corp".into(),
            issued_at: now - chrono::Duration::days(366),
            expires_at: now - chrono::Duration::days(1),
            signature: String::new(),
        };
        // Expired enterprise should not have pro features
        assert!(!lic.has_feature("websocket"));
        assert!(!lic.has_feature("dashboard"));
        // But should have free features
        assert!(lic.has_feature("basic_chat"));
    }

    #[test]
    fn test_effective_tier_not_expired() {
        let now = Utc::now();
        let lic = License {
            tier: LicenseTier::Enterprise,
            max_agents: 1000,
            issued_to: "valid-corp".into(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(365),
            signature: String::new(),
        };
        assert_eq!(lic.effective_tier(), LicenseTier::Enterprise);
    }
}

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Metadata for Agent Passport
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PassportMetadata {
    pub name: String,
    pub protocols: Vec<String>,       // e.g., "ECNP", "MCP", "A2A"
    pub payment_methods: Vec<String>, // e.g., "X402", "SuiEscrow", "Direct"
    pub description: Option<String>,
}

/// Capability Manifest v2 (ECM v2)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityManifestV2 {
    pub device_id: String,
    pub platform: String,
    pub capabilities: Vec<String>,
    pub mcp_compatible: bool,
    pub a2a_capable: bool,
}

/// AgentPassport for on-chain identity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentPassport {
    pub id: Uuid,
    pub device_pubkey: String,
    pub nft_object_id: Option<String>,
    pub capabilities: CapabilityManifestV2,
    pub metadata: PassportMetadata,
    pub reputation_score: f64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl AgentPassport {
    pub fn new(
        device_pubkey: String,
        name: String,
        platform: String,
        capabilities: Vec<String>,
        mcp_compatible: bool,
        a2a_capable: bool,
    ) -> Self {
        let metadata = PassportMetadata {
            name,
            protocols: vec!["ECNP".to_string(), "MCP".to_string(), "A2A".to_string()],
            payment_methods: vec!["SuiEscrow".to_string()],
            description: None,
        };

        let cap_manifest = CapabilityManifestV2 {
            device_id: device_pubkey.clone(),
            platform,
            capabilities,
            mcp_compatible,
            a2a_capable,
        };

        Self {
            id: Uuid::new_v4(),
            device_pubkey,
            nft_object_id: None,
            capabilities: cap_manifest,
            metadata,
            reputation_score: 0.0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn link_nft(&mut self, object_id: String) {
        self.nft_object_id = Some(object_id);
        self.updated_at = Utc::now();
    }

    pub fn update_reputation(&mut self, score: f64) {
        self.reputation_score = score;
        self.updated_at = Utc::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passport_creation() {
        let passport = AgentPassport::new(
            "pubkey_123".to_string(),
            "Agent Alpha".to_string(),
            "linux".to_string(),
            vec!["shell_exec".to_string()],
            true,
            true,
        );

        assert_eq!(passport.device_pubkey, "pubkey_123");
        assert_eq!(passport.metadata.name, "Agent Alpha");
        assert!(passport.capabilities.mcp_compatible);
        assert_eq!(passport.reputation_score, 0.0);
    }

    #[test]
    fn test_passport_link_nft() {
        let mut passport = AgentPassport::new(
            "pubkey_123".to_string(),
            "Agent Beta".to_string(),
            "macOS".to_string(),
            vec![],
            false,
            false,
        );

        assert!(passport.nft_object_id.is_none());
        passport.link_nft("0xabcd1234".to_string());
        assert_eq!(passport.nft_object_id.unwrap(), "0xabcd1234");
    }

    #[test]
    fn test_passport_update_reputation() {
        let mut passport = AgentPassport::new(
            "pubkey_123".to_string(),
            "Agent Gamma".to_string(),
            "windows".to_string(),
            vec![],
            false,
            false,
        );

        passport.update_reputation(95.5);
        assert_eq!(passport.reputation_score, 95.5);
    }
}

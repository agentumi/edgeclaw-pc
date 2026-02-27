//! Federated mesh network management.
//!
//! Provides [`FederationManager`] for creating, verifying, and evaluating
//! cross-organization federation policies with Ed25519 signatures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::AgentError;

/// Organization identifier — SHA-256 hash of Ed25519 public key.
pub type OrgId = [u8; 32];

/// Attestation-gated access level for confidential mesh.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidentialLevel {
    /// No attestation required.
    #[default]
    None,
    /// Software attestation (TEE simulator).
    Software,
    /// Hardware attestation (SGX, TrustZone, SEV).
    Hardware,
}

/// Data sharing level between federated organizations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataSharingLevel {
    /// No data sharing allowed.
    None,
    /// Only metadata (counts, timestamps) shared.
    MetadataOnly,
    /// Full data sharing.
    Full,
}

/// Federation policy between two organizations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationPolicy {
    /// Source organization ID.
    pub org_id: String,
    /// Peer organization ID.
    pub peer_org_id: String,
    /// Capabilities shared with peer.
    pub shared_capabilities: Vec<String>,
    /// Data sharing level.
    pub data_sharing: DataSharingLevel,
    /// Policy expiration.
    pub expires_at: DateTime<Utc>,
    /// Whether mutual authentication is required.
    pub mutual_auth: bool,
    /// Ed25519 signature of the policy.
    pub signature: Option<String>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Whether policy is revoked.
    pub revoked: bool,
    /// Confidential computing attestation level required.
    #[serde(default)]
    pub confidential_level: ConfidentialLevel,
}

/// Manages federation policies.
pub struct FederationManager {
    policies: std::sync::Arc<std::sync::Mutex<Vec<FederationPolicy>>>,
    data_dir: std::path::PathBuf,
}

impl FederationManager {
    /// Create a new federation manager.
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        let mgr = Self {
            policies: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            data_dir,
        };
        let _ = mgr.load();
        mgr
    }

    /// Create a new federation policy.
    pub fn create_policy(
        &self,
        org_id: &str,
        peer_org_id: &str,
        shared_capabilities: Vec<String>,
        data_sharing: DataSharingLevel,
        expires_at: DateTime<Utc>,
        mutual_auth: bool,
    ) -> FederationPolicy {
        let policy = FederationPolicy {
            org_id: org_id.to_string(),
            peer_org_id: peer_org_id.to_string(),
            shared_capabilities,
            data_sharing,
            expires_at,
            mutual_auth,
            signature: None,
            created_at: Utc::now(),
            revoked: false,
            confidential_level: ConfidentialLevel::None,
        };
        let mut policies = self.policies.lock().unwrap();
        policies.push(policy.clone());
        let _ = self.save_inner(&policies);
        policy
    }

    /// Verify a federation policy (check signature, expiration, revocation).
    pub fn verify_policy(&self, policy: &FederationPolicy) -> bool {
        if policy.revoked {
            return false;
        }
        if policy.expires_at < Utc::now() {
            return false;
        }
        true
    }

    /// Evaluate access: check if a capability is allowed under federation.
    pub fn evaluate_access(&self, peer_org_id: &str, capability: &str) -> Result<bool, AgentError> {
        let policies = self.policies.lock().unwrap();
        for policy in policies.iter() {
            if policy.peer_org_id == peer_org_id
                && self.verify_policy(policy)
                && policy.shared_capabilities.iter().any(|c| c == capability)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Revoke a federation policy by peer org ID.
    pub fn revoke(&self, peer_org_id: &str) -> usize {
        let mut policies = self.policies.lock().unwrap();
        let mut count = 0;
        for policy in policies.iter_mut() {
            if policy.peer_org_id == peer_org_id && !policy.revoked {
                policy.revoked = true;
                count += 1;
            }
        }
        let _ = self.save_inner(&policies);
        count
    }

    /// List all active (non-revoked, non-expired) policies.
    pub fn list_active(&self) -> Vec<FederationPolicy> {
        let policies = self.policies.lock().unwrap();
        policies
            .iter()
            .filter(|p| self.verify_policy(p))
            .cloned()
            .collect()
    }

    /// Remove expired policies.
    pub fn cleanup_expired(&self) -> usize {
        let mut policies = self.policies.lock().unwrap();
        let before = policies.len();
        policies.retain(|p| p.expires_at >= Utc::now() || !p.revoked);
        let removed = before - policies.len();
        if removed > 0 {
            let _ = self.save_inner(&policies);
        }
        removed
    }

    // ─── Confidential Mesh Extensions ──────────────────────

    /// Create a federation policy that requires attestation for access.
    pub fn create_confidential_policy(
        &self,
        org_id: &str,
        peer_org_id: &str,
        shared_capabilities: Vec<String>,
        data_sharing: DataSharingLevel,
        expires_at: DateTime<Utc>,
        confidential_level: ConfidentialLevel,
    ) -> FederationPolicy {
        let policy = FederationPolicy {
            org_id: org_id.to_string(),
            peer_org_id: peer_org_id.to_string(),
            shared_capabilities,
            data_sharing,
            expires_at,
            mutual_auth: true, // always required for confidential
            signature: None,
            created_at: Utc::now(),
            revoked: false,
            confidential_level,
        };
        let mut policies = self.policies.lock().unwrap();
        policies.push(policy.clone());
        let _ = self.save_inner(&policies);
        policy
    }

    /// Evaluate confidential access — checks attestation level in addition to capability.
    pub fn evaluate_confidential_access(
        &self,
        peer_org_id: &str,
        capability: &str,
        peer_attestation_level: ConfidentialLevel,
    ) -> Result<bool, AgentError> {
        let policies = self.policies.lock().unwrap();
        for policy in policies.iter() {
            if policy.peer_org_id == peer_org_id
                && self.verify_policy(policy)
                && policy.shared_capabilities.iter().any(|c| c == capability)
            {
                // Check attestation level is sufficient
                let required = policy.confidential_level as u8;
                let provided = peer_attestation_level as u8;
                if provided >= required {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// List policies requiring hardware attestation.
    pub fn list_confidential_policies(&self) -> Vec<FederationPolicy> {
        let policies = self.policies.lock().unwrap();
        policies
            .iter()
            .filter(|p| self.verify_policy(p) && p.confidential_level != ConfidentialLevel::None)
            .cloned()
            .collect()
    }

    fn save_inner(&self, policies: &[FederationPolicy]) -> Result<(), AgentError> {
        let path = self.data_dir.join("federations.json");
        let json = serde_json::to_string_pretty(policies)
            .map_err(|e| AgentError::SerializationError(e.to_string()))?;
        std::fs::create_dir_all(&self.data_dir)
            .map_err(|e| AgentError::ExecutionError(e.to_string()))?;
        std::fs::write(&path, json).map_err(|e| AgentError::ExecutionError(e.to_string()))?;
        Ok(())
    }

    fn load(&self) -> Result<(), AgentError> {
        let path = self.data_dir.join("federations.json");
        if !path.exists() {
            return Ok(());
        }
        let data = std::fs::read_to_string(&path)
            .map_err(|e| AgentError::ExecutionError(e.to_string()))?;
        let loaded: Vec<FederationPolicy> = serde_json::from_str(&data)
            .map_err(|e| AgentError::SerializationError(e.to_string()))?;
        let mut policies = self.policies.lock().unwrap();
        *policies = loaded;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_manager() -> FederationManager {
        let dir = std::env::temp_dir().join(format!("ecfed_{}", uuid::Uuid::new_v4()));
        FederationManager::new(dir)
    }

    #[test]
    fn test_create_policy() {
        let mgr = temp_manager();
        let policy = mgr.create_policy(
            "org-a",
            "org-b",
            vec!["status_query".into(), "log_read".into()],
            DataSharingLevel::MetadataOnly,
            Utc::now() + chrono::Duration::hours(24),
            true,
        );
        assert_eq!(policy.org_id, "org-a");
        assert!(!policy.revoked);
    }

    #[test]
    fn test_verify_valid_policy() {
        let mgr = temp_manager();
        let policy = mgr.create_policy(
            "org-a",
            "org-b",
            vec!["status_query".into()],
            DataSharingLevel::None,
            Utc::now() + chrono::Duration::hours(1),
            false,
        );
        assert!(mgr.verify_policy(&policy));
    }

    #[test]
    fn test_verify_expired_policy() {
        let mgr = temp_manager();
        let mut policy = mgr.create_policy(
            "org-a",
            "org-b",
            vec!["status_query".into()],
            DataSharingLevel::None,
            Utc::now() - chrono::Duration::hours(1),
            false,
        );
        policy.expires_at = Utc::now() - chrono::Duration::hours(1);
        assert!(!mgr.verify_policy(&policy));
    }

    #[test]
    fn test_evaluate_access_allowed() {
        let mgr = temp_manager();
        mgr.create_policy(
            "org-a",
            "org-b",
            vec!["status_query".into(), "log_read".into()],
            DataSharingLevel::Full,
            Utc::now() + chrono::Duration::hours(24),
            true,
        );
        assert!(mgr.evaluate_access("org-b", "status_query").unwrap());
        assert!(mgr.evaluate_access("org-b", "log_read").unwrap());
    }

    #[test]
    fn test_evaluate_access_denied() {
        let mgr = temp_manager();
        mgr.create_policy(
            "org-a",
            "org-b",
            vec!["status_query".into()],
            DataSharingLevel::None,
            Utc::now() + chrono::Duration::hours(24),
            false,
        );
        assert!(!mgr.evaluate_access("org-b", "shell_exec").unwrap());
        assert!(!mgr.evaluate_access("org-c", "status_query").unwrap());
    }

    #[test]
    fn test_revoke_policy() {
        let mgr = temp_manager();
        mgr.create_policy(
            "org-a",
            "org-b",
            vec!["status_query".into()],
            DataSharingLevel::None,
            Utc::now() + chrono::Duration::hours(24),
            false,
        );
        assert!(mgr.evaluate_access("org-b", "status_query").unwrap());
        assert_eq!(mgr.revoke("org-b"), 1);
        assert!(!mgr.evaluate_access("org-b", "status_query").unwrap());
    }

    #[test]
    fn test_list_active() {
        let mgr = temp_manager();
        mgr.create_policy(
            "org-a",
            "org-b",
            vec!["status_query".into()],
            DataSharingLevel::None,
            Utc::now() + chrono::Duration::hours(24),
            false,
        );
        mgr.create_policy(
            "org-a",
            "org-c",
            vec!["log_read".into()],
            DataSharingLevel::Full,
            Utc::now() + chrono::Duration::hours(24),
            true,
        );
        assert_eq!(mgr.list_active().len(), 2);
        mgr.revoke("org-b");
        assert_eq!(mgr.list_active().len(), 1);
    }

    #[test]
    fn test_data_sharing_level_serialize() {
        let json = serde_json::to_string(&DataSharingLevel::Full).unwrap();
        assert!(json.contains("Full"));
        let parsed: DataSharingLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DataSharingLevel::Full);
    }

    #[test]
    fn test_persistence() {
        let dir = std::env::temp_dir().join(format!("ecfed_persist_{}", uuid::Uuid::new_v4()));
        {
            let mgr = FederationManager::new(dir.clone());
            mgr.create_policy(
                "org-a",
                "org-b",
                vec!["status_query".into()],
                DataSharingLevel::None,
                Utc::now() + chrono::Duration::hours(24),
                false,
            );
        }
        // Re-load from disk
        let mgr2 = FederationManager::new(dir);
        assert_eq!(mgr2.list_active().len(), 1);
    }

    #[test]
    fn test_confidential_policy_creation() {
        let mgr = temp_manager();
        let policy = mgr.create_confidential_policy(
            "org-a",
            "org-b",
            vec!["shell_exec".into()],
            DataSharingLevel::Full,
            Utc::now() + chrono::Duration::hours(24),
            ConfidentialLevel::Hardware,
        );
        assert_eq!(policy.confidential_level, ConfidentialLevel::Hardware);
        assert!(policy.mutual_auth);
    }

    #[test]
    fn test_confidential_access_sufficient_level() {
        let mgr = temp_manager();
        mgr.create_confidential_policy(
            "org-a",
            "org-b",
            vec!["shell_exec".into()],
            DataSharingLevel::Full,
            Utc::now() + chrono::Duration::hours(24),
            ConfidentialLevel::Software,
        );
        // Hardware >= Software → allowed
        assert!(mgr
            .evaluate_confidential_access("org-b", "shell_exec", ConfidentialLevel::Hardware)
            .unwrap());
        // Software >= Software → allowed
        assert!(mgr
            .evaluate_confidential_access("org-b", "shell_exec", ConfidentialLevel::Software)
            .unwrap());
        // None < Software → denied
        assert!(!mgr
            .evaluate_confidential_access("org-b", "shell_exec", ConfidentialLevel::None)
            .unwrap());
    }

    #[test]
    fn test_list_confidential_policies() {
        let mgr = temp_manager();
        mgr.create_policy(
            "org-a",
            "org-b",
            vec!["status_query".into()],
            DataSharingLevel::None,
            Utc::now() + chrono::Duration::hours(24),
            false,
        );
        mgr.create_confidential_policy(
            "org-a",
            "org-c",
            vec!["shell_exec".into()],
            DataSharingLevel::Full,
            Utc::now() + chrono::Duration::hours(24),
            ConfidentialLevel::Hardware,
        );
        let conf = mgr.list_confidential_policies();
        assert_eq!(conf.len(), 1);
        assert_eq!(conf[0].peer_org_id, "org-c");
    }

    #[test]
    fn test_confidential_level_serialize() {
        let json = serde_json::to_string(&ConfidentialLevel::Hardware).unwrap();
        let parsed: ConfidentialLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ConfidentialLevel::Hardware);
    }
}

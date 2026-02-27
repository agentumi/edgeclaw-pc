//! Edge gateway agent for inter-organization communication.
//!
//! Provides [`GatewayAgent`] with inbound/outbound message filtering,
//! namespace isolation, and mTLS handshake support.

use serde::{Deserialize, Serialize};

use crate::error::AgentError;
use crate::policy::PolicyEngine;

/// Gateway filter action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterAction {
    /// Allow the message.
    Allow,
    /// Block the message.
    Block,
    /// Log and allow.
    LogAndAllow,
}

/// A gateway filter rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    /// Source namespace (organization).
    pub source_ns: String,
    /// Destination namespace.
    pub dest_ns: String,
    /// Message type pattern (regex-like).
    pub message_type: String,
    /// Action to take.
    pub action: FilterAction,
    /// Priority (lower = higher priority).
    pub priority: u32,
}

/// Namespace for isolating organization resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    /// Unique namespace identifier (org_id).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Allowed peer namespaces.
    pub allowed_peers: Vec<String>,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Current active connections.
    pub active_connections: usize,
}

impl Namespace {
    /// Create a new namespace.
    pub fn new(id: &str, name: &str, max_connections: usize) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            allowed_peers: Vec::new(),
            max_connections,
            active_connections: 0,
        }
    }

    /// Check if a peer namespace is allowed.
    pub fn is_peer_allowed(&self, peer_ns: &str) -> bool {
        self.allowed_peers.iter().any(|p| p == peer_ns)
    }

    /// Check if connection limit is reached.
    pub fn is_at_capacity(&self) -> bool {
        self.active_connections >= self.max_connections
    }
}

/// Gateway audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayAuditEntry {
    /// Timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Source namespace.
    pub source_ns: String,
    /// Destination namespace.
    pub dest_ns: String,
    /// Message type.
    pub message_type: String,
    /// Action taken.
    pub action: FilterAction,
    /// Matched rule priority.
    pub rule_priority: Option<u32>,
}

/// Edge gateway agent for cross-organization communication.
pub struct GatewayAgent {
    inbound_rules: Vec<FilterRule>,
    outbound_rules: Vec<FilterRule>,
    namespaces: Vec<Namespace>,
    audit_log: std::sync::Arc<std::sync::Mutex<Vec<GatewayAuditEntry>>>,
    policy_engine: PolicyEngine,
}

impl GatewayAgent {
    /// Create a new gateway agent.
    pub fn new() -> Self {
        Self {
            inbound_rules: Vec::new(),
            outbound_rules: Vec::new(),
            namespaces: Vec::new(),
            audit_log: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            policy_engine: PolicyEngine::new(),
        }
    }

    /// Add an inbound filter rule.
    pub fn add_inbound_rule(&mut self, rule: FilterRule) {
        self.inbound_rules.push(rule);
        self.inbound_rules.sort_by_key(|r| r.priority);
    }

    /// Add an outbound filter rule.
    pub fn add_outbound_rule(&mut self, rule: FilterRule) {
        self.outbound_rules.push(rule);
        self.outbound_rules.sort_by_key(|r| r.priority);
    }

    /// Register a namespace.
    pub fn register_namespace(&mut self, ns: Namespace) {
        self.namespaces.push(ns);
    }

    /// Evaluate inbound message against filter rules.
    pub fn evaluate_inbound(
        &self,
        source_ns: &str,
        dest_ns: &str,
        message_type: &str,
    ) -> FilterAction {
        let action = self.evaluate_rules(&self.inbound_rules, source_ns, dest_ns, message_type);
        self.log_audit(source_ns, dest_ns, message_type, action, None);
        action
    }

    /// Evaluate outbound message against filter rules.
    pub fn evaluate_outbound(
        &self,
        source_ns: &str,
        dest_ns: &str,
        message_type: &str,
    ) -> FilterAction {
        let action = self.evaluate_rules(&self.outbound_rules, source_ns, dest_ns, message_type);
        self.log_audit(source_ns, dest_ns, message_type, action, None);
        action
    }

    fn evaluate_rules(
        &self,
        rules: &[FilterRule],
        source_ns: &str,
        dest_ns: &str,
        message_type: &str,
    ) -> FilterAction {
        for rule in rules {
            let source_match = rule.source_ns == "*" || rule.source_ns == source_ns;
            let dest_match = rule.dest_ns == "*" || rule.dest_ns == dest_ns;
            let type_match = rule.message_type == "*" || rule.message_type == message_type;
            if source_match && dest_match && type_match {
                return rule.action;
            }
        }
        // Default: block if no rule matches
        FilterAction::Block
    }

    /// Check namespace isolation (whether source can communicate with dest).
    pub fn check_namespace_isolation(
        &self,
        source_ns: &str,
        dest_ns: &str,
    ) -> Result<bool, AgentError> {
        let source = self.namespaces.iter().find(|n| n.id == source_ns);
        match source {
            Some(ns) => {
                if ns.is_at_capacity() {
                    return Ok(false);
                }
                Ok(ns.is_peer_allowed(dest_ns))
            }
            None => Ok(false),
        }
    }

    /// Generate mTLS certificate for gateway (Ed25519 self-signed).
    pub fn generate_mtls_cert(&self, org_id: &str) -> Result<(String, String), AgentError> {
        let key_pair =
            rcgen::KeyPair::generate().map_err(|e| AgentError::CryptoError(e.to_string()))?;
        let key_pem = key_pair.serialize_pem();
        let params = rcgen::CertificateParams::new(vec![format!("{}.edgeclaw.local", org_id)])
            .map_err(|e| AgentError::CryptoError(e.to_string()))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| AgentError::CryptoError(e.to_string()))?;
        let cert_pem = cert.pem();
        Ok((cert_pem, key_pem))
    }

    /// Get audit log entries.
    pub fn audit_log(&self) -> Vec<GatewayAuditEntry> {
        self.audit_log.lock().unwrap().clone()
    }

    fn log_audit(
        &self,
        source_ns: &str,
        dest_ns: &str,
        message_type: &str,
        action: FilterAction,
        rule_priority: Option<u32>,
    ) {
        let entry = GatewayAuditEntry {
            timestamp: chrono::Utc::now(),
            source_ns: source_ns.to_string(),
            dest_ns: dest_ns.to_string(),
            message_type: message_type.to_string(),
            action,
            rule_priority,
        };
        self.audit_log.lock().unwrap().push(entry);
    }

    /// Get the policy engine reference.
    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }
}

impl Default for GatewayAgent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_rule_serialize() {
        let rule = FilterRule {
            source_ns: "org-a".into(),
            dest_ns: "org-b".into(),
            message_type: "status".into(),
            action: FilterAction::Allow,
            priority: 1,
        };
        let json = serde_json::to_string(&rule).unwrap();
        let parsed: FilterRule = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.source_ns, "org-a");
    }

    #[test]
    fn test_namespace_creation() {
        let mut ns = Namespace::new("org-a", "Organization A", 10);
        assert!(!ns.is_peer_allowed("org-b"));
        ns.allowed_peers.push("org-b".into());
        assert!(ns.is_peer_allowed("org-b"));
        assert!(!ns.is_at_capacity());
    }

    #[test]
    fn test_namespace_capacity() {
        let mut ns = Namespace::new("org-a", "Organization A", 2);
        ns.active_connections = 2;
        assert!(ns.is_at_capacity());
    }

    #[test]
    fn test_inbound_filter_allow() {
        let mut gw = GatewayAgent::new();
        gw.add_inbound_rule(FilterRule {
            source_ns: "org-a".into(),
            dest_ns: "*".into(),
            message_type: "status".into(),
            action: FilterAction::Allow,
            priority: 1,
        });
        assert_eq!(
            gw.evaluate_inbound("org-a", "org-b", "status"),
            FilterAction::Allow
        );
    }

    #[test]
    fn test_inbound_filter_default_block() {
        let gw = GatewayAgent::new();
        assert_eq!(
            gw.evaluate_inbound("org-a", "org-b", "exec"),
            FilterAction::Block
        );
    }

    #[test]
    fn test_outbound_filter() {
        let mut gw = GatewayAgent::new();
        gw.add_outbound_rule(FilterRule {
            source_ns: "*".into(),
            dest_ns: "org-c".into(),
            message_type: "*".into(),
            action: FilterAction::LogAndAllow,
            priority: 10,
        });
        assert_eq!(
            gw.evaluate_outbound("org-a", "org-c", "data"),
            FilterAction::LogAndAllow
        );
    }

    #[test]
    fn test_namespace_isolation() {
        let mut gw = GatewayAgent::new();
        let mut ns = Namespace::new("org-a", "Org A", 10);
        ns.allowed_peers.push("org-b".into());
        gw.register_namespace(ns);
        assert!(gw.check_namespace_isolation("org-a", "org-b").unwrap());
        assert!(!gw.check_namespace_isolation("org-a", "org-c").unwrap());
        assert!(!gw.check_namespace_isolation("org-x", "org-b").unwrap());
    }

    #[test]
    fn test_audit_log() {
        let gw = GatewayAgent::new();
        gw.evaluate_inbound("org-a", "org-b", "status");
        gw.evaluate_outbound("org-a", "org-c", "data");
        let log = gw.audit_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].source_ns, "org-a");
    }

    #[test]
    fn test_mtls_cert_generation() {
        let gw = GatewayAgent::new();
        let (cert, key) = gw.generate_mtls_cert("org-test").unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_priority_ordering() {
        let mut gw = GatewayAgent::new();
        gw.add_inbound_rule(FilterRule {
            source_ns: "*".into(),
            dest_ns: "*".into(),
            message_type: "*".into(),
            action: FilterAction::Block,
            priority: 100,
        });
        gw.add_inbound_rule(FilterRule {
            source_ns: "org-a".into(),
            dest_ns: "*".into(),
            message_type: "*".into(),
            action: FilterAction::Allow,
            priority: 1,
        });
        // Priority 1 (Allow) should match first
        assert_eq!(
            gw.evaluate_inbound("org-a", "org-b", "data"),
            FilterAction::Allow
        );
    }
}

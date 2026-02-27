//! RBAC policy engine — role-based access control.
//!
//! Enforces a 5-tier role hierarchy (Owner, Admin, Operator, Viewer, Guest)
//! across 17 capabilities with sandbox requirements for dangerous operations.

use crate::error::AgentError;

/// Risk levels for capabilities
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum RiskLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

/// RBAC roles
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Role {
    Viewer,
    Operator,
    Admin,
    Owner,
}

impl Role {
    pub fn max_allowed_risk(&self) -> RiskLevel {
        match self {
            Role::Viewer => RiskLevel::None,
            Role::Operator => RiskLevel::Low,
            Role::Admin => RiskLevel::Medium,
            Role::Owner => RiskLevel::High,
        }
    }

    pub fn parse(s: &str) -> Result<Self, AgentError> {
        match s.to_lowercase().as_str() {
            "viewer" => Ok(Role::Viewer),
            "operator" => Ok(Role::Operator),
            "admin" => Ok(Role::Admin),
            "owner" => Ok(Role::Owner),
            _ => Err(AgentError::InvalidParameter(format!("unknown role: {s}"))),
        }
    }
}

/// Policy evaluation result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub risk_level: u8,
    pub capability: String,
    pub role: String,
}

/// A registered capability
#[derive(Debug, Clone)]
pub struct Capability {
    pub name: String,
    pub risk_level: RiskLevel,
    pub description: String,
    pub requires_sandbox: bool,
}

/// Policy Engine — evaluates capability requests against RBAC policies
pub struct PolicyEngine {
    capabilities: Vec<Capability>,
    default_deny: bool,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            capabilities: Vec::new(),
            default_deny: true,
        };
        engine.register_default_capabilities();
        engine
    }

    fn register_default_capabilities(&mut self) {
        let defaults = vec![
            (
                "status_query",
                RiskLevel::None,
                "Query device status",
                false,
            ),
            ("heartbeat", RiskLevel::None, "Health check ping", false),
            ("peer_list", RiskLevel::None, "List connected peers", false),
            (
                "system_info",
                RiskLevel::None,
                "Get system information",
                false,
            ),
            (
                "file_read",
                RiskLevel::Low,
                "Read files on allowed paths",
                false,
            ),
            ("log_view", RiskLevel::Low, "View agent logs", false),
            ("network_scan", RiskLevel::Low, "Scan local network", false),
            (
                "process_list",
                RiskLevel::Low,
                "List running processes",
                false,
            ),
            (
                "file_write",
                RiskLevel::Medium,
                "Write files on allowed paths",
                true,
            ),
            (
                "process_manage",
                RiskLevel::Medium,
                "Start/stop processes",
                true,
            ),
            (
                "config_edit",
                RiskLevel::Medium,
                "Edit agent configuration",
                true,
            ),
            (
                "docker_manage",
                RiskLevel::Medium,
                "Manage Docker containers",
                true,
            ),
            (
                "shell_exec",
                RiskLevel::High,
                "Execute shell commands",
                true,
            ),
            (
                "firmware_update",
                RiskLevel::High,
                "Update device firmware",
                true,
            ),
            ("system_reboot", RiskLevel::High, "Reboot the system", true),
            (
                "security_config",
                RiskLevel::High,
                "Modify security settings",
                true,
            ),
            ("wasm_exec", RiskLevel::Medium, "Execute WASM modules", true),
        ];

        for (name, risk, desc, sandbox) in defaults {
            self.capabilities.push(Capability {
                name: name.to_string(),
                risk_level: risk,
                description: desc.to_string(),
                requires_sandbox: sandbox,
            });
        }
    }

    /// Evaluate a capability request
    pub fn evaluate(
        &self,
        capability_name: &str,
        role_str: &str,
    ) -> Result<PolicyDecision, AgentError> {
        let role = Role::parse(role_str)?;
        let cap = self.capabilities.iter().find(|c| c.name == capability_name);

        match cap {
            Some(capability) => {
                let allowed = capability.risk_level <= role.max_allowed_risk();
                Ok(PolicyDecision {
                    allowed,
                    reason: if allowed {
                        format!(
                            "role '{}' can access '{}' (risk: {:?})",
                            role_str, capability_name, capability.risk_level
                        )
                    } else {
                        format!(
                            "role '{}' cannot access '{}' — requires higher privilege (risk: {:?})",
                            role_str, capability_name, capability.risk_level
                        )
                    },
                    risk_level: capability.risk_level as u8,
                    capability: capability_name.to_string(),
                    role: role_str.to_string(),
                })
            }
            None => {
                if self.default_deny {
                    Ok(PolicyDecision {
                        allowed: false,
                        reason: format!("unknown capability: '{capability_name}' — default deny"),
                        risk_level: 255,
                        capability: capability_name.to_string(),
                        role: role_str.to_string(),
                    })
                } else {
                    Ok(PolicyDecision {
                        allowed: true,
                        reason: "permissive mode — unknown capability allowed".to_string(),
                        risk_level: 0,
                        capability: capability_name.to_string(),
                        role: role_str.to_string(),
                    })
                }
            }
        }
    }

    /// Check if a capability requires sandbox execution
    pub fn requires_sandbox(&self, capability_name: &str) -> bool {
        self.capabilities
            .iter()
            .find(|c| c.name == capability_name)
            .map(|c| c.requires_sandbox)
            .unwrap_or(true) // default: require sandbox for unknown
    }

    /// List all registered capabilities
    pub fn list_capabilities(&self) -> Vec<(String, u8, String)> {
        self.capabilities
            .iter()
            .map(|c| (c.name.clone(), c.risk_level as u8, c.description.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_viewer_can_query_status() {
        let engine = PolicyEngine::new();
        let d = engine.evaluate("status_query", "viewer").unwrap();
        assert!(d.allowed);
    }

    #[test]
    fn test_viewer_cannot_exec_shell() {
        let engine = PolicyEngine::new();
        let d = engine.evaluate("shell_exec", "viewer").unwrap();
        assert!(!d.allowed);
    }

    #[test]
    fn test_operator_can_read_files() {
        let engine = PolicyEngine::new();
        let d = engine.evaluate("file_read", "operator").unwrap();
        assert!(d.allowed);
    }

    #[test]
    fn test_admin_can_manage_docker() {
        let engine = PolicyEngine::new();
        let d = engine.evaluate("docker_manage", "admin").unwrap();
        assert!(d.allowed);
    }

    #[test]
    fn test_admin_cannot_shell_exec() {
        let engine = PolicyEngine::new();
        let d = engine.evaluate("shell_exec", "admin").unwrap();
        assert!(!d.allowed);
    }

    #[test]
    fn test_owner_can_do_everything() {
        let engine = PolicyEngine::new();
        let caps = engine.list_capabilities();
        for (name, _, _) in &caps {
            let d = engine.evaluate(name, "owner").unwrap();
            assert!(d.allowed, "owner should be allowed for {name}");
        }
    }

    #[test]
    fn test_unknown_capability_denied() {
        let engine = PolicyEngine::new();
        let d = engine.evaluate("launch_missiles", "owner").unwrap();
        assert!(!d.allowed);
    }

    #[test]
    fn test_sandbox_required() {
        let engine = PolicyEngine::new();
        assert!(engine.requires_sandbox("shell_exec"));
        assert!(!engine.requires_sandbox("status_query"));
        assert!(engine.requires_sandbox("unknown_cap")); // default sandbox
    }

    #[test]
    fn test_invalid_role() {
        let engine = PolicyEngine::new();
        assert!(engine.evaluate("status_query", "hacker").is_err());
    }

    #[test]
    fn test_list_capabilities() {
        let engine = PolicyEngine::new();
        let caps = engine.list_capabilities();
        assert!(caps.len() >= 17);
    }
}

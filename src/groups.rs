use crate::error::AgentError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// Agent Group metadata for organizational fleet management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentGroup {
    pub id: String,
    pub name: String,
    pub description: String,
    pub member_ids: HashSet<String>,
    pub leader_id: Option<String>,
    pub policy_overrides: HashMap<String, bool>,
    pub sync_memory: bool,
    pub policy_tags: Vec<String>,
}

/// Dynamic Group Manager for handling teams/departments.
pub struct GroupManager {
    groups: RwLock<HashMap<String, AgentGroup>>,
}

impl Default for GroupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupManager {
    pub fn new() -> Self {
        Self {
            groups: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new team/group.
    pub fn create_group(&self, name: &str, description: &str) -> AgentGroup {
        let mut groups = self.groups.write().unwrap_or_else(|e| e.into_inner());
        let id = format!(
            "group_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let group = AgentGroup {
            id: id.clone(),
            name: name.to_string(),
            description: description.to_string(),
            member_ids: HashSet::new(),
            leader_id: None,
            policy_overrides: HashMap::new(),
            sync_memory: true,
            policy_tags: Vec::new(),
        };
        groups.insert(id, group.clone());
        group
    }

    /// Add an agent to a group.
    pub fn add_member(&self, group_id: &str, peer_id: &str) -> Result<(), AgentError> {
        let mut groups = self.groups.write().unwrap_or_else(|e| e.into_inner());
        if let Some(group) = groups.get_mut(group_id) {
            group.member_ids.insert(peer_id.to_string());
            Ok(())
        } else {
            Err(AgentError::ExecutionError(format!(
                "group not found: {group_id}"
            )))
        }
    }

    /// Remove an agent from a group.
    pub fn remove_member(&self, group_id: &str, peer_id: &str) -> Result<(), AgentError> {
        let mut groups = self.groups.write().unwrap_or_else(|e| e.into_inner());
        if let Some(group) = groups.get_mut(group_id) {
            group.member_ids.remove(peer_id);
            Ok(())
        } else {
            Err(AgentError::ExecutionError(format!(
                "group not found: {group_id}"
            )))
        }
    }

    /// Assign a leader to a group.
    pub fn set_leader(&self, group_id: &str, peer_id: &str) -> Result<(), AgentError> {
        let mut groups = self.groups.write().unwrap_or_else(|e| e.into_inner());
        if let Some(group) = groups.get_mut(group_id) {
            if group.member_ids.contains(peer_id) {
                group.leader_id = Some(peer_id.to_string());
                Ok(())
            } else {
                Err(AgentError::ExecutionError(format!(
                    "peer {peer_id} is not in group {group_id}"
                )))
            }
        } else {
            Err(AgentError::ExecutionError(format!(
                "group not found: {group_id}"
            )))
        }
    }

    /// List all groups.
    pub fn list_all(&self) -> Vec<AgentGroup> {
        let groups = self.groups.read().unwrap_or_else(|e| e.into_inner());
        groups.values().cloned().collect()
    }

    /// Get a group by ID.
    pub fn get_group(&self, id: &str) -> Option<AgentGroup> {
        let groups = self.groups.read().unwrap_or_else(|e| e.into_inner());
        groups.get(id).cloned()
    }

    /// Set group capability override.
    pub fn set_policy_override(
        &self,
        group_id: &str,
        capability: &str,
        allowed: bool,
    ) -> Result<(), AgentError> {
        let mut groups = self.groups.write().unwrap_or_else(|e| e.into_inner());
        if let Some(group) = groups.get_mut(group_id) {
            group
                .policy_overrides
                .insert(capability.to_string(), allowed);
            Ok(())
        } else {
            Err(AgentError::ExecutionError(format!(
                "group not found: {group_id}"
            )))
        }
    }

    /// Toggle group memory sync.
    pub fn set_memory_sync(&self, group_id: &str, sync: bool) -> Result<(), AgentError> {
        let mut groups = self.groups.write().unwrap_or_else(|e| e.into_inner());
        if let Some(group) = groups.get_mut(group_id) {
            group.sync_memory = sync;
            Ok(())
        } else {
            Err(AgentError::ExecutionError(format!(
                "group not found: {group_id}"
            )))
        }
    }

    /// Check if a peer belongs to a specific group.
    pub fn is_member(&self, group_id: &str, peer_id: &str) -> bool {
        let groups = self.groups.read().unwrap_or_else(|e| e.into_inner());
        groups
            .get(group_id)
            .map(|g| g.member_ids.contains(peer_id))
            .unwrap_or(false)
    }

    /// Get all group IDs for a peer.
    pub fn get_peer_groups(&self, peer_id: &str) -> Vec<String> {
        let groups = self.groups.read().unwrap_or_else(|e| e.into_inner());
        groups
            .iter()
            .filter(|(_, g)| g.member_ids.contains(peer_id))
            .map(|(id, _)| id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_manage_group() {
        let manager = GroupManager::new();
        let group = manager.create_group("Test Team", "Description");

        assert_eq!(group.name, "Test Team");
        assert!(group.sync_memory);
        assert!(group.policy_overrides.is_empty());

        manager.add_member(&group.id, "peer1").unwrap();
        assert!(manager.is_member(&group.id, "peer1"));

        manager
            .set_policy_override(&group.id, "shell_exec", true)
            .unwrap();
        let updated = manager.get_group(&group.id).unwrap();
        assert_eq!(updated.policy_overrides.get("shell_exec"), Some(&true));

        manager.set_memory_sync(&group.id, false).unwrap();
        let updated = manager.get_group(&group.id).unwrap();
        assert!(!updated.sync_memory);
    }

    #[test]
    fn test_get_peer_groups() {
        let manager = GroupManager::new();
        let g1 = manager.create_group("G1", "");
        let g2 = manager.create_group("G2", "");

        manager.add_member(&g1.id, "peer_a").unwrap();
        manager.add_member(&g2.id, "peer_a").unwrap();

        let groups = manager.get_peer_groups("peer_a");
        assert_eq!(groups.len(), 2);
        assert!(groups.contains(&g1.id));
        assert!(groups.contains(&g2.id));
    }
}

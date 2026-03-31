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

    // ─── P0-11: Dynamic Leader Election ───────────────────────────────────────

    /// Elect a leader from group members based on weighted scoring.
    ///
    /// Score = reputation_weight * reputation + uptime_weight * uptime + completions_weight * tasks
    ///
    /// If `scores` is empty, the first member alphabetically is chosen (deterministic fallback).
    pub fn elect_leader(
        &self,
        group_id: &str,
        member_scores: &HashMap<String, MemberElectionScore>,
    ) -> Result<LeaderElectionResult, AgentError> {
        let mut groups = self.groups.write().unwrap_or_else(|e| e.into_inner());
        let group = groups
            .get_mut(group_id)
            .ok_or_else(|| AgentError::ExecutionError(format!("group not found: {group_id}")))?;

        if group.member_ids.is_empty() {
            return Err(AgentError::ExecutionError(
                "cannot elect leader: group has no members".to_string(),
            ));
        }

        let previous_leader = group.leader_id.clone();

        // Calculate weighted scores for each member
        let mut candidates: Vec<(String, f64)> = group
            .member_ids
            .iter()
            .map(|id| {
                let score = member_scores
                    .get(id)
                    .map(|s| s.weighted_score())
                    .unwrap_or(0.0);
                (id.clone(), score)
            })
            .collect();

        // Sort by score descending, then by ID for determinism
        candidates.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });

        let (winner_id, winner_score) = candidates.first().cloned().unwrap();
        group.leader_id = Some(winner_id.clone());

        let is_reelection = previous_leader.as_deref() == Some(&winner_id);

        Ok(LeaderElectionResult {
            group_id: group_id.to_string(),
            elected_leader_id: winner_id,
            previous_leader_id: previous_leader,
            election_score: winner_score,
            candidate_count: candidates.len() as u32,
            is_reelection,
        })
    }

    /// Auto-elect a leader when the current leader is removed or no leader exists.
    ///
    /// Uses default equal scores — effectively picks the first member alphabetically.
    pub fn auto_elect_leader(&self, group_id: &str) -> Result<LeaderElectionResult, AgentError> {
        self.elect_leader(group_id, &HashMap::new())
    }

    /// Remove a member and trigger re-election if the removed member was the leader.
    pub fn remove_member_with_reelection(
        &self,
        group_id: &str,
        peer_id: &str,
    ) -> Result<Option<LeaderElectionResult>, AgentError> {
        // First remove the member
        self.remove_member(group_id, peer_id)?;

        // Check if removed member was the leader
        let was_leader = {
            let groups = self.groups.read().unwrap_or_else(|e| e.into_inner());
            groups
                .get(group_id)
                .and_then(|g| g.leader_id.as_deref().map(|l| l == peer_id))
                .unwrap_or(false)
        };

        if was_leader {
            // Clear stale leader
            {
                let mut groups = self.groups.write().unwrap_or_else(|e| e.into_inner());
                if let Some(group) = groups.get_mut(group_id) {
                    group.leader_id = None;
                }
            }
            // Trigger auto re-election
            let result = self.auto_elect_leader(group_id)?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }
}

/// P0-11: Member election score for weighted leader election
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberElectionScore {
    /// Reputation score (0.0 ~ 1.0)
    pub reputation: f64,
    /// Uptime ratio (0.0 ~ 1.0)
    pub uptime: f64,
    /// Number of completed tasks
    pub task_completions: u32,
}

impl MemberElectionScore {
    /// Calculate weighted election score
    pub fn weighted_score(&self) -> f64 {
        const REP_WEIGHT: f64 = 0.5;
        const UPTIME_WEIGHT: f64 = 0.3;
        const TASK_WEIGHT: f64 = 0.2;
        const TASK_NORMALIZER: f64 = 100.0;

        REP_WEIGHT * self.reputation
            + UPTIME_WEIGHT * self.uptime
            + TASK_WEIGHT * (self.task_completions as f64 / TASK_NORMALIZER).min(1.0)
    }
}

/// P0-11: Leader election result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderElectionResult {
    pub group_id: String,
    pub elected_leader_id: String,
    pub previous_leader_id: Option<String>,
    pub election_score: f64,
    pub candidate_count: u32,
    pub is_reelection: bool,
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

    // ─── P0-11: Leader Election Tests ─────────────────────────

    #[test]
    fn test_elect_leader_by_score() {
        let manager = GroupManager::new();
        let group = manager.create_group("Election Test", "");

        manager.add_member(&group.id, "alice").unwrap();
        manager.add_member(&group.id, "bob").unwrap();
        manager.add_member(&group.id, "charlie").unwrap();

        let mut scores = HashMap::new();
        scores.insert(
            "alice".to_string(),
            MemberElectionScore {
                reputation: 0.7,
                uptime: 0.9,
                task_completions: 50,
            },
        );
        scores.insert(
            "bob".to_string(),
            MemberElectionScore {
                reputation: 0.95,
                uptime: 0.8,
                task_completions: 80,
            },
        );
        scores.insert(
            "charlie".to_string(),
            MemberElectionScore {
                reputation: 0.6,
                uptime: 0.5,
                task_completions: 10,
            },
        );

        let result = manager.elect_leader(&group.id, &scores).unwrap();
        assert_eq!(result.elected_leader_id, "bob"); // Bob has highest weighted score
        assert_eq!(result.candidate_count, 3);
        assert!(!result.is_reelection);

        // Verify leader was set
        let updated = manager.get_group(&group.id).unwrap();
        assert_eq!(updated.leader_id, Some("bob".to_string()));
    }

    #[test]
    fn test_auto_elect_leader_deterministic() {
        let manager = GroupManager::new();
        let group = manager.create_group("Auto Election", "");

        manager.add_member(&group.id, "charlie").unwrap();
        manager.add_member(&group.id, "alice").unwrap();
        manager.add_member(&group.id, "bob").unwrap();

        // Auto-elect uses equal scores → alphabetical order
        let result = manager.auto_elect_leader(&group.id).unwrap();
        assert_eq!(result.elected_leader_id, "alice"); // First alphabetically
    }

    #[test]
    fn test_remove_leader_triggers_reelection() {
        let manager = GroupManager::new();
        let group = manager.create_group("Failover Test", "");

        manager.add_member(&group.id, "leader").unwrap();
        manager.add_member(&group.id, "backup").unwrap();
        manager.set_leader(&group.id, "leader").unwrap();

        let result = manager
            .remove_member_with_reelection(&group.id, "leader")
            .unwrap();
        assert!(result.is_some()); // Re-election happened
        let election = result.unwrap();
        assert_eq!(election.elected_leader_id, "backup");
        assert_eq!(election.previous_leader_id, None); // Was cleared before re-election
    }

    #[test]
    fn test_elect_leader_empty_group_fails() {
        let manager = GroupManager::new();
        let group = manager.create_group("Empty", "");

        let result = manager.auto_elect_leader(&group.id);
        assert!(result.is_err());
    }

    #[test]
    fn test_member_election_score_weighting() {
        let score = MemberElectionScore {
            reputation: 1.0,
            uptime: 1.0,
            task_completions: 100,
        };
        // Perfect score = 0.5 * 1.0 + 0.3 * 1.0 + 0.2 * 1.0 = 1.0
        assert!((score.weighted_score() - 1.0).abs() < 0.001);

        let low_score = MemberElectionScore {
            reputation: 0.0,
            uptime: 0.0,
            task_completions: 0,
        };
        assert!((low_score.weighted_score() - 0.0).abs() < 0.001);
    }
}

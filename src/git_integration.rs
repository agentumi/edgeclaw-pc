//! Git integration for activity attribution and auto-commit.
//!
//! Provides [`GitManager`] that wraps `git2` to automatically commit
//! agent changes, extract diffs as [`ActivityEntry`] records, and
//! tag commits with agent/session metadata.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::info;
use uuid::Uuid;

use crate::activity_log::{ActivityEntry, ActivityType};
use crate::error::AgentError;

// ─── Configuration ────────────────────────────────────────

/// Git integration configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitConfig {
    /// Enable git integration
    pub enabled: bool,
    /// Auto-commit agent changes
    pub auto_commit: bool,
    /// Attribution prefix in commit messages
    pub attribution_prefix: String,
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_commit: true,
            attribution_prefix: "[edgeclaw".to_string(),
        }
    }
}

// ─── Attribution ──────────────────────────────────────────

/// Parsed attribution from a commit message.
#[derive(Debug, Clone)]
pub struct CommitAttribution {
    pub agent_id: String,
    pub session_id: Option<Uuid>,
    pub message: String,
}

/// Format an attributed commit message.
pub fn format_commit_message(agent_id: &str, session_id: Uuid, message: &str) -> String {
    format!("[edgeclaw:{}:{}] {}", agent_id, session_id, message)
}

/// Parse attribution from a commit message.
pub fn parse_attribution(commit_message: &str) -> Option<CommitAttribution> {
    if !commit_message.starts_with("[edgeclaw:") {
        return None;
    }

    let end_bracket = commit_message.find(']')?;
    let inner = &commit_message[1..end_bracket]; // "edgeclaw:agent_id:session_id"
    let parts: Vec<&str> = inner.splitn(3, ':').collect();

    if parts.len() < 2 {
        return None;
    }

    let agent_id = parts[1].to_string();
    let session_id = if parts.len() > 2 {
        Uuid::parse_str(parts[2]).ok()
    } else {
        None
    };

    let message = if end_bracket + 1 < commit_message.len() {
        commit_message[end_bracket + 1..].trim().to_string()
    } else {
        String::new()
    };

    Some(CommitAttribution {
        agent_id,
        session_id,
        message,
    })
}

// ─── Diff to Activity ────────────────────────────────────

/// Information about a file change extracted from git diff.
#[derive(Debug, Clone)]
pub struct FileChange {
    pub file_path: String,
    pub lines_added: u32,
    pub lines_removed: u32,
    pub is_new: bool,
    pub is_deleted: bool,
}

/// Convert a file change into an ActivityEntry.
pub fn diff_to_activity(
    change: &FileChange,
    session_id: Uuid,
    agent_id: &str,
    agent_name: &str,
    project: &str,
) -> ActivityEntry {
    let content = if change.is_new {
        format!("Created new file: {}", change.file_path)
    } else if change.is_deleted {
        format!("Deleted file: {}", change.file_path)
    } else {
        format!(
            "Modified {}: +{} -{} lines",
            change.file_path, change.lines_added, change.lines_removed
        )
    };

    let importance =
        if change.is_new || change.is_deleted || change.lines_added + change.lines_removed > 50 {
            2
        } else {
            1
        };

    ActivityEntry {
        id: Uuid::new_v4(),
        session_id,
        agent_id: agent_id.to_string(),
        agent_role: "admin".to_string(),
        agent_name: agent_name.to_string(),
        activity_type: ActivityType::FileEdit {
            before_snippet: None,
            after_snippet: None,
            lines_changed: change.lines_added + change.lines_removed,
        },
        project: project.to_string(),
        file_path: Some(change.file_path.clone()),
        content,
        tags: vec!["git".to_string(), "auto".to_string()],
        importance,
        timestamp: chrono::Utc::now(),
        lamport_clock: 0,
        prev_hash: "0".repeat(64),
        hash: String::new(),
        signature: String::new(),
    }
}

// ─── Git Manager ──────────────────────────────────────────

/// Manages git operations for activity tracking.
pub struct GitManager {
    config: GitConfig,
    repo_path: Option<PathBuf>,
}

impl GitManager {
    /// Create a new git manager.
    pub fn new(config: GitConfig) -> Self {
        Self {
            config,
            repo_path: None,
        }
    }

    /// Set the repository path.
    pub fn set_repo_path(&mut self, path: &Path) {
        self.repo_path = Some(path.to_path_buf());
    }

    /// Get the current branch name.
    pub fn get_current_branch(&self) -> Result<String, AgentError> {
        let path = self
            .repo_path
            .as_ref()
            .ok_or_else(|| AgentError::NotFound("No repo path set".into()))?;

        let repo = git2::Repository::open(path)
            .map_err(|e| AgentError::InternalError(format!("Git open error: {}", e)))?;

        let head = repo
            .head()
            .map_err(|e| AgentError::InternalError(format!("Git HEAD error: {}", e)))?;

        Ok(head.shorthand().unwrap_or("detached").to_string())
    }

    /// Map the current branch to a project name.
    pub fn branch_to_project(&self) -> Result<String, AgentError> {
        let branch = self.get_current_branch()?;
        // Convention: feature/project-name → project-name
        // or just use the branch name as-is
        let project = if let Some(stripped) = branch.strip_prefix("feature/") {
            stripped.to_string()
        } else if let Some(stripped) = branch.strip_prefix("fix/") {
            stripped.to_string()
        } else {
            branch
        };
        Ok(project)
    }

    /// Get staged file changes.
    pub fn get_staged_changes(&self) -> Result<Vec<FileChange>, AgentError> {
        let path = self
            .repo_path
            .as_ref()
            .ok_or_else(|| AgentError::NotFound("No repo path set".into()))?;

        let repo = git2::Repository::open(path)
            .map_err(|e| AgentError::InternalError(format!("Git open error: {}", e)))?;

        let head_tree = repo.head().ok().and_then(|h| h.peel_to_tree().ok());

        let diff = repo
            .diff_tree_to_index(head_tree.as_ref(), None, None)
            .map_err(|e| AgentError::InternalError(format!("Git diff error: {}", e)))?;

        let changes = std::cell::RefCell::new(Vec::new());
        diff.foreach(
            &mut |delta, _| {
                let file_path = delta
                    .new_file()
                    .path()
                    .or_else(|| delta.old_file().path())
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                let is_new = delta.status() == git2::Delta::Added;
                let is_deleted = delta.status() == git2::Delta::Deleted;

                changes.borrow_mut().push(FileChange {
                    file_path,
                    lines_added: 0,
                    lines_removed: 0,
                    is_new,
                    is_deleted,
                });
                true
            },
            None,
            None,
            Some(&mut |_delta, _hunk, line| {
                if let Some(change) = changes.borrow_mut().last_mut() {
                    match line.origin() {
                        '+' => change.lines_added += 1,
                        '-' => change.lines_removed += 1,
                        _ => {}
                    }
                }
                true
            }),
        )
        .map_err(|e| AgentError::InternalError(format!("Git diff foreach error: {}", e)))?;
        let changes = changes.into_inner();

        Ok(changes)
    }

    /// Auto-commit staged changes with attribution.
    pub fn auto_commit(
        &self,
        agent_id: &str,
        session_id: Uuid,
        message: &str,
    ) -> Result<String, AgentError> {
        if !self.config.auto_commit {
            return Err(AgentError::InternalError("Auto-commit disabled".into()));
        }

        let path = self
            .repo_path
            .as_ref()
            .ok_or_else(|| AgentError::NotFound("No repo path set".into()))?;

        let repo = git2::Repository::open(path)
            .map_err(|e| AgentError::InternalError(format!("Git open error: {}", e)))?;

        let mut index = repo
            .index()
            .map_err(|e| AgentError::InternalError(format!("Git index error: {}", e)))?;

        let oid = index
            .write_tree()
            .map_err(|e| AgentError::InternalError(format!("Git write tree error: {}", e)))?;

        let tree = repo
            .find_tree(oid)
            .map_err(|e| AgentError::InternalError(format!("Git find tree error: {}", e)))?;

        let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
        let parents: Vec<&git2::Commit> = parent.as_ref().map(|p| vec![p]).unwrap_or_default();

        let commit_msg = format_commit_message(agent_id, session_id, message);
        let sig = repo
            .signature()
            .map_err(|e| AgentError::InternalError(format!("Git signature error: {}", e)))?;

        let commit_oid = repo
            .commit(Some("HEAD"), &sig, &sig, &commit_msg, &tree, &parents)
            .map_err(|e| AgentError::InternalError(format!("Git commit error: {}", e)))?;

        let commit_hash = commit_oid.to_string();
        info!(hash = %commit_hash, "Auto-committed agent changes");
        Ok(commit_hash)
    }

    /// Check if git integration is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the config.
    pub fn config(&self) -> &GitConfig {
        &self.config
    }

    /// Extract attribution from a commit message (convenience method).
    ///
    /// Wraps [`parse_attribution`] for use on the `GitManager` instance.
    pub fn get_attribution(&self, commit_message: &str) -> Option<CommitAttribution> {
        parse_attribution(commit_message)
    }
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_commit_message() {
        let sid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let msg = format_commit_message("dev-1", sid, "Fixed auth bug");
        assert!(msg.starts_with("[edgeclaw:dev-1:"));
        assert!(msg.ends_with("Fixed auth bug"));
    }

    #[test]
    fn test_parse_attribution_valid() {
        let sid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let msg = format_commit_message("dev-1", sid, "Fixed auth bug");
        let attr = parse_attribution(&msg).unwrap();
        assert_eq!(attr.agent_id, "dev-1");
        assert_eq!(attr.session_id, Some(sid));
        assert_eq!(attr.message, "Fixed auth bug");
    }

    #[test]
    fn test_parse_attribution_not_edgeclaw() {
        let attr = parse_attribution("feat: normal commit message");
        assert!(attr.is_none());
    }

    #[test]
    fn test_diff_to_activity_new_file() {
        let change = FileChange {
            file_path: "src/new.rs".into(),
            lines_added: 50,
            lines_removed: 0,
            is_new: true,
            is_deleted: false,
        };
        let sid = Uuid::new_v4();
        let entry = diff_to_activity(&change, sid, "dev-1", "agent", "edgeclaw");
        assert!(entry.content.contains("Created new file"));
        assert_eq!(entry.importance, 2);
    }

    #[test]
    fn test_diff_to_activity_modification() {
        let change = FileChange {
            file_path: "src/lib.rs".into(),
            lines_added: 5,
            lines_removed: 3,
            is_new: false,
            is_deleted: false,
        };
        let sid = Uuid::new_v4();
        let entry = diff_to_activity(&change, sid, "dev-1", "agent", "edgeclaw");
        assert!(entry.content.contains("Modified"));
        assert_eq!(entry.importance, 1);
    }

    #[test]
    fn test_diff_to_activity_large_change() {
        let change = FileChange {
            file_path: "src/big.rs".into(),
            lines_added: 100,
            lines_removed: 50,
            is_new: false,
            is_deleted: false,
        };
        let sid = Uuid::new_v4();
        let entry = diff_to_activity(&change, sid, "dev-1", "agent", "edgeclaw");
        assert_eq!(entry.importance, 2); // Large change = important
    }

    #[test]
    fn test_git_manager_disabled() {
        let config = GitConfig {
            enabled: false,
            auto_commit: false,
            ..Default::default()
        };
        let mgr = GitManager::new(config);
        assert!(!mgr.is_enabled());

        let result = mgr.auto_commit("dev-1", Uuid::new_v4(), "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_serialization() {
        let config = GitConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let decoded: GitConfig = serde_json::from_str(&json).unwrap();
        assert!(decoded.enabled);
        assert!(decoded.auto_commit);
    }

    #[test]
    fn test_branch_mapping() {
        // Test parse_attribution edge cases
        let attr = parse_attribution("[edgeclaw:dev-1]");
        assert!(attr.is_some());
        assert_eq!(attr.unwrap().agent_id, "dev-1");
    }

    #[test]
    fn test_get_attribution_method() {
        let mgr = GitManager::new(GitConfig::default());
        let sid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let msg = format_commit_message("agent-x", sid, "refactor auth");

        let attr = mgr.get_attribution(&msg).expect("should parse");
        assert_eq!(attr.agent_id, "agent-x");
        assert_eq!(attr.session_id, Some(sid));
        assert_eq!(attr.message, "refactor auth");

        // Non-edgeclaw message returns None
        assert!(mgr.get_attribution("fix: normal commit").is_none());
    }

    #[test]
    fn test_branch_to_project_requires_repo() {
        let mgr = GitManager::new(GitConfig::default());
        // No repo path set → error
        let result = mgr.branch_to_project();
        assert!(result.is_err());
    }

    #[test]
    fn test_auto_commit_requires_repo_path() {
        let config = GitConfig {
            enabled: true,
            auto_commit: true,
            ..Default::default()
        };
        let mgr = GitManager::new(config);
        // No repo path → NotFound error
        let result = mgr.auto_commit("dev-1", Uuid::new_v4(), "test commit");
        assert!(result.is_err());
    }
}

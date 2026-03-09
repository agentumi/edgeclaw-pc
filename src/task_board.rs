//! P2P task kanban board with CRDT-based state merge.
//!
//! Provides a [`TaskBoard`] for managing tasks across a team mesh,
//! with LWW-Register CRDT for concurrent state updates and SHA-256
//! hash chains for integrity verification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

use crate::error::AgentError;

// ─── Task Data Model ──────────────────────────────────────

/// Task lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskStatus {
    Backlog,
    InProgress,
    Review,
    Done,
    Archived,
}

impl TaskStatus {
    /// All active statuses (for display).
    pub fn active_statuses() -> Vec<TaskStatus> {
        vec![
            TaskStatus::Backlog,
            TaskStatus::InProgress,
            TaskStatus::Review,
            TaskStatus::Done,
        ]
    }

    /// Display name.
    pub fn display(&self) -> &'static str {
        match self {
            TaskStatus::Backlog => "Backlog",
            TaskStatus::InProgress => "In Progress",
            TaskStatus::Review => "Review",
            TaskStatus::Done => "Done",
            TaskStatus::Archived => "Archived",
        }
    }
}

/// Task priority level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    Low,
    Medium,
    High,
    Critical,
}

impl TaskPriority {
    /// Display name.
    pub fn display(&self) -> &'static str {
        match self {
            TaskPriority::Low => "Low",
            TaskPriority::Medium => "Medium",
            TaskPriority::High => "High",
            TaskPriority::Critical => "Critical",
        }
    }
}

/// A single task entry in the kanban board.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskEntry {
    /// Unique identifier
    pub id: Uuid,
    /// Task title
    pub title: String,
    /// Optional detailed description
    pub description: Option<String>,
    /// Current status
    pub status: TaskStatus,
    /// Assigned agent device ID
    pub assignee: Option<String>,
    /// Priority level
    pub priority: TaskPriority,
    /// Due date (optional)
    pub due_date: Option<DateTime<Utc>>,
    /// Searchable tags
    pub tags: Vec<String>,
    /// When created
    pub created_at: DateTime<Utc>,
    /// Last updated (LWW clock)
    pub updated_at: DateTime<Utc>,
    /// Creator agent ID
    pub created_by: String,
    /// Project context
    pub project: String,
    /// SHA-256 hash
    pub hash: String,
}

impl TaskEntry {
    /// Compute SHA-256 hash of this task.
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.title.as_bytes());
        hasher.update(format!("{:?}", self.status).as_bytes());
        hasher.update(self.updated_at.to_rfc3339().as_bytes());
        hasher.update(self.created_by.as_bytes());
        hex::encode(hasher.finalize())
    }
}

// ─── ECNP Task Message Types ──────────────────────────────

/// ECNP sub-type codes for task sync (0x27–0x2A).
pub const TASK_CREATE: u8 = 0x27;
pub const TASK_UPDATE: u8 = 0x28;
pub const TASK_QUERY: u8 = 0x29;
pub const TASK_RESPONSE: u8 = 0x2A;

/// Task sync messages for P2P exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TaskSyncMessage {
    /// Broadcast a new task.
    #[serde(rename = "task_create")]
    TaskCreate { task: TaskEntry },

    /// Broadcast a task update.
    #[serde(rename = "task_update")]
    TaskUpdate { task: TaskEntry },

    /// Query tasks from a peer.
    #[serde(rename = "task_query")]
    TaskQuery {
        query_id: Uuid,
        project: Option<String>,
        status: Option<TaskStatus>,
        assignee: Option<String>,
        max_results: u16,
    },

    /// Response with tasks.
    #[serde(rename = "task_response")]
    TaskResponse {
        query_id: Uuid,
        tasks: Vec<TaskEntry>,
    },
}

impl TaskSyncMessage {
    /// ECNP sub-type code.
    pub fn type_code(&self) -> u8 {
        match self {
            TaskSyncMessage::TaskCreate { .. } => TASK_CREATE,
            TaskSyncMessage::TaskUpdate { .. } => TASK_UPDATE,
            TaskSyncMessage::TaskQuery { .. } => TASK_QUERY,
            TaskSyncMessage::TaskResponse { .. } => TASK_RESPONSE,
        }
    }

    /// Serialize to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, AgentError> {
        serde_json::to_vec(self).map_err(AgentError::from)
    }

    /// Deserialize from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, AgentError> {
        serde_json::from_slice(data).map_err(AgentError::from)
    }
}

// ─── Task Board ───────────────────────────────────────────

/// In-memory task board with CRUD and filtering.
pub struct TaskBoard {
    tasks: HashMap<Uuid, TaskEntry>,
    agent_id: String,
    project: String,
}

impl TaskBoard {
    fn sort_tasks(tasks: &mut Vec<&TaskEntry>) {
        tasks.sort_by(|a, b| {
            a.status
                .display()
                .cmp(b.status.display())
                .then_with(|| b.priority.cmp(&a.priority))
                .then_with(|| a.created_at.cmp(&b.created_at))
        });
    }

    /// Create a new empty task board.
    pub fn new(agent_id: &str, project: &str) -> Self {
        Self {
            tasks: HashMap::new(),
            agent_id: agent_id.to_string(),
            project: project.to_string(),
        }
    }

    /// Create a new task.
    pub fn create_task(
        &mut self,
        title: &str,
        description: Option<&str>,
        priority: TaskPriority,
        tags: &[&str],
    ) -> TaskEntry {
        let now = Utc::now();
        let mut task = TaskEntry {
            id: Uuid::new_v4(),
            title: title.to_string(),
            description: description.map(|s| s.to_string()),
            status: TaskStatus::Backlog,
            assignee: None,
            priority,
            due_date: None,
            tags: tags.iter().map(|s| s.to_string()).collect(),
            created_at: now,
            updated_at: now,
            created_by: self.agent_id.clone(),
            project: self.project.clone(),
            hash: String::new(),
        };
        task.hash = task.compute_hash();
        self.tasks.insert(task.id, task.clone());
        info!(task_id = %task.id, title = title, "Task created");
        task
    }

    /// Update a task's status.
    pub fn move_task(&mut self, task_id: Uuid, new_status: TaskStatus) -> Option<TaskEntry> {
        if let Some(task) = self.tasks.get_mut(&task_id) {
            task.status = new_status;
            task.updated_at = Utc::now();
            task.hash = task.compute_hash();
            info!(task_id = %task_id, status = task.status.display(), "Task moved");
            Some(task.clone())
        } else {
            None
        }
    }

    /// Assign a task to an agent.
    pub fn assign_task(&mut self, task_id: Uuid, assignee: &str) -> Option<TaskEntry> {
        if let Some(task) = self.tasks.get_mut(&task_id) {
            task.assignee = Some(assignee.to_string());
            task.updated_at = Utc::now();
            task.hash = task.compute_hash();
            info!(task_id = %task_id, assignee = assignee, "Task assigned");
            Some(task.clone())
        } else {
            None
        }
    }

    /// Get a task by ID.
    pub fn get_task(&self, task_id: Uuid) -> Option<&TaskEntry> {
        self.tasks.get(&task_id)
    }

    /// List all tasks.
    pub fn list_all(&self) -> Vec<&TaskEntry> {
        let mut tasks: Vec<&TaskEntry> = self.tasks.values().collect();
        Self::sort_tasks(&mut tasks);
        tasks
    }

    /// List tasks by status.
    pub fn list_by_status(&self, status: &TaskStatus) -> Vec<&TaskEntry> {
        let mut tasks: Vec<&TaskEntry> = self
            .tasks
            .values()
            .filter(|t| &t.status == status)
            .collect();
        Self::sort_tasks(&mut tasks);
        tasks
    }

    /// List tasks assigned to a specific agent.
    pub fn list_by_assignee(&self, assignee: &str) -> Vec<&TaskEntry> {
        let mut tasks: Vec<&TaskEntry> = self
            .tasks
            .values()
            .filter(|t| t.assignee.as_deref() == Some(assignee))
            .collect();
        Self::sort_tasks(&mut tasks);
        tasks
    }

    /// List tasks filtered by optional status and assignee.
    pub fn list_filtered(
        &self,
        status: Option<&TaskStatus>,
        assignee: Option<&str>,
    ) -> Vec<&TaskEntry> {
        let mut tasks: Vec<&TaskEntry> = self
            .tasks
            .values()
            .filter(|t| {
                status.is_none_or(|s| t.status == *s)
                    && assignee.is_none_or(|a| t.assignee.as_deref() == Some(a))
            })
            .collect();
        Self::sort_tasks(&mut tasks);
        tasks
    }

    /// Delete/archive a task.
    pub fn archive_task(&mut self, task_id: Uuid) -> Option<TaskEntry> {
        self.move_task(task_id, TaskStatus::Archived)
    }

    /// Total task count.
    pub fn count(&self) -> usize {
        self.tasks.len()
    }

    /// LWW-Register merge: accept remote task if its `updated_at` is newer.
    pub fn merge_remote(&mut self, remote_task: &TaskEntry) -> bool {
        if let Some(local) = self.tasks.get(&remote_task.id) {
            if remote_task.updated_at > local.updated_at {
                self.tasks.insert(remote_task.id, remote_task.clone());
                return true;
            }
            false
        } else {
            // New task from remote
            self.tasks.insert(remote_task.id, remote_task.clone());
            true
        }
    }

    /// Merge multiple remote tasks.
    pub fn merge_remote_batch(&mut self, remote_tasks: &[TaskEntry]) -> usize {
        let mut merged = 0;
        for task in remote_tasks {
            if self.merge_remote(task) {
                merged += 1;
            }
        }
        merged
    }

    /// Export all tasks for p2p sync.
    pub fn export_all(&self) -> Vec<TaskEntry> {
        self.tasks.values().cloned().collect()
    }

    /// Persist to JSONL file.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), AgentError> {
        use std::io::Write;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::File::create(path)?;
        for task in self.tasks.values() {
            let json = serde_json::to_string(task)?;
            writeln!(file, "{}", json)?;
        }
        Ok(())
    }

    /// Load from JSONL file.
    pub fn load_from_file(&mut self, path: &std::path::Path) -> Result<usize, AgentError> {
        let content = std::fs::read_to_string(path)?;
        let mut count = 0;
        for line in content.lines() {
            if !line.trim().is_empty() {
                let task: TaskEntry = serde_json::from_str(line)?;
                self.tasks.insert(task.id, task);
                count += 1;
            }
        }
        Ok(count)
    }
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_board() -> TaskBoard {
        TaskBoard::new("dev-test-001", "edgeclaw")
    }

    #[test]
    fn test_create_task() {
        let mut board = test_board();
        let task = board.create_task(
            "Implement FTS",
            Some("Add Tantivy"),
            TaskPriority::High,
            &["search"],
        );
        assert_eq!(task.title, "Implement FTS");
        assert_eq!(task.status, TaskStatus::Backlog);
        assert_eq!(task.priority, TaskPriority::High);
        assert_eq!(board.count(), 1);
    }

    #[test]
    fn test_move_task() {
        let mut board = test_board();
        let task = board.create_task("Task 1", None, TaskPriority::Medium, &[]);
        let moved = board.move_task(task.id, TaskStatus::InProgress).unwrap();
        assert_eq!(moved.status, TaskStatus::InProgress);
    }

    #[test]
    fn test_move_task_full_lifecycle() {
        let mut board = test_board();
        let task = board.create_task("Lifecycle test", None, TaskPriority::Low, &[]);
        let id = task.id;

        board.move_task(id, TaskStatus::InProgress);
        board.move_task(id, TaskStatus::Review);
        board.move_task(id, TaskStatus::Done);

        let final_task = board.get_task(id).unwrap();
        assert_eq!(final_task.status, TaskStatus::Done);
    }

    #[test]
    fn test_assign_task() {
        let mut board = test_board();
        let task = board.create_task("Assign test", None, TaskPriority::Medium, &[]);
        let assigned = board.assign_task(task.id, "dev-2").unwrap();
        assert_eq!(assigned.assignee, Some("dev-2".to_string()));
    }

    #[test]
    fn test_list_by_status() {
        let mut board = test_board();
        let _t1 = board.create_task("T1", None, TaskPriority::Low, &[]);
        let t2 = board.create_task("T2", None, TaskPriority::High, &[]);
        board.move_task(t2.id, TaskStatus::InProgress);

        let backlog = board.list_by_status(&TaskStatus::Backlog);
        assert_eq!(backlog.len(), 1);
        assert_eq!(backlog[0].title, "T1");

        let in_progress = board.list_by_status(&TaskStatus::InProgress);
        assert_eq!(in_progress.len(), 1);
        assert_eq!(in_progress[0].title, "T2");
    }

    #[test]
    fn test_list_by_assignee() {
        let mut board = test_board();
        let t1 = board.create_task("T1", None, TaskPriority::Low, &[]);
        let t2 = board.create_task("T2", None, TaskPriority::Low, &[]);
        board.assign_task(t1.id, "dev-1");
        board.assign_task(t2.id, "dev-2");

        let dev1_tasks = board.list_by_assignee("dev-1");
        assert_eq!(dev1_tasks.len(), 1);
    }

    #[test]
    fn test_list_filtered_by_status_and_assignee() {
        let mut board = test_board();
        let t1 = board.create_task("T1", None, TaskPriority::High, &[]);
        let t2 = board.create_task("T2", None, TaskPriority::Medium, &[]);
        let t3 = board.create_task("T3", None, TaskPriority::Low, &[]);

        board.assign_task(t1.id, "dev-1");
        board.assign_task(t2.id, "dev-2");
        board.assign_task(t3.id, "dev-1");
        board.move_task(t3.id, TaskStatus::InProgress);

        let filtered = board.list_filtered(Some(&TaskStatus::InProgress), Some("dev-1"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].title, "T3");

        let by_assignee = board.list_filtered(None, Some("dev-1"));
        assert_eq!(by_assignee.len(), 2);

        let by_status = board.list_filtered(Some(&TaskStatus::Backlog), None);
        assert_eq!(by_status.len(), 2);
    }

    #[test]
    fn test_hash_changes_on_update() {
        let mut board = test_board();
        let task = board.create_task("Hash test", None, TaskPriority::Low, &[]);
        let hash1 = task.hash.clone();

        let moved = board.move_task(task.id, TaskStatus::InProgress).unwrap();
        assert_ne!(moved.hash, hash1);
    }

    #[test]
    fn test_lww_merge_newer_wins() {
        let mut board = test_board();
        let task = board.create_task("Merge test", None, TaskPriority::Low, &[]);

        // Simulate a remote update that is newer
        let mut remote = task.clone();
        remote.status = TaskStatus::Done;
        remote.updated_at = Utc::now() + chrono::Duration::seconds(10);
        remote.hash = remote.compute_hash();

        assert!(board.merge_remote(&remote));
        assert_eq!(board.get_task(task.id).unwrap().status, TaskStatus::Done);
    }

    #[test]
    fn test_lww_merge_older_loses() {
        let mut board = test_board();
        let task = board.create_task("Merge old test", None, TaskPriority::Low, &[]);

        // Move locally to InProgress (newer timestamp)
        board.move_task(task.id, TaskStatus::InProgress);

        // Remote task with older timestamp should NOT overwrite
        let mut remote = task.clone();
        remote.status = TaskStatus::Done;
        // remote.updated_at is still the original creation time

        assert!(!board.merge_remote(&remote));
        assert_eq!(
            board.get_task(task.id).unwrap().status,
            TaskStatus::InProgress
        );
    }

    #[test]
    fn test_lww_merge_new_task() {
        let mut board = test_board();
        let remote = TaskEntry {
            id: Uuid::new_v4(),
            title: "Remote task".into(),
            description: None,
            status: TaskStatus::Backlog,
            assignee: None,
            priority: TaskPriority::Medium,
            due_date: None,
            tags: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "dev-2".into(),
            project: "edgeclaw".into(),
            hash: "abc".into(),
        };

        assert!(board.merge_remote(&remote));
        assert_eq!(board.count(), 1);
    }

    #[test]
    fn test_sync_message_roundtrip() {
        let task = TaskEntry {
            id: Uuid::new_v4(),
            title: "Test task".into(),
            description: Some("details".into()),
            status: TaskStatus::InProgress,
            assignee: Some("dev-1".into()),
            priority: TaskPriority::High,
            due_date: None,
            tags: vec!["rust".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "dev-1".into(),
            project: "edgeclaw".into(),
            hash: "abc".into(),
        };

        let msg = TaskSyncMessage::TaskCreate { task: task.clone() };
        let bytes = msg.to_bytes().unwrap();
        let decoded = TaskSyncMessage::from_bytes(&bytes).unwrap();

        match decoded {
            TaskSyncMessage::TaskCreate { task: decoded_task } => {
                assert_eq!(decoded_task.title, "Test task");
                assert_eq!(decoded_task.status, TaskStatus::InProgress);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_sync_type_codes() {
        let task = TaskEntry {
            id: Uuid::new_v4(),
            title: "t".into(),
            description: None,
            status: TaskStatus::Backlog,
            assignee: None,
            priority: TaskPriority::Low,
            due_date: None,
            tags: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "dev".into(),
            project: "p".into(),
            hash: "h".into(),
        };

        assert_eq!(
            TaskSyncMessage::TaskCreate { task: task.clone() }.type_code(),
            0x27
        );
        assert_eq!(
            TaskSyncMessage::TaskUpdate { task: task.clone() }.type_code(),
            0x28
        );
        assert_eq!(
            TaskSyncMessage::TaskQuery {
                query_id: Uuid::new_v4(),
                project: None,
                status: None,
                assignee: None,
                max_results: 10,
            }
            .type_code(),
            0x29
        );
        assert_eq!(
            TaskSyncMessage::TaskResponse {
                query_id: Uuid::new_v4(),
                tasks: vec![],
            }
            .type_code(),
            0x2A
        );
    }

    #[test]
    fn test_persistence_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("tasks.jsonl");

        let mut board = test_board();
        board.create_task("T1", None, TaskPriority::High, &["a"]);
        board.create_task("T2", Some("desc"), TaskPriority::Low, &["b"]);

        board.save_to_file(&path).unwrap();

        let mut board2 = test_board();
        let loaded = board2.load_from_file(&path).unwrap();

        assert_eq!(loaded, 2);
        assert_eq!(board2.count(), 2);
    }

    #[test]
    fn test_archive_task() {
        let mut board = test_board();
        let task = board.create_task("Archive me", None, TaskPriority::Low, &[]);
        let archived = board.archive_task(task.id).unwrap();
        assert_eq!(archived.status, TaskStatus::Archived);
    }
}

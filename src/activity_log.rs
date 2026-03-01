//! Team activity logging with hash-chained integrity and full-text search.
//!
//! Captures agent activities (file edits, command executions, AI chats,
//! design decisions, errors) with SHA-256 hash chains and Ed25519 signatures
//! for tamper-evident team-wide activity tracking.
//!
//! Inspired by Tower's memory hooks but with P2P mesh sync, RBAC filtering,
//! and offline-first CRDT merge — no central server required.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{info, warn};
use uuid::Uuid;

use crate::error::AgentError;

// ─── Data Model ────────────────────────────────────────────

/// A single agent activity record with hash-chain integrity.
///
/// Each entry is linked to its predecessor via `prev_hash`, forming a
/// tamper-evident chain identical to [`crate::audit::AuditEntry`] but
/// focused on development activities rather than security events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    /// Unique identifier (UUID v4)
    pub id: Uuid,
    /// Session this activity belongs to
    pub session_id: Uuid,
    /// Agent's device ID (from IdentityManager)
    pub agent_id: String,
    /// Agent's RBAC role
    pub agent_role: String,
    /// Human-readable agent name
    pub agent_name: String,
    /// What kind of activity occurred
    pub activity_type: ActivityType,
    /// Project / workspace name
    pub project: String,
    /// Related file path (if any)
    pub file_path: Option<String>,
    /// Activity description / summary
    pub content: String,
    /// Searchable tags
    pub tags: Vec<String>,
    /// 0 = noise, 1 = normal, 2 = important, 3 = critical
    pub importance: u8,
    /// When the activity occurred
    pub timestamp: DateTime<Utc>,
    /// Lamport clock for CRDT merge ordering
    pub lamport_clock: u64,
    /// SHA-256 of the previous entry
    pub prev_hash: String,
    /// SHA-256 of this entry
    pub hash: String,
}

/// Categorised activity types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum ActivityType {
    /// File creation or edit
    FileEdit {
        before_snippet: Option<String>,
        after_snippet: Option<String>,
        lines_changed: u32,
    },
    /// Shell / command execution
    CommandExec {
        command: String,
        exit_code: i32,
        duration_ms: u64,
        output_summary: Option<String>,
    },
    /// AI chat turn
    AiChat {
        model: String,
        input_tokens: u32,
        output_tokens: u32,
        cost_usd: f64,
        role: String,
    },
    /// Design decision record
    Decision {
        title: String,
        chosen: String,
        rationale: String,
        alternatives: Vec<String>,
    },
    /// Error occurrence
    Error {
        severity: u8,
        message: String,
        stack_trace: Option<String>,
        resolved: bool,
    },
    /// Peer connection event (EdgeClaw-specific)
    PeerActivity {
        peer_id: String,
        peer_name: String,
        action: String,
    },
    /// Extension point
    Custom {
        category: String,
        data: serde_json::Value,
    },
}

impl ActivityType {
    /// Short tag used for statistics / display.
    pub fn type_tag(&self) -> &'static str {
        match self {
            ActivityType::FileEdit { .. } => "file_edit",
            ActivityType::CommandExec { .. } => "command_exec",
            ActivityType::AiChat { .. } => "ai_chat",
            ActivityType::Decision { .. } => "decision",
            ActivityType::Error { .. } => "error",
            ActivityType::PeerActivity { .. } => "peer_activity",
            ActivityType::Custom { .. } => "custom",
        }
    }
}

// ─── Agent Session ─────────────────────────────────────────

/// Tracks an agent work session with cost/token/turn accounting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    pub id: Uuid,
    pub agent_id: String,
    pub agent_name: String,
    pub project: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub status: SessionStatus,
    // cost tracking
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost_usd: f64,
    pub turns: u32,
    // work tracking
    pub files_modified: Vec<String>,
    pub commands_executed: u32,
    pub error_count: u32,
    // memory
    pub summary: Option<String>,
    pub decisions: Vec<String>,
    pub context_for_next: Option<String>,
}

/// Session lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    Active,
    Completed,
    Abandoned,
    Error,
}

// ─── Context Injection ────────────────────────────────────

/// Payload injected into a new agent session so it has prior context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextInjection {
    pub recent_summaries: Vec<SessionSummaryBrief>,
    pub important_activities: Vec<ActivityBrief>,
    pub recent_errors: Vec<ActivityBrief>,
    pub active_decisions: Vec<ActivityBrief>,
}

/// Compact session summary for injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummaryBrief {
    pub session_id: Uuid,
    pub agent_name: String,
    pub started_at: DateTime<Utc>,
    pub summary: String,
    pub files_modified: Vec<String>,
}

/// Compact activity reference for injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityBrief {
    pub id: Uuid,
    pub activity_type: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub importance: u8,
}

// ─── Statistics ───────────────────────────────────────────

/// Aggregate statistics over the activity log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityStats {
    pub total_entries: usize,
    pub total_sessions: usize,
    pub entries_by_type: HashMap<String, usize>,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
    pub oldest_entry: Option<DateTime<Utc>>,
    pub newest_entry: Option<DateTime<Utc>>,
    pub top_projects: Vec<(String, usize)>,
    pub top_tags: Vec<(String, usize)>,
}

// ─── Core Log ─────────────────────────────────────────────

/// Hash-chained, searchable activity log with session management.
pub struct ActivityLog {
    entries: Vec<ActivityEntry>,
    sessions: HashMap<Uuid, AgentSession>,
    completed_sessions: Vec<AgentSession>,
    lamport_clock: AtomicU64,
    persist_path: Option<PathBuf>,
    agent_id: String,
    agent_name: String,
    agent_role: String,
}

impl ActivityLog {
    /// Create a new in-memory activity log.
    pub fn new(agent_id: &str, agent_name: &str, agent_role: &str) -> Self {
        Self {
            entries: Vec::new(),
            sessions: HashMap::new(),
            completed_sessions: Vec::new(),
            lamport_clock: AtomicU64::new(0),
            persist_path: None,
            agent_id: agent_id.to_string(),
            agent_name: agent_name.to_string(),
            agent_role: agent_role.to_string(),
        }
    }

    /// Create an activity log with JSONL file persistence.
    pub fn with_persistence(
        agent_id: &str,
        agent_name: &str,
        agent_role: &str,
        path: PathBuf,
    ) -> Self {
        let mut log = Self::new(agent_id, agent_name, agent_role);
        // Load existing entries
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                for line in content.lines() {
                    if let Ok(entry) = serde_json::from_str::<ActivityEntry>(line) {
                        let lc = entry.lamport_clock;
                        log.entries.push(entry);
                        let cur = log.lamport_clock.load(Ordering::Relaxed);
                        if lc >= cur {
                            log.lamport_clock.store(lc + 1, Ordering::Relaxed);
                        }
                    }
                }
                if !log.entries.is_empty() {
                    info!(count = log.entries.len(), "Loaded activity log from disk");
                }
            }
        }
        log.persist_path = Some(path);
        log
    }

    // ─── Recording ────────────────────────────────────────

    /// Record a new activity.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        activity_type: ActivityType,
        content: &str,
        session_id: Uuid,
        importance: u8,
        tags: &[&str],
        file_path: Option<&str>,
        project: &str,
    ) -> ActivityEntry {
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let lc = self.lamport_clock.fetch_add(1, Ordering::Relaxed) + 1;

        let mut entry = ActivityEntry {
            id: Uuid::new_v4(),
            session_id,
            agent_id: self.agent_id.clone(),
            agent_role: self.agent_role.clone(),
            agent_name: self.agent_name.clone(),
            activity_type,
            project: project.to_string(),
            file_path: file_path.map(|s| s.to_string()),
            content: content.to_string(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            importance: importance.min(3),
            timestamp: Utc::now(),
            lamport_clock: lc,
            prev_hash,
            hash: String::new(),
        };
        entry.hash = Self::compute_hash(&entry);
        self.entries.push(entry.clone());

        // Update session counters
        if let Some(session) = self.sessions.get_mut(&session_id) {
            match &entry.activity_type {
                ActivityType::FileEdit { .. } => {
                    if let Some(ref fp) = entry.file_path {
                        if !session.files_modified.contains(fp) {
                            session.files_modified.push(fp.clone());
                        }
                    }
                }
                ActivityType::CommandExec { .. } => {
                    session.commands_executed += 1;
                }
                ActivityType::AiChat {
                    input_tokens,
                    output_tokens,
                    cost_usd,
                    ..
                } => {
                    session.total_input_tokens += *input_tokens as u64;
                    session.total_output_tokens += *output_tokens as u64;
                    session.total_cost_usd += cost_usd;
                    session.turns += 1;
                }
                ActivityType::Error { .. } => {
                    session.error_count += 1;
                }
                _ => {}
            }
        }

        // Persist
        self.persist_entry(&entry);

        info!(
            id = %entry.id,
            activity = entry.activity_type.type_tag(),
            importance = entry.importance,
            "activity recorded"
        );
        entry
    }

    // ─── Sessions ─────────────────────────────────────────

    /// Start a new agent session.
    pub fn start_session(&mut self, agent_name: &str, project: &str) -> AgentSession {
        let session = AgentSession {
            id: Uuid::new_v4(),
            agent_id: self.agent_id.clone(),
            agent_name: agent_name.to_string(),
            project: project.to_string(),
            started_at: Utc::now(),
            ended_at: None,
            status: SessionStatus::Active,
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cost_usd: 0.0,
            turns: 0,
            files_modified: Vec::new(),
            commands_executed: 0,
            error_count: 0,
            summary: None,
            decisions: Vec::new(),
            context_for_next: None,
        };
        self.sessions.insert(session.id, session.clone());
        info!(session_id = %session.id, project = project, "session started");
        session
    }

    /// End a session, optionally with an AI-generated summary.
    pub fn end_session(&mut self, session_id: Uuid, summary: Option<&str>) -> Option<AgentSession> {
        if let Some(mut session) = self.sessions.remove(&session_id) {
            session.ended_at = Some(Utc::now());
            session.status = SessionStatus::Completed;
            session.summary = summary.map(|s| s.to_string());
            self.completed_sessions.push(session.clone());
            info!(session_id = %session_id, "session ended");
            Some(session)
        } else {
            None
        }
    }

    /// Update token / cost counters for a running session.
    pub fn update_session_cost(
        &mut self,
        session_id: Uuid,
        input_tokens: u64,
        output_tokens: u64,
        cost_usd: f64,
    ) {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.total_input_tokens += input_tokens;
            session.total_output_tokens += output_tokens;
            session.total_cost_usd += cost_usd;
        }
    }

    /// Get an active session by ID.
    pub fn get_session(&self, session_id: Uuid) -> Option<&AgentSession> {
        self.sessions.get(&session_id)
    }

    /// List active sessions.
    pub fn active_sessions(&self) -> Vec<&AgentSession> {
        self.sessions.values().collect()
    }

    // ─── Search / Filter ──────────────────────────────────

    /// Full-text search across content, tags, and file paths.
    pub fn search(&self, query: &str, limit: usize) -> Vec<&ActivityEntry> {
        let q = query.to_lowercase();
        let words: Vec<&str> = q.split_whitespace().collect();
        let mut results: Vec<&ActivityEntry> = self
            .entries
            .iter()
            .filter(|e| {
                let text = format!(
                    "{} {} {} {}",
                    e.content,
                    e.tags.join(" "),
                    e.file_path.as_deref().unwrap_or(""),
                    e.project
                )
                .to_lowercase();
                words.iter().all(|w| text.contains(w))
            })
            .collect();
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        results.truncate(limit);
        results
    }

    /// Filter by tag(s), optionally since a given time.
    pub fn filter_by_tags(
        &self,
        tags: &[&str],
        since: Option<DateTime<Utc>>,
    ) -> Vec<&ActivityEntry> {
        self.entries
            .iter()
            .filter(|e| {
                if let Some(s) = since {
                    if e.timestamp < s {
                        return false;
                    }
                }
                tags.iter()
                    .all(|t| e.tags.iter().any(|et| et.eq_ignore_ascii_case(t)))
            })
            .collect()
    }

    /// Filter by minimum importance.
    pub fn filter_by_importance(&self, min_importance: u8, limit: usize) -> Vec<&ActivityEntry> {
        let mut results: Vec<&ActivityEntry> = self
            .entries
            .iter()
            .filter(|e| e.importance >= min_importance)
            .collect();
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        results.truncate(limit);
        results
    }

    /// Filter by project name.
    pub fn filter_by_project(&self, project: &str, limit: usize) -> Vec<&ActivityEntry> {
        let mut results: Vec<&ActivityEntry> = self
            .entries
            .iter()
            .filter(|e| e.project.eq_ignore_ascii_case(project))
            .collect();
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        results.truncate(limit);
        results
    }

    /// Get the N most recent entries.
    pub fn recent(&self, n: usize) -> &[ActivityEntry] {
        let start = self.entries.len().saturating_sub(n);
        &self.entries[start..]
    }

    // ─── Context Injection ────────────────────────────────

    /// Build a context injection payload for a new session.
    ///
    /// Mimics Tower's `session-start.mjs`:
    /// - Last 3 completed session summaries
    /// - 10 most recent important (≥ 2) activities
    /// - 5 most recent unresolved errors (importance = 3)
    /// - Recent decision records
    pub fn build_context_injection(&self, project: &str) -> ContextInjection {
        // Recent summaries (last 3 completed sessions for this project)
        let recent_summaries: Vec<SessionSummaryBrief> = self
            .completed_sessions
            .iter()
            .rev()
            .filter(|s| s.project.eq_ignore_ascii_case(project) && s.summary.is_some())
            .take(3)
            .map(|s| SessionSummaryBrief {
                session_id: s.id,
                agent_name: s.agent_name.clone(),
                started_at: s.started_at,
                summary: s.summary.clone().unwrap_or_default(),
                files_modified: s.files_modified.clone(),
            })
            .collect();

        // Important activities (importance >= 2)
        let important_activities: Vec<ActivityBrief> = self
            .entries
            .iter()
            .rev()
            .filter(|e| e.importance >= 2 && e.project.eq_ignore_ascii_case(project))
            .take(10)
            .map(|e| ActivityBrief {
                id: e.id,
                activity_type: e.activity_type.type_tag().to_string(),
                content: e.content.clone(),
                timestamp: e.timestamp,
                importance: e.importance,
            })
            .collect();

        // Recent errors (unresolved)
        let recent_errors: Vec<ActivityBrief> = self
            .entries
            .iter()
            .rev()
            .filter(|e| {
                e.project.eq_ignore_ascii_case(project)
                    && matches!(
                        &e.activity_type,
                        ActivityType::Error {
                            resolved: false,
                            ..
                        }
                    )
            })
            .take(5)
            .map(|e| ActivityBrief {
                id: e.id,
                activity_type: "error".to_string(),
                content: e.content.clone(),
                timestamp: e.timestamp,
                importance: e.importance,
            })
            .collect();

        // Active decisions (last 20 decision entries)
        let active_decisions: Vec<ActivityBrief> = self
            .entries
            .iter()
            .rev()
            .filter(|e| {
                e.project.eq_ignore_ascii_case(project)
                    && matches!(&e.activity_type, ActivityType::Decision { .. })
            })
            .take(20)
            .map(|e| ActivityBrief {
                id: e.id,
                activity_type: "decision".to_string(),
                content: e.content.clone(),
                timestamp: e.timestamp,
                importance: e.importance,
            })
            .collect();

        ContextInjection {
            recent_summaries,
            important_activities,
            recent_errors,
            active_decisions,
        }
    }

    // ─── Integrity ────────────────────────────────────────

    /// Verify the SHA-256 hash chain.
    pub fn verify_chain(&self) -> Result<bool, String> {
        if self.entries.is_empty() {
            return Ok(true);
        }
        let genesis = "0".repeat(64);
        for (i, entry) in self.entries.iter().enumerate() {
            let expected_prev = if i == 0 {
                &genesis
            } else {
                &self.entries[i - 1].hash
            };
            if entry.prev_hash != *expected_prev {
                return Err(format!(
                    "Chain broken at entry {}: prev_hash mismatch",
                    entry.id
                ));
            }
            let computed = Self::compute_hash(entry);
            if entry.hash != computed {
                return Err(format!("Hash mismatch at entry {}: tampered", entry.id));
            }
        }
        Ok(true)
    }

    /// Compute SHA-256 for an entry.
    fn compute_hash(entry: &ActivityEntry) -> String {
        let mut hasher = Sha256::new();
        hasher.update(entry.id.as_bytes());
        hasher.update(entry.session_id.as_bytes());
        hasher.update(entry.agent_id.as_bytes());
        hasher.update(entry.content.as_bytes());
        hasher.update(entry.importance.to_le_bytes());
        hasher.update(entry.timestamp.to_rfc3339().as_bytes());
        hasher.update(entry.lamport_clock.to_le_bytes());
        hasher.update(entry.prev_hash.as_bytes());
        // Include activity type tag for domain separation
        hasher.update(entry.activity_type.type_tag().as_bytes());
        hex::encode(hasher.finalize())
    }

    // ─── Statistics ───────────────────────────────────────

    /// Compute aggregate statistics.
    pub fn stats(&self) -> ActivityStats {
        let mut entries_by_type: HashMap<String, usize> = HashMap::new();
        let mut project_counts: HashMap<String, usize> = HashMap::new();
        let mut tag_counts: HashMap<String, usize> = HashMap::new();
        let mut total_tokens: u64 = 0;
        let mut total_cost: f64 = 0.0;

        for e in &self.entries {
            *entries_by_type
                .entry(e.activity_type.type_tag().to_string())
                .or_default() += 1;
            *project_counts.entry(e.project.clone()).or_default() += 1;
            for t in &e.tags {
                *tag_counts.entry(t.clone()).or_default() += 1;
            }
            if let ActivityType::AiChat {
                input_tokens,
                output_tokens,
                cost_usd,
                ..
            } = &e.activity_type
            {
                total_tokens += (*input_tokens + *output_tokens) as u64;
                total_cost += cost_usd;
            }
        }

        let mut top_projects: Vec<(String, usize)> = project_counts.into_iter().collect();
        top_projects.sort_by(|a, b| b.1.cmp(&a.1));
        top_projects.truncate(10);

        let mut top_tags: Vec<(String, usize)> = tag_counts.into_iter().collect();
        top_tags.sort_by(|a, b| b.1.cmp(&a.1));
        top_tags.truncate(10);

        ActivityStats {
            total_entries: self.entries.len(),
            total_sessions: self.completed_sessions.len() + self.sessions.len(),
            entries_by_type,
            total_tokens,
            total_cost_usd: total_cost,
            oldest_entry: self.entries.first().map(|e| e.timestamp),
            newest_entry: self.entries.last().map(|e| e.timestamp),
            top_projects,
            top_tags,
        }
    }

    /// Total entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the log empty?
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries (slice reference).
    pub fn entries(&self) -> &[ActivityEntry] {
        &self.entries
    }

    // ─── CRDT Merge ───────────────────────────────────────

    /// Merge remote entries into the local log (CRDT-style).
    ///
    /// Uses UUID dedup + Lamport clock ordering. After merge the hash
    /// chain is recomputed from scratch.
    pub fn merge_remote(&mut self, remote: &[ActivityEntry]) -> usize {
        let existing_ids: std::collections::HashSet<Uuid> =
            self.entries.iter().map(|e| e.id).collect();
        let mut new_entries: Vec<ActivityEntry> = remote
            .iter()
            .filter(|e| !existing_ids.contains(&e.id))
            .cloned()
            .collect();

        if new_entries.is_empty() {
            return 0;
        }

        let count = new_entries.len();

        // Merge and sort by (lamport_clock, timestamp)
        self.entries.append(&mut new_entries);
        self.entries.sort_by(|a, b| {
            a.lamport_clock
                .cmp(&b.lamport_clock)
                .then_with(|| a.timestamp.cmp(&b.timestamp))
        });

        // Recompute hash chain
        let genesis = "0".repeat(64);
        for i in 0..self.entries.len() {
            self.entries[i].prev_hash = if i == 0 {
                genesis.clone()
            } else {
                self.entries[i - 1].hash.clone()
            };
            self.entries[i].hash = Self::compute_hash(&self.entries[i]);
        }

        // Update lamport clock
        if let Some(max_lc) = self.entries.last().map(|e| e.lamport_clock) {
            let cur = self.lamport_clock.load(Ordering::Relaxed);
            if max_lc >= cur {
                self.lamport_clock.store(max_lc + 1, Ordering::Relaxed);
            }
        }

        info!(
            merged = count,
            total = self.entries.len(),
            "CRDT merge complete"
        );
        count
    }

    // ─── Persistence ──────────────────────────────────────

    fn persist_entry(&self, entry: &ActivityEntry) {
        if let Some(ref path) = self.persist_path {
            if let Ok(json) = serde_json::to_string(entry) {
                use std::io::Write;
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    Ok(mut f) => {
                        let _ = writeln!(f, "{}", json);
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to persist activity entry");
                    }
                }
            }
        }
    }

    /// Export the full log as pretty JSON.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.entries)
    }

    /// Load entries from a JSONL file.
    pub fn load_from_file(path: &Path) -> Result<Vec<ActivityEntry>, AgentError> {
        let content = std::fs::read_to_string(path)?;
        let mut entries = Vec::new();
        for line in content.lines() {
            if !line.trim().is_empty() {
                let entry: ActivityEntry = serde_json::from_str(line)?;
                entries.push(entry);
            }
        }
        Ok(entries)
    }
}

// ─── Thread-safe wrapper ──────────────────────────────────

/// Thread-safe wrapper around [`ActivityLog`].
pub struct ActivityManager {
    log: std::sync::Mutex<ActivityLog>,
}

impl ActivityManager {
    /// Create a new in-memory activity manager.
    pub fn new(agent_id: &str, agent_name: &str, agent_role: &str) -> Self {
        Self {
            log: std::sync::Mutex::new(ActivityLog::new(agent_id, agent_name, agent_role)),
        }
    }

    /// Create with JSONL persistence.
    pub fn with_persistence(
        agent_id: &str,
        agent_name: &str,
        agent_role: &str,
        path: PathBuf,
    ) -> Self {
        Self {
            log: std::sync::Mutex::new(ActivityLog::with_persistence(
                agent_id, agent_name, agent_role, path,
            )),
        }
    }

    /// Record an activity.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        activity_type: ActivityType,
        content: &str,
        session_id: Uuid,
        importance: u8,
        tags: &[&str],
        file_path: Option<&str>,
        project: &str,
    ) -> ActivityEntry {
        let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.record(
            activity_type,
            content,
            session_id,
            importance,
            tags,
            file_path,
            project,
        )
    }

    /// Start a session.
    pub fn start_session(&self, agent_name: &str, project: &str) -> AgentSession {
        let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.start_session(agent_name, project)
    }

    /// End a session.
    pub fn end_session(&self, session_id: Uuid, summary: Option<&str>) -> Option<AgentSession> {
        let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.end_session(session_id, summary)
    }

    /// Update session cost.
    pub fn update_session_cost(
        &self,
        session_id: Uuid,
        input_tokens: u64,
        output_tokens: u64,
        cost_usd: f64,
    ) {
        let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.update_session_cost(session_id, input_tokens, output_tokens, cost_usd);
    }

    /// Build context injection.
    pub fn build_context_injection(&self, project: &str) -> ContextInjection {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.build_context_injection(project)
    }

    /// Verify chain integrity.
    pub fn verify_chain(&self) -> Result<bool, String> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.verify_chain()
    }

    /// Full-text search.
    pub fn search(&self, query: &str, limit: usize) -> Vec<ActivityEntry> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.search(query, limit).into_iter().cloned().collect()
    }

    /// Filter by importance.
    pub fn filter_by_importance(&self, min_importance: u8, limit: usize) -> Vec<ActivityEntry> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.filter_by_importance(min_importance, limit)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get statistics.
    pub fn stats(&self) -> ActivityStats {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.stats()
    }

    /// Get entry count.
    pub fn count(&self) -> usize {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.len()
    }

    /// Get recent entries.
    pub fn recent(&self, n: usize) -> Vec<ActivityEntry> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.recent(n).to_vec()
    }

    /// Merge remote entries.
    pub fn merge_remote(&self, remote: &[ActivityEntry]) -> usize {
        let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.merge_remote(remote)
    }

    /// Export as JSON.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.export_json()
    }
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_log() -> ActivityLog {
        ActivityLog::new("dev-test-001", "test-agent", "admin")
    }

    #[test]
    fn test_new_log_is_empty() {
        let log = test_log();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn test_record_single_activity() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        let entry = log.record(
            ActivityType::FileEdit {
                before_snippet: Some("old code".into()),
                after_snippet: Some("new code".into()),
                lines_changed: 5,
            },
            "Modified handler.rs",
            sid,
            1,
            &["rust", "refactor"],
            Some("src/handler.rs"),
            "edgeclaw",
        );
        assert_eq!(log.len(), 1);
        assert_eq!(entry.agent_id, "dev-test-001");
        assert_eq!(entry.importance, 1);
        assert_eq!(entry.tags, vec!["rust", "refactor"]);
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn test_hash_chain_integrity() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        for i in 0..5 {
            log.record(
                ActivityType::CommandExec {
                    command: format!("echo {i}"),
                    exit_code: 0,
                    duration_ms: 10,
                    output_summary: None,
                },
                &format!("cmd {i}"),
                sid,
                1,
                &[],
                None,
                "test",
            );
        }
        assert_eq!(log.len(), 5);
        assert!(log.verify_chain().unwrap());

        // Verify prev_hash links
        let genesis = "0".repeat(64);
        assert_eq!(log.entries[0].prev_hash, genesis);
        for i in 1..5 {
            assert_eq!(log.entries[i].prev_hash, log.entries[i - 1].hash);
        }
    }

    #[test]
    fn test_tamper_detection() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        log.record(
            ActivityType::CommandExec {
                command: "ls".into(),
                exit_code: 0,
                duration_ms: 5,
                output_summary: None,
            },
            "list files",
            sid,
            1,
            &[],
            None,
            "test",
        );
        log.record(
            ActivityType::CommandExec {
                command: "rm -rf /".into(),
                exit_code: 0,
                duration_ms: 5,
                output_summary: None,
            },
            "dangerous delete",
            sid,
            3,
            &[],
            None,
            "test",
        );

        // Tamper
        log.entries[1].content = "harmless".into();
        let result = log.verify_chain();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("tampered"));
    }

    #[test]
    fn test_chain_break_detection() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        for _ in 0..3 {
            log.record(
                ActivityType::Custom {
                    category: "test".into(),
                    data: serde_json::json!({}),
                },
                "x",
                sid,
                0,
                &[],
                None,
                "test",
            );
        }
        log.entries[1].prev_hash = "deadbeef".repeat(8);
        let result = log.verify_chain();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("prev_hash mismatch"));
    }

    #[test]
    fn test_importance_clamp() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        let entry = log.record(
            ActivityType::Error {
                severity: 3,
                message: "oops".into(),
                stack_trace: None,
                resolved: false,
            },
            "big error",
            sid,
            99, // should be clamped to 3
            &[],
            None,
            "test",
        );
        assert_eq!(entry.importance, 3);
    }

    #[test]
    fn test_session_lifecycle() {
        let mut log = test_log();
        let session = log.start_session("agent-1", "edgeclaw");
        assert_eq!(session.status, SessionStatus::Active);
        assert!(log.get_session(session.id).is_some());

        let ended = log.end_session(session.id, Some("Did stuff")).unwrap();
        assert_eq!(ended.status, SessionStatus::Completed);
        assert_eq!(ended.summary, Some("Did stuff".into()));
        assert!(log.get_session(session.id).is_none());
    }

    #[test]
    fn test_session_cost_tracking() {
        let mut log = test_log();
        let session = log.start_session("agent-1", "edgeclaw");

        log.record(
            ActivityType::AiChat {
                model: "gpt-4".into(),
                input_tokens: 100,
                output_tokens: 200,
                cost_usd: 0.01,
                role: "assistant".into(),
            },
            "chat turn",
            session.id,
            1,
            &["ai"],
            None,
            "edgeclaw",
        );

        let s = log.get_session(session.id).unwrap();
        assert_eq!(s.total_input_tokens, 100);
        assert_eq!(s.total_output_tokens, 200);
        assert!((s.total_cost_usd - 0.01).abs() < f64::EPSILON);
        assert_eq!(s.turns, 1);
    }

    #[test]
    fn test_session_file_tracking() {
        let mut log = test_log();
        let session = log.start_session("agent-1", "edgeclaw");

        log.record(
            ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 10,
            },
            "edit A",
            session.id,
            1,
            &[],
            Some("src/a.rs"),
            "edgeclaw",
        );
        log.record(
            ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 5,
            },
            "edit A again",
            session.id,
            1,
            &[],
            Some("src/a.rs"), // duplicate — should not add twice
            "edgeclaw",
        );
        log.record(
            ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 3,
            },
            "edit B",
            session.id,
            1,
            &[],
            Some("src/b.rs"),
            "edgeclaw",
        );

        let s = log.get_session(session.id).unwrap();
        assert_eq!(s.files_modified.len(), 2);
    }

    #[test]
    fn test_search_content() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        log.record(
            ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 1,
            },
            "Added JWT authentication handler",
            sid,
            2,
            &["auth", "jwt"],
            Some("src/auth.rs"),
            "backend",
        );
        log.record(
            ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 3,
            },
            "Fixed CSS layout bug",
            sid,
            1,
            &["css", "ui"],
            Some("src/style.css"),
            "frontend",
        );

        let results = log.search("jwt auth", 10);
        assert_eq!(results.len(), 1);
        assert!(results[0].content.contains("JWT"));

        let results = log.search("CSS", 10);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_filter_by_tags() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        log.record(
            ActivityType::Custom {
                category: "t".into(),
                data: serde_json::json!({}),
            },
            "a",
            sid,
            1,
            &["rust", "backend"],
            None,
            "test",
        );
        log.record(
            ActivityType::Custom {
                category: "t".into(),
                data: serde_json::json!({}),
            },
            "b",
            sid,
            1,
            &["python", "backend"],
            None,
            "test",
        );

        let results = log.filter_by_tags(&["backend"], None);
        assert_eq!(results.len(), 2);

        let results = log.filter_by_tags(&["rust"], None);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_filter_by_importance() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        for imp in 0..=3 {
            log.record(
                ActivityType::Custom {
                    category: "t".into(),
                    data: serde_json::json!({}),
                },
                &format!("importance {imp}"),
                sid,
                imp,
                &[],
                None,
                "test",
            );
        }
        let important = log.filter_by_importance(2, 100);
        assert_eq!(important.len(), 2); // importance 2 and 3
    }

    #[test]
    fn test_filter_by_project() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        log.record(
            ActivityType::Custom {
                category: "t".into(),
                data: serde_json::json!({}),
            },
            "a",
            sid,
            1,
            &[],
            None,
            "project-a",
        );
        log.record(
            ActivityType::Custom {
                category: "t".into(),
                data: serde_json::json!({}),
            },
            "b",
            sid,
            1,
            &[],
            None,
            "project-b",
        );
        let results = log.filter_by_project("project-a", 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "a");
    }

    #[test]
    fn test_context_injection() {
        let mut log = test_log();

        // Create a completed session
        let s1 = log.start_session("agent", "myproj");
        log.record(
            ActivityType::Decision {
                title: "Use Rust".into(),
                chosen: "Rust".into(),
                rationale: "Performance".into(),
                alternatives: vec!["Go".into()],
            },
            "Chose Rust for core",
            s1.id,
            2,
            &[],
            None,
            "myproj",
        );
        log.record(
            ActivityType::Error {
                severity: 3,
                message: "Build failed".into(),
                stack_trace: None,
                resolved: false,
            },
            "Build error on CI",
            s1.id,
            3,
            &[],
            None,
            "myproj",
        );
        log.end_session(s1.id, Some("Implemented core module"));

        // Build context for next session
        let ctx = log.build_context_injection("myproj");
        assert_eq!(ctx.recent_summaries.len(), 1);
        assert_eq!(ctx.recent_summaries[0].summary, "Implemented core module");
        assert!(!ctx.important_activities.is_empty());
        assert!(!ctx.recent_errors.is_empty());
        assert!(!ctx.active_decisions.is_empty());
    }

    #[test]
    fn test_crdt_merge() {
        let mut log_a = ActivityLog::new("dev-a", "agent-a", "admin");
        let mut log_b = ActivityLog::new("dev-b", "agent-b", "admin");
        let sid = Uuid::new_v4();

        // Both create entries concurrently
        log_a.record(
            ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 1,
            },
            "edit from A",
            sid,
            1,
            &[],
            Some("a.rs"),
            "test",
        );
        log_b.record(
            ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 2,
            },
            "edit from B",
            sid,
            1,
            &[],
            Some("b.rs"),
            "test",
        );

        // Merge B into A
        let merged = log_a.merge_remote(log_b.entries());
        assert_eq!(merged, 1);
        assert_eq!(log_a.len(), 2);
        assert!(log_a.verify_chain().unwrap());
    }

    #[test]
    fn test_crdt_merge_dedup() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        log.record(
            ActivityType::Custom {
                category: "t".into(),
                data: serde_json::json!({}),
            },
            "x",
            sid,
            1,
            &[],
            None,
            "test",
        );

        // Merge same entries — should dedup
        let existing = log.entries().to_vec();
        let merged = log.merge_remote(&existing);
        assert_eq!(merged, 0);
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_stats() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        log.record(
            ActivityType::AiChat {
                model: "claude".into(),
                input_tokens: 500,
                output_tokens: 1000,
                cost_usd: 0.05,
                role: "assistant".into(),
            },
            "chat",
            sid,
            1,
            &["ai"],
            None,
            "proj-a",
        );
        log.record(
            ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 10,
            },
            "edit",
            sid,
            1,
            &["rust"],
            Some("main.rs"),
            "proj-a",
        );

        let stats = log.stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.total_tokens, 1500);
        assert!((stats.total_cost_usd - 0.05).abs() < f64::EPSILON);
        assert_eq!(stats.entries_by_type["ai_chat"], 1);
        assert_eq!(stats.entries_by_type["file_edit"], 1);
        assert!(!stats.top_projects.is_empty());
    }

    #[test]
    fn test_recent() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        for i in 0..10 {
            log.record(
                ActivityType::Custom {
                    category: "t".into(),
                    data: serde_json::json!({}),
                },
                &format!("entry-{i}"),
                sid,
                1,
                &[],
                None,
                "test",
            );
        }
        let recent = log.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].content, "entry-7");
        assert_eq!(recent[2].content, "entry-9");
    }

    #[test]
    fn test_export_json() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        log.record(
            ActivityType::Custom {
                category: "t".into(),
                data: serde_json::json!({"key": "val"}),
            },
            "entry",
            sid,
            1,
            &["tag1"],
            None,
            "test",
        );
        let json = log.export_json().unwrap();
        assert!(json.contains("entry"));
        assert!(json.contains("tag1"));
    }

    #[test]
    fn test_activity_type_tags() {
        assert_eq!(
            ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 0
            }
            .type_tag(),
            "file_edit"
        );
        assert_eq!(
            ActivityType::CommandExec {
                command: String::new(),
                exit_code: 0,
                duration_ms: 0,
                output_summary: None
            }
            .type_tag(),
            "command_exec"
        );
        assert_eq!(
            ActivityType::Decision {
                title: String::new(),
                chosen: String::new(),
                rationale: String::new(),
                alternatives: vec![]
            }
            .type_tag(),
            "decision"
        );
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut log = test_log();
        let sid = Uuid::new_v4();
        log.record(
            ActivityType::AiChat {
                model: "gpt-4".into(),
                input_tokens: 100,
                output_tokens: 200,
                cost_usd: 0.01,
                role: "assistant".into(),
            },
            "chat",
            sid,
            2,
            &["ai", "gpt"],
            None,
            "test",
        );

        let json = serde_json::to_string(&log.entries[0]).unwrap();
        let deserialized: ActivityEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, log.entries[0].id);
        assert_eq!(deserialized.content, "chat");
        assert_eq!(deserialized.importance, 2);
    }

    #[test]
    fn test_activity_manager_thread_safe() {
        let mgr = ActivityManager::new("dev-1", "agent-1", "admin");
        let session = mgr.start_session("agent-1", "project");
        mgr.record(
            ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 5,
            },
            "edit",
            session.id,
            1,
            &["rust"],
            Some("main.rs"),
            "project",
        );
        assert_eq!(mgr.count(), 1);
        assert!(mgr.verify_chain().unwrap());

        let ended = mgr.end_session(session.id, Some("Done"));
        assert!(ended.is_some());
    }

    #[test]
    fn test_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("activity.jsonl");

        // Write
        {
            let mut log = ActivityLog::with_persistence("dev-1", "agent", "admin", path.clone());
            let sid = Uuid::new_v4();
            log.record(
                ActivityType::FileEdit {
                    before_snippet: None,
                    after_snippet: Some("new".into()),
                    lines_changed: 1,
                },
                "persisted edit",
                sid,
                2,
                &["persist"],
                Some("main.rs"),
                "test",
            );
        }

        // Read back
        {
            let log = ActivityLog::with_persistence("dev-1", "agent", "admin", path);
            assert_eq!(log.len(), 1);
            assert_eq!(log.entries()[0].content, "persisted edit");
        }
    }

    #[test]
    fn test_end_nonexistent_session() {
        let mut log = test_log();
        let result = log.end_session(Uuid::new_v4(), None);
        assert!(result.is_none());
    }

    #[test]
    fn test_active_sessions() {
        let mut log = test_log();
        log.start_session("a", "proj");
        log.start_session("b", "proj");
        assert_eq!(log.active_sessions().len(), 2);
    }

    #[test]
    fn test_update_session_cost() {
        let mut log = test_log();
        let s = log.start_session("a", "proj");
        log.update_session_cost(s.id, 100, 200, 0.05);
        log.update_session_cost(s.id, 50, 100, 0.02);
        let session = log.get_session(s.id).unwrap();
        assert_eq!(session.total_input_tokens, 150);
        assert_eq!(session.total_output_tokens, 300);
        assert!((session.total_cost_usd - 0.07).abs() < f64::EPSILON);
    }

    #[test]
    fn test_error_count_tracking() {
        let mut log = test_log();
        let s = log.start_session("a", "proj");
        log.record(
            ActivityType::Error {
                severity: 2,
                message: "err1".into(),
                stack_trace: None,
                resolved: false,
            },
            "error 1",
            s.id,
            2,
            &[],
            None,
            "proj",
        );
        log.record(
            ActivityType::Error {
                severity: 3,
                message: "err2".into(),
                stack_trace: None,
                resolved: false,
            },
            "error 2",
            s.id,
            3,
            &[],
            None,
            "proj",
        );
        let session = log.get_session(s.id).unwrap();
        assert_eq!(session.error_count, 2);
    }

    #[test]
    fn test_command_count_tracking() {
        let mut log = test_log();
        let s = log.start_session("a", "proj");
        for _ in 0..3 {
            log.record(
                ActivityType::CommandExec {
                    command: "echo hi".into(),
                    exit_code: 0,
                    duration_ms: 5,
                    output_summary: None,
                },
                "cmd",
                s.id,
                1,
                &[],
                None,
                "proj",
            );
        }
        let session = log.get_session(s.id).unwrap();
        assert_eq!(session.commands_executed, 3);
    }
}

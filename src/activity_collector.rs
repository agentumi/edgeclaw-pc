//! Collects [`AgentEvent`]s from the [`EventBus`] and converts them into
//! [`ActivityEntry`] records in the [`ActivityManager`].
//!
//! Serves the same role as Tower's `post-tool-use.mjs` memory hook but
//! runs in-process with configurable noise filters.

use std::sync::Arc;
use uuid::Uuid;

use crate::activity_log::{ActivityManager, ActivityType};
use crate::events::AgentEvent;

// ─── Noise Filter ─────────────────────────────────────────

/// Rule for suppressing noisy or irrelevant activity records.
#[derive(Debug, Clone)]
pub enum NoiseFilter {
    /// Ignore file paths matching a glob pattern.
    PathGlob(String),
    /// Ignore commands matching a substring.
    CommandSubstring(String),
    /// Ignore entries below this importance threshold.
    MinImportance(u8),
}

impl NoiseFilter {
    /// Check whether a candidate activity should be suppressed.
    pub fn should_filter(
        &self,
        file_path: Option<&str>,
        command: Option<&str>,
        importance: u8,
    ) -> bool {
        match self {
            NoiseFilter::PathGlob(pattern) => {
                if let Some(fp) = file_path {
                    fp.contains(pattern)
                } else {
                    false
                }
            }
            NoiseFilter::CommandSubstring(sub) => {
                if let Some(cmd) = command {
                    cmd.contains(sub)
                } else {
                    false
                }
            }
            NoiseFilter::MinImportance(min) => importance < *min,
        }
    }
}

// ─── Collector ────────────────────────────────────────────

/// Transforms [`AgentEvent`]s into [`ActivityEntry`] records.
pub struct ActivityCollector {
    activity_manager: Arc<ActivityManager>,
    filters: Vec<NoiseFilter>,
    project: String,
}

impl ActivityCollector {
    /// Create a new collector wired to the given activity manager.
    pub fn new(activity_manager: Arc<ActivityManager>, project: &str) -> Self {
        Self {
            activity_manager,
            filters: default_filters(),
            project: project.to_string(),
        }
    }

    /// Add a custom noise filter.
    pub fn add_filter(&mut self, filter: NoiseFilter) {
        self.filters.push(filter);
    }

    /// Set the project/workspace name.
    pub fn set_project(&mut self, project: &str) {
        self.project = project.to_string();
    }

    /// Process a single event.  Returns the recorded entry ID on success,
    /// or `None` if the event was filtered out.
    pub fn process_event(&self, event: &AgentEvent, session_id: Uuid) -> Option<Uuid> {
        let (activity_type, content, importance, tags, file_path, command) =
            self.classify(event)?;

        // Apply noise filters
        for f in &self.filters {
            if f.should_filter(file_path.as_deref(), command.as_deref(), importance) {
                return None;
            }
        }

        let entry = self.activity_manager.record(
            activity_type,
            &content,
            session_id,
            importance,
            &tags.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            file_path.as_deref(),
            &self.project,
        );
        Some(entry.id)
    }

    /// Classify an event into activity fields.
    #[allow(clippy::type_complexity)]
    fn classify(
        &self,
        event: &AgentEvent,
    ) -> Option<(
        ActivityType,
        String,
        u8,
        Vec<String>,
        Option<String>,
        Option<String>,
    )> {
        match event {
            AgentEvent::CommandStarted {
                command, peer_id, ..
            } => Some((
                ActivityType::CommandExec {
                    command: command.clone(),
                    exit_code: -1, // pending
                    duration_ms: 0,
                    output_summary: None,
                },
                format!("Command started by {peer_id}: {command}"),
                1,
                vec!["command".into(), "started".into()],
                None,
                Some(command.clone()),
            )),

            AgentEvent::CommandCompleted {
                execution_id,
                success,
                exit_code,
                duration_ms,
            } => {
                let imp = if *success { 1 } else { 2 };
                Some((
                    ActivityType::CommandExec {
                        command: execution_id.clone(),
                        exit_code: exit_code.unwrap_or(-1),
                        duration_ms: *duration_ms,
                        output_summary: None,
                    },
                    format!(
                        "Command {} (exit={}, {}ms)",
                        if *success { "succeeded" } else { "failed" },
                        exit_code.unwrap_or(-1),
                        duration_ms,
                    ),
                    imp,
                    vec!["command".into(), "completed".into()],
                    None,
                    None,
                ))
            }

            AgentEvent::ChatMessage {
                peer_id,
                role,
                content,
            } => Some((
                ActivityType::AiChat {
                    model: "unknown".into(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost_usd: 0.0,
                    role: role.clone(),
                },
                format!("[{role}@{peer_id}] {}", truncate(content, 200)),
                1,
                vec!["chat".into(), role.clone()],
                None,
                None,
            )),

            AgentEvent::PeerConnected {
                peer_id,
                device_name,
                address,
            } => Some((
                ActivityType::PeerActivity {
                    peer_id: peer_id.clone(),
                    peer_name: device_name.clone(),
                    action: "connected".into(),
                },
                format!("Peer connected: {device_name} ({address})"),
                1,
                vec!["peer".into(), "connected".into()],
                None,
                None,
            )),

            AgentEvent::PeerDisconnected { peer_id, reason } => Some((
                ActivityType::PeerActivity {
                    peer_id: peer_id.clone(),
                    peer_name: String::new(),
                    action: "disconnected".into(),
                },
                format!("Peer disconnected: {peer_id} — {reason}"),
                1,
                vec!["peer".into(), "disconnected".into()],
                None,
                None,
            )),

            AgentEvent::Alert {
                severity,
                message,
                source,
            } => {
                let sev = match severity {
                    crate::events::AlertSeverity::Info => 1u8,
                    crate::events::AlertSeverity::Warning => 2,
                    crate::events::AlertSeverity::Critical => 3,
                };
                Some((
                    ActivityType::Error {
                        severity: sev,
                        message: message.clone(),
                        stack_trace: None,
                        resolved: false,
                    },
                    format!("[{source}] {message}"),
                    sev,
                    vec!["alert".into(), source.clone()],
                    None,
                    None,
                ))
            }

            AgentEvent::AuditEntry {
                sequence,
                actor,
                capability,
                result,
            } => Some((
                ActivityType::Custom {
                    category: "audit".into(),
                    data: serde_json::json!({
                        "sequence": sequence,
                        "actor": actor,
                        "capability": capability,
                        "result": result,
                    }),
                },
                format!("Audit #{sequence}: {actor} → {capability} = {result}"),
                1,
                vec!["audit".into()],
                None,
                None,
            )),

            AgentEvent::FileModified {
                file_path,
                lines_changed,
                before_snippet,
                after_snippet,
                peer_id,
            } => Some((
                ActivityType::FileEdit {
                    before_snippet: before_snippet.clone(),
                    after_snippet: after_snippet.clone(),
                    lines_changed: *lines_changed,
                },
                format!("Modified {file_path} ({lines_changed} lines) by {peer_id}"),
                2,
                vec!["file".into(), "edit".into()],
                None,
                Some(file_path.clone()),
            )),

            AgentEvent::DecisionMade {
                title,
                chosen,
                rationale,
                alternatives,
            } => Some((
                ActivityType::Decision {
                    title: title.clone(),
                    chosen: chosen.clone(),
                    rationale: rationale.clone(),
                    alternatives: alternatives.clone(),
                },
                format!("Decision: {title} → {chosen}"),
                3,
                vec!["decision".into()],
                None,
                None,
            )),

            AgentEvent::ErrorOccurred {
                severity,
                message,
                source,
                stack_trace,
            } => Some((
                ActivityType::Error {
                    severity: *severity,
                    message: message.clone(),
                    stack_trace: stack_trace.clone(),
                    resolved: false,
                },
                format!("[{source}] {message}"),
                if *severity >= 3 { 3 } else { *severity },
                vec!["error".into(), source.clone()],
                None,
                None,
            )),

            // Status & metric events are low-value noise; skip by default
            AgentEvent::StatusChange { .. }
            | AgentEvent::Heartbeat { .. }
            | AgentEvent::MetricUpdate { .. }
            | AgentEvent::CommandOutput { .. } => None,
        }
    }
}

/// Default noise filters (mirrors Tower's exclusions).
fn default_filters() -> Vec<NoiseFilter> {
    vec![
        NoiseFilter::PathGlob("node_modules".into()),
        NoiseFilter::PathGlob("target/debug".into()),
        NoiseFilter::PathGlob("target/release".into()),
        NoiseFilter::PathGlob(".git/".into()),
        NoiseFilter::CommandSubstring("cd ".into()),
        NoiseFilter::CommandSubstring("ls".into()),
        NoiseFilter::CommandSubstring("pwd".into()),
    ]
}

/// Truncate a string for display.
fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        let end = s
            .char_indices()
            .take_while(|(i, _)| *i < max)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(max);
        &s[..end]
    }
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{AlertSeverity, OutputStream};
    use chrono::Utc;

    fn setup() -> (Arc<ActivityManager>, ActivityCollector, Uuid) {
        let mgr = Arc::new(ActivityManager::new("dev-test", "agent-test", "admin"));
        let session = mgr.start_session("agent-test", "test-project");
        let collector = ActivityCollector::new(Arc::clone(&mgr), "test-project");
        (mgr, collector, session.id)
    }

    #[test]
    fn test_command_started_event() {
        let (mgr, collector, sid) = setup();
        let event = AgentEvent::CommandStarted {
            execution_id: "exec-1".into(),
            command: "cargo test".into(),
            peer_id: "peer-1".into(),
            timestamp: Utc::now(),
        };
        let result = collector.process_event(&event, sid);
        assert!(result.is_some());
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_command_completed_event() {
        let (mgr, collector, sid) = setup();
        let event = AgentEvent::CommandCompleted {
            execution_id: "exec-1".into(),
            success: true,
            exit_code: Some(0),
            duration_ms: 1200,
        };
        let result = collector.process_event(&event, sid);
        assert!(result.is_some());
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_failed_command_higher_importance() {
        let (mgr, collector, sid) = setup();
        let event = AgentEvent::CommandCompleted {
            execution_id: "exec-1".into(),
            success: false,
            exit_code: Some(1),
            duration_ms: 500,
        };
        collector.process_event(&event, sid);
        let entries = mgr.recent(1);
        assert_eq!(entries[0].importance, 2);
    }

    #[test]
    fn test_chat_message_event() {
        let (mgr, collector, sid) = setup();
        let event = AgentEvent::ChatMessage {
            peer_id: "peer-1".into(),
            role: "user".into(),
            content: "Hello agent".into(),
        };
        let result = collector.process_event(&event, sid);
        assert!(result.is_some());
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_peer_connected_event() {
        let (mgr, collector, sid) = setup();
        let event = AgentEvent::PeerConnected {
            peer_id: "p1".into(),
            device_name: "iPhone".into(),
            address: "10.0.0.1".into(),
        };
        let result = collector.process_event(&event, sid);
        assert!(result.is_some());
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_peer_disconnected_event() {
        let (mgr, collector, sid) = setup();
        let event = AgentEvent::PeerDisconnected {
            peer_id: "p1".into(),
            reason: "timeout".into(),
        };
        let result = collector.process_event(&event, sid);
        assert!(result.is_some());
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_alert_event_critical() {
        let (mgr, collector, sid) = setup();
        let event = AgentEvent::Alert {
            severity: AlertSeverity::Critical,
            message: "disk full".into(),
            source: "monitor".into(),
        };
        collector.process_event(&event, sid);
        let entries = mgr.recent(1);
        assert_eq!(entries[0].importance, 3);
    }

    #[test]
    fn test_heartbeat_filtered() {
        let (_mgr, collector, sid) = setup();
        let event = AgentEvent::Heartbeat { uptime_secs: 42 };
        let result = collector.process_event(&event, sid);
        assert!(result.is_none());
    }

    #[test]
    fn test_metric_update_filtered() {
        let (_mgr, collector, sid) = setup();
        let event = AgentEvent::MetricUpdate {
            cpu_percent: 50.0,
            memory_percent: 60.0,
            active_connections: 3,
            active_executions: 1,
        };
        let result = collector.process_event(&event, sid);
        assert!(result.is_none());
    }

    #[test]
    fn test_command_output_filtered() {
        let (_mgr, collector, sid) = setup();
        let event = AgentEvent::CommandOutput {
            execution_id: "e1".into(),
            stream: OutputStream::Stdout,
            data: "output".into(),
        };
        let result = collector.process_event(&event, sid);
        assert!(result.is_none());
    }

    #[test]
    fn test_noise_filter_path_glob() {
        let (mgr, mut collector, sid) = setup();
        collector.add_filter(NoiseFilter::PathGlob("node_modules".into()));

        // This event doesn't have file_path so glob won't trigger
        let event = AgentEvent::CommandStarted {
            execution_id: "exec-1".into(),
            command: "cargo build".into(),
            peer_id: "peer-1".into(),
            timestamp: Utc::now(),
        };
        let result = collector.process_event(&event, sid);
        assert!(result.is_some());
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_noise_filter_command_substring() {
        let (_mgr, collector, sid) = setup();

        // "ls" should be filtered by default
        let event = AgentEvent::CommandStarted {
            execution_id: "exec-1".into(),
            command: "ls -la".into(),
            peer_id: "peer-1".into(),
            timestamp: Utc::now(),
        };
        let result = collector.process_event(&event, sid);
        assert!(result.is_none(), "ls should be filtered");
    }

    #[test]
    fn test_custom_filter() {
        let (_mgr, mut collector, sid) = setup();
        collector.add_filter(NoiseFilter::MinImportance(2));

        // Importance 1 should be filtered
        let event = AgentEvent::CommandCompleted {
            execution_id: "exec-1".into(),
            success: true,
            exit_code: Some(0),
            duration_ms: 10,
        };
        let result = collector.process_event(&event, sid);
        assert!(result.is_none(), "importance 1 should be below threshold 2");
    }

    #[test]
    fn test_audit_entry_event() {
        let (mgr, collector, sid) = setup();
        let event = AgentEvent::AuditEntry {
            sequence: 42,
            actor: "admin".into(),
            capability: "shell_exec".into(),
            result: "success".into(),
        };
        let result = collector.process_event(&event, sid);
        assert!(result.is_some());
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_set_project() {
        let (mgr, mut collector, sid) = setup();
        collector.set_project("new-project");
        let event = AgentEvent::CommandCompleted {
            execution_id: "exec-1".into(),
            success: true,
            exit_code: Some(0),
            duration_ms: 100,
        };
        collector.process_event(&event, sid);
        let entries = mgr.recent(1);
        assert_eq!(entries[0].project, "new-project");
    }

    #[test]
    fn test_truncate_long_content() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5), "hello");
        assert_eq!(truncate("", 5), "");
    }

    #[test]
    fn test_noise_filter_should_filter() {
        let path_filter = NoiseFilter::PathGlob("node_modules".into());
        assert!(path_filter.should_filter(Some("src/node_modules/x.js"), None, 1));
        assert!(!path_filter.should_filter(Some("src/main.rs"), None, 1));
        assert!(!path_filter.should_filter(None, None, 1));

        let cmd_filter = NoiseFilter::CommandSubstring("pwd".into());
        assert!(cmd_filter.should_filter(None, Some("pwd"), 1));
        assert!(!cmd_filter.should_filter(None, Some("cargo build"), 1));

        let imp_filter = NoiseFilter::MinImportance(2);
        assert!(imp_filter.should_filter(None, None, 1));
        assert!(!imp_filter.should_filter(None, None, 2));
        assert!(!imp_filter.should_filter(None, None, 3));
    }

    #[test]
    fn test_status_change_filtered() {
        let (_mgr, collector, sid) = setup();
        let event = AgentEvent::StatusChange {
            previous: "offline".into(),
            current: "online".into(),
            reason: "startup".into(),
        };
        let result = collector.process_event(&event, sid);
        assert!(result.is_none());
    }
}

//! P2P team activity synchronization over ECNP.
//!
//! Replaces Tower's central Express server with peer-to-peer mesh sync.
//! Activities are broadcast to all connected peers using ECNP binary
//! framing, with RBAC filtering and CRDT merge for offline support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::activity_log::{ActivityEntry, AgentSession, ContextInjection};
use crate::error::AgentError;

// ─── Sync Message Types ───────────────────────────────────

/// ECNP sub-type codes for activity sync (0x20–0x26 range).
pub const ACTIVITY_BROADCAST: u8 = 0x20;
pub const SESSION_SUMMARY: u8 = 0x21;
pub const LOG_QUERY: u8 = 0x22;
pub const LOG_RESPONSE: u8 = 0x23;
pub const CONTEXT_REQUEST: u8 = 0x24;
pub const CONTEXT_RESPONSE: u8 = 0x25;
pub const ACTIVITY_ACK: u8 = 0x26;

/// Messages exchanged between peers for activity synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TeamSyncMessage {
    /// Broadcast one or more activity entries to peers.
    #[serde(rename = "activity_broadcast")]
    ActivityBroadcast { entries: Vec<ActivityEntry> },

    /// Share a completed session summary.
    #[serde(rename = "session_summary")]
    SessionSummary { session: AgentSession },

    /// Query a peer's activity log.
    #[serde(rename = "log_query")]
    LogQuery {
        query_id: Uuid,
        query_text: String,
        since: Option<DateTime<Utc>>,
        max_results: u16,
        project: Option<String>,
        min_importance: Option<u8>,
    },

    /// Response to a log query.
    #[serde(rename = "log_response")]
    LogResponse {
        query_id: Uuid,
        total_count: u32,
        entries: Vec<ActivityEntry>,
    },

    /// Request context injection data (session-start equivalent).
    #[serde(rename = "context_request")]
    ContextRequest { project: String, session_id: Uuid },

    /// Response with context injection payload.
    #[serde(rename = "context_response")]
    ContextResponse {
        session_id: Uuid,
        context: ContextInjection,
    },

    /// Acknowledge receipt of activity entries.
    #[serde(rename = "activity_ack")]
    ActivityAck {
        entry_ids: Vec<Uuid>,
        received_by: String,
    },
}

impl TeamSyncMessage {
    /// Serialize to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, AgentError> {
        serde_json::to_vec(self).map_err(AgentError::from)
    }

    /// Deserialize from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, AgentError> {
        serde_json::from_slice(data).map_err(AgentError::from)
    }

    /// ECNP sub-type code for this message.
    pub fn sync_type_code(&self) -> u8 {
        match self {
            TeamSyncMessage::ActivityBroadcast { .. } => ACTIVITY_BROADCAST,
            TeamSyncMessage::SessionSummary { .. } => SESSION_SUMMARY,
            TeamSyncMessage::LogQuery { .. } => LOG_QUERY,
            TeamSyncMessage::LogResponse { .. } => LOG_RESPONSE,
            TeamSyncMessage::ContextRequest { .. } => CONTEXT_REQUEST,
            TeamSyncMessage::ContextResponse { .. } => CONTEXT_RESPONSE,
            TeamSyncMessage::ActivityAck { .. } => ACTIVITY_ACK,
        }
    }

    /// Human-readable message kind.
    pub fn kind(&self) -> &'static str {
        match self {
            TeamSyncMessage::ActivityBroadcast { .. } => "activity_broadcast",
            TeamSyncMessage::SessionSummary { .. } => "session_summary",
            TeamSyncMessage::LogQuery { .. } => "log_query",
            TeamSyncMessage::LogResponse { .. } => "log_response",
            TeamSyncMessage::ContextRequest { .. } => "context_request",
            TeamSyncMessage::ContextResponse { .. } => "context_response",
            TeamSyncMessage::ActivityAck { .. } => "activity_ack",
        }
    }
}

// ─── RBAC Filter ──────────────────────────────────────────

/// Filter activity entries based on the requester's RBAC role.
///
/// | Role     | Access                            |
/// |----------|-----------------------------------|
/// | Owner    | All entries                       |
/// | Admin    | All entries                       |
/// | Operator | Same project only                 |
/// | Viewer   | Summaries only (importance ≥ 2)   |
/// | Guest    | None                              |
pub fn filter_for_role(
    entries: &[ActivityEntry],
    role: &str,
    requester_project: Option<&str>,
) -> Vec<ActivityEntry> {
    match role {
        "owner" | "admin" => entries.to_vec(),
        "operator" => {
            if let Some(proj) = requester_project {
                entries
                    .iter()
                    .filter(|e| e.project.eq_ignore_ascii_case(proj))
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            }
        }
        "viewer" => entries
            .iter()
            .filter(|e| e.importance >= 2)
            .cloned()
            .collect(),
        _ => Vec::new(), // guest or unknown
    }
}

// ─── Sync Codec Helpers ───────────────────────────────────

/// Check if an ECNP message type byte is an activity sync message.
pub fn is_activity_sync_type(msg_type: u8) -> bool {
    (ACTIVITY_BROADCAST..=ACTIVITY_ACK).contains(&msg_type)
}

/// Get description of an activity sync message type.
pub fn sync_type_name(msg_type: u8) -> &'static str {
    match msg_type {
        ACTIVITY_BROADCAST => "ActivityBroadcast",
        SESSION_SUMMARY => "SessionSummary",
        LOG_QUERY => "LogQuery",
        LOG_RESPONSE => "LogResponse",
        CONTEXT_REQUEST => "ContextRequest",
        CONTEXT_RESPONSE => "ContextResponse",
        ACTIVITY_ACK => "ActivityAck",
        _ => "Unknown",
    }
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity_log::{ActivityBrief, ActivityType, SessionStatus, SessionSummaryBrief};

    fn sample_entry(project: &str, importance: u8) -> ActivityEntry {
        ActivityEntry {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            agent_id: "dev-1".into(),
            agent_role: "admin".into(),
            agent_name: "agent-1".into(),
            activity_type: ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 5,
            },
            project: project.into(),
            file_path: Some("src/main.rs".into()),
            content: "edited file".into(),
            tags: vec!["rust".into()],
            importance,
            timestamp: Utc::now(),
            lamport_clock: 1,
            prev_hash: "0".repeat(64),
            hash: "abc123".into(),
        }
    }

    fn sample_session() -> AgentSession {
        AgentSession {
            id: Uuid::new_v4(),
            agent_id: "dev-1".into(),
            agent_name: "agent-1".into(),
            project: "edgeclaw".into(),
            started_at: Utc::now(),
            ended_at: Some(Utc::now()),
            status: SessionStatus::Completed,
            total_input_tokens: 500,
            total_output_tokens: 1000,
            total_cost_usd: 0.05,
            turns: 10,
            files_modified: vec!["main.rs".into()],
            commands_executed: 5,
            error_count: 1,
            summary: Some("Implemented feature X".into()),
            decisions: vec!["Use Rust".into()],
            context_for_next: Some("Continue with tests".into()),
        }
    }

    // ─── Serialization ─────────────────────────────────

    #[test]
    fn test_activity_broadcast_roundtrip() {
        let msg = TeamSyncMessage::ActivityBroadcast {
            entries: vec![sample_entry("edgeclaw", 1)],
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = TeamSyncMessage::from_bytes(&bytes).unwrap();
        match decoded {
            TeamSyncMessage::ActivityBroadcast { entries } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].project, "edgeclaw");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_session_summary_roundtrip() {
        let msg = TeamSyncMessage::SessionSummary {
            session: sample_session(),
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = TeamSyncMessage::from_bytes(&bytes).unwrap();
        match decoded {
            TeamSyncMessage::SessionSummary { session } => {
                assert_eq!(session.agent_name, "agent-1");
                assert_eq!(session.turns, 10);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_log_query_roundtrip() {
        let qid = Uuid::new_v4();
        let msg = TeamSyncMessage::LogQuery {
            query_id: qid,
            query_text: "JWT auth".into(),
            since: Some(Utc::now()),
            max_results: 50,
            project: Some("backend".into()),
            min_importance: Some(2),
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = TeamSyncMessage::from_bytes(&bytes).unwrap();
        match decoded {
            TeamSyncMessage::LogQuery {
                query_id,
                query_text,
                max_results,
                ..
            } => {
                assert_eq!(query_id, qid);
                assert_eq!(query_text, "JWT auth");
                assert_eq!(max_results, 50);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_log_response_roundtrip() {
        let qid = Uuid::new_v4();
        let msg = TeamSyncMessage::LogResponse {
            query_id: qid,
            total_count: 1,
            entries: vec![sample_entry("backend", 2)],
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = TeamSyncMessage::from_bytes(&bytes).unwrap();
        match decoded {
            TeamSyncMessage::LogResponse {
                query_id,
                total_count,
                entries,
            } => {
                assert_eq!(query_id, qid);
                assert_eq!(total_count, 1);
                assert_eq!(entries.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_context_request_roundtrip() {
        let sid = Uuid::new_v4();
        let msg = TeamSyncMessage::ContextRequest {
            project: "edgeclaw".into(),
            session_id: sid,
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = TeamSyncMessage::from_bytes(&bytes).unwrap();
        match decoded {
            TeamSyncMessage::ContextRequest {
                project,
                session_id,
            } => {
                assert_eq!(project, "edgeclaw");
                assert_eq!(session_id, sid);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_context_response_roundtrip() {
        let sid = Uuid::new_v4();
        let ctx = ContextInjection {
            recent_summaries: vec![SessionSummaryBrief {
                session_id: Uuid::new_v4(),
                agent_name: "a".into(),
                started_at: Utc::now(),
                summary: "did stuff".into(),
                files_modified: vec!["main.rs".into()],
            }],
            important_activities: vec![ActivityBrief {
                id: Uuid::new_v4(),
                activity_type: "decision".into(),
                content: "chose Rust".into(),
                timestamp: Utc::now(),
                importance: 2,
            }],
            recent_errors: vec![],
            active_decisions: vec![],
        };
        let msg = TeamSyncMessage::ContextResponse {
            session_id: sid,
            context: ctx,
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = TeamSyncMessage::from_bytes(&bytes).unwrap();
        match decoded {
            TeamSyncMessage::ContextResponse {
                session_id,
                context,
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(context.recent_summaries.len(), 1);
                assert_eq!(context.important_activities.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_activity_ack_roundtrip() {
        let ids = vec![Uuid::new_v4(), Uuid::new_v4()];
        let msg = TeamSyncMessage::ActivityAck {
            entry_ids: ids.clone(),
            received_by: "dev-2".into(),
        };
        let bytes = msg.to_bytes().unwrap();
        let decoded = TeamSyncMessage::from_bytes(&bytes).unwrap();
        match decoded {
            TeamSyncMessage::ActivityAck {
                entry_ids,
                received_by,
            } => {
                assert_eq!(entry_ids.len(), 2);
                assert_eq!(received_by, "dev-2");
            }
            _ => panic!("wrong variant"),
        }
    }

    // ─── Type codes ────────────────────────────────────

    #[test]
    fn test_sync_type_codes() {
        assert_eq!(
            TeamSyncMessage::ActivityBroadcast { entries: vec![] }.sync_type_code(),
            0x20
        );
        assert_eq!(
            TeamSyncMessage::SessionSummary {
                session: sample_session()
            }
            .sync_type_code(),
            0x21
        );
        assert_eq!(
            TeamSyncMessage::LogQuery {
                query_id: Uuid::new_v4(),
                query_text: String::new(),
                since: None,
                max_results: 10,
                project: None,
                min_importance: None,
            }
            .sync_type_code(),
            0x22
        );
        assert_eq!(
            TeamSyncMessage::LogResponse {
                query_id: Uuid::new_v4(),
                total_count: 0,
                entries: vec![],
            }
            .sync_type_code(),
            0x23
        );
        assert_eq!(
            TeamSyncMessage::ContextRequest {
                project: String::new(),
                session_id: Uuid::new_v4(),
            }
            .sync_type_code(),
            0x24
        );
        assert_eq!(
            TeamSyncMessage::ContextResponse {
                session_id: Uuid::new_v4(),
                context: ContextInjection {
                    recent_summaries: vec![],
                    important_activities: vec![],
                    recent_errors: vec![],
                    active_decisions: vec![],
                },
            }
            .sync_type_code(),
            0x25
        );
        assert_eq!(
            TeamSyncMessage::ActivityAck {
                entry_ids: vec![],
                received_by: String::new(),
            }
            .sync_type_code(),
            0x26
        );
    }

    #[test]
    fn test_kind_names() {
        let msg = TeamSyncMessage::ActivityBroadcast { entries: vec![] };
        assert_eq!(msg.kind(), "activity_broadcast");
    }

    // ─── RBAC Filtering ────────────────────────────────

    #[test]
    fn test_filter_owner_sees_all() {
        let entries = vec![
            sample_entry("proj-a", 1),
            sample_entry("proj-b", 1),
            sample_entry("proj-a", 3),
        ];
        let filtered = filter_for_role(&entries, "owner", None);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn test_filter_admin_sees_all() {
        let entries = vec![sample_entry("proj-a", 1), sample_entry("proj-b", 2)];
        let filtered = filter_for_role(&entries, "admin", None);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_operator_same_project() {
        let entries = vec![
            sample_entry("proj-a", 1),
            sample_entry("proj-b", 1),
            sample_entry("proj-a", 2),
        ];
        let filtered = filter_for_role(&entries, "operator", Some("proj-a"));
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|e| e.project == "proj-a"));
    }

    #[test]
    fn test_filter_operator_no_project() {
        let entries = vec![sample_entry("proj-a", 1)];
        let filtered = filter_for_role(&entries, "operator", None);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_viewer_important_only() {
        let entries = vec![
            sample_entry("proj-a", 0),
            sample_entry("proj-a", 1),
            sample_entry("proj-a", 2),
            sample_entry("proj-a", 3),
        ];
        let filtered = filter_for_role(&entries, "viewer", None);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|e| e.importance >= 2));
    }

    #[test]
    fn test_filter_guest_sees_nothing() {
        let entries = vec![sample_entry("proj-a", 3)];
        let filtered = filter_for_role(&entries, "guest", None);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_unknown_role_sees_nothing() {
        let entries = vec![sample_entry("proj-a", 3)];
        let filtered = filter_for_role(&entries, "hacker", None);
        assert!(filtered.is_empty());
    }

    // ─── Helpers ───────────────────────────────────────

    #[test]
    fn test_is_activity_sync_type() {
        assert!(is_activity_sync_type(0x20));
        assert!(is_activity_sync_type(0x23));
        assert!(is_activity_sync_type(0x26));
        assert!(!is_activity_sync_type(0x01));
        assert!(!is_activity_sync_type(0x27));
        assert!(!is_activity_sync_type(0xFF));
    }

    #[test]
    fn test_sync_type_name() {
        assert_eq!(sync_type_name(0x20), "ActivityBroadcast");
        assert_eq!(sync_type_name(0x21), "SessionSummary");
        assert_eq!(sync_type_name(0x22), "LogQuery");
        assert_eq!(sync_type_name(0x23), "LogResponse");
        assert_eq!(sync_type_name(0x24), "ContextRequest");
        assert_eq!(sync_type_name(0x25), "ContextResponse");
        assert_eq!(sync_type_name(0x26), "ActivityAck");
        assert_eq!(sync_type_name(0xFF), "Unknown");
    }

    #[test]
    fn test_empty_broadcast() {
        let msg = TeamSyncMessage::ActivityBroadcast { entries: vec![] };
        let bytes = msg.to_bytes().unwrap();
        let decoded = TeamSyncMessage::from_bytes(&bytes).unwrap();
        match decoded {
            TeamSyncMessage::ActivityBroadcast { entries } => {
                assert!(entries.is_empty());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_invalid_json_returns_error() {
        let result = TeamSyncMessage::from_bytes(b"not json");
        assert!(result.is_err());
    }
}

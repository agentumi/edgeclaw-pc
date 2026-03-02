//! CBOR binary encoding for P2P activity sync payloads.
//!
//! Provides efficient binary serialization using CBOR (RFC 8949) for
//! [`TeamSyncMessage`] and [`ActivityEntry`] payloads, reducing bandwidth
//! by ~40% compared to JSON while maintaining compatibility with legacy peers.

use serde::{de::DeserializeOwned, Serialize};
use std::io::Cursor;
use tracing::warn;

use crate::activity_log::{ActivityEntry, AgentSession};
use crate::error::AgentError;
use crate::team_sync::TeamSyncMessage;

/// Encoding format flag embedded in ECNP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadEncoding {
    /// Legacy JSON encoding (compatible with V3.0 peers)
    Json = 0,
    /// CBOR binary encoding (V4.0+)
    Cbor = 1,
}

impl PayloadEncoding {
    /// Parse from a byte flag.
    pub fn from_byte(b: u8) -> Self {
        match b {
            1 => PayloadEncoding::Cbor,
            _ => PayloadEncoding::Json,
        }
    }

    /// Convert to byte flag.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

// ─── Generic CBOR Utilities ───────────────────────────────

/// Encode any serializable value to CBOR bytes.
pub fn encode_cbor<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, AgentError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| AgentError::SerializationError(format!("CBOR encode error: {}", e)))?;
    Ok(buf)
}

/// Decode CBOR bytes to a deserializable value.
pub fn decode_cbor<T: DeserializeOwned>(data: &[u8]) -> Result<T, AgentError> {
    ciborium::from_reader(Cursor::new(data))
        .map_err(|e| AgentError::SerializationError(format!("CBOR decode error: {}", e)))
}

// ─── TeamSyncMessage CBOR ─────────────────────────────────

impl TeamSyncMessage {
    /// Serialize to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, AgentError> {
        encode_cbor(self)
    }

    /// Deserialize from CBOR bytes.
    pub fn from_cbor(data: &[u8]) -> Result<Self, AgentError> {
        decode_cbor(data)
    }

    /// Serialize using the specified encoding.
    pub fn encode(&self, encoding: PayloadEncoding) -> Result<Vec<u8>, AgentError> {
        match encoding {
            PayloadEncoding::Json => self.to_bytes(),
            PayloadEncoding::Cbor => self.to_cbor(),
        }
    }

    /// Deserialize using the specified encoding.
    pub fn decode(data: &[u8], encoding: PayloadEncoding) -> Result<Self, AgentError> {
        match encoding {
            PayloadEncoding::Json => Self::from_bytes(data),
            PayloadEncoding::Cbor => Self::from_cbor(data),
        }
    }

    /// Try CBOR first, then fall back to JSON (for backward compatibility).
    pub fn decode_auto(data: &[u8]) -> Result<Self, AgentError> {
        // Try CBOR first
        match Self::from_cbor(data) {
            Ok(msg) => Ok(msg),
            Err(_) => {
                // Fall back to JSON
                warn!("CBOR decode failed, falling back to JSON");
                Self::from_bytes(data)
            }
        }
    }
}

// ─── ActivityEntry CBOR ───────────────────────────────────

/// Encode a single activity entry to CBOR.
pub fn encode_activity_cbor(entry: &ActivityEntry) -> Result<Vec<u8>, AgentError> {
    encode_cbor(entry)
}

/// Decode a single activity entry from CBOR.
pub fn decode_activity_cbor(data: &[u8]) -> Result<ActivityEntry, AgentError> {
    decode_cbor(data)
}

/// Encode multiple activity entries to CBOR.
pub fn encode_activities_cbor(entries: &[ActivityEntry]) -> Result<Vec<u8>, AgentError> {
    encode_cbor(entries)
}

/// Decode multiple activity entries from CBOR.
pub fn decode_activities_cbor(data: &[u8]) -> Result<Vec<ActivityEntry>, AgentError> {
    decode_cbor(data)
}

/// Encode an agent session to CBOR.
pub fn encode_session_cbor(session: &AgentSession) -> Result<Vec<u8>, AgentError> {
    encode_cbor(session)
}

/// Decode an agent session from CBOR.
pub fn decode_session_cbor(data: &[u8]) -> Result<AgentSession, AgentError> {
    decode_cbor(data)
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity_log::{
        ActivityBrief, ActivityType, ContextInjection, SessionStatus, SessionSummaryBrief,
    };
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_entry() -> ActivityEntry {
        ActivityEntry {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            agent_id: "dev-1".into(),
            agent_role: "admin".into(),
            agent_name: "agent-1".into(),
            activity_type: ActivityType::FileEdit {
                before_snippet: Some("old".into()),
                after_snippet: Some("new".into()),
                lines_changed: 10,
            },
            project: "edgeclaw".into(),
            file_path: Some("src/main.rs".into()),
            content: "Fixed authentication bug".into(),
            tags: vec!["rust".into(), "security".into()],
            importance: 2,
            timestamp: Utc::now(),
            lamport_clock: 42,
            prev_hash: "0".repeat(64),
            hash: "abc123def456".into(),
            signature: String::new(),
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
            total_input_tokens: 1000,
            total_output_tokens: 2000,
            total_cost_usd: 0.10,
            turns: 15,
            files_modified: vec!["main.rs".into(), "lib.rs".into()],
            commands_executed: 8,
            error_count: 2,
            summary: Some("Completed feature".into()),
            decisions: vec!["Use CBOR".into()],
            context_for_next: Some("Next: tests".into()),
        }
    }

    #[test]
    fn test_cbor_activity_entry_roundtrip() {
        let entry = sample_entry();
        let cbor = encode_activity_cbor(&entry).unwrap();
        let decoded: ActivityEntry = decode_activity_cbor(&cbor).unwrap();
        assert_eq!(decoded.id, entry.id);
        assert_eq!(decoded.content, entry.content);
        assert_eq!(decoded.importance, entry.importance);
        assert_eq!(decoded.lamport_clock, entry.lamport_clock);
    }

    #[test]
    fn test_cbor_session_roundtrip() {
        let session = sample_session();
        let cbor = encode_session_cbor(&session).unwrap();
        let decoded: AgentSession = decode_session_cbor(&cbor).unwrap();
        assert_eq!(decoded.id, session.id);
        assert_eq!(decoded.agent_name, session.agent_name);
        assert_eq!(decoded.turns, session.turns);
        assert_eq!(decoded.total_cost_usd, session.total_cost_usd);
    }

    #[test]
    fn test_cbor_team_sync_broadcast_roundtrip() {
        let msg = TeamSyncMessage::ActivityBroadcast {
            entries: vec![sample_entry(), sample_entry()],
        };
        let cbor = msg.to_cbor().unwrap();
        let decoded = TeamSyncMessage::from_cbor(&cbor).unwrap();
        match decoded {
            TeamSyncMessage::ActivityBroadcast { entries } => {
                assert_eq!(entries.len(), 2);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_cbor_team_sync_session_summary_roundtrip() {
        let msg = TeamSyncMessage::SessionSummary {
            session: sample_session(),
        };
        let cbor = msg.to_cbor().unwrap();
        let decoded = TeamSyncMessage::from_cbor(&cbor).unwrap();
        match decoded {
            TeamSyncMessage::SessionSummary { session } => {
                assert_eq!(session.turns, 15);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_cbor_team_sync_log_query_roundtrip() {
        let qid = Uuid::new_v4();
        let msg = TeamSyncMessage::LogQuery {
            query_id: qid,
            query_text: "search term".into(),
            since: Some(Utc::now()),
            max_results: 25,
            project: Some("edgeclaw".into()),
            min_importance: Some(2),
        };
        let cbor = msg.to_cbor().unwrap();
        let decoded = TeamSyncMessage::from_cbor(&cbor).unwrap();
        match decoded {
            TeamSyncMessage::LogQuery {
                query_id,
                query_text,
                max_results,
                ..
            } => {
                assert_eq!(query_id, qid);
                assert_eq!(query_text, "search term");
                assert_eq!(max_results, 25);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_cbor_team_sync_log_response_roundtrip() {
        let qid = Uuid::new_v4();
        let msg = TeamSyncMessage::LogResponse {
            query_id: qid,
            total_count: 3,
            entries: vec![sample_entry()],
        };
        let cbor = msg.to_cbor().unwrap();
        let decoded = TeamSyncMessage::from_cbor(&cbor).unwrap();
        match decoded {
            TeamSyncMessage::LogResponse {
                query_id,
                total_count,
                entries,
            } => {
                assert_eq!(query_id, qid);
                assert_eq!(total_count, 3);
                assert_eq!(entries.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_cbor_team_sync_context_roundtrip() {
        let sid = Uuid::new_v4();
        let msg = TeamSyncMessage::ContextResponse {
            session_id: sid,
            context: ContextInjection {
                recent_summaries: vec![SessionSummaryBrief {
                    session_id: Uuid::new_v4(),
                    agent_name: "a".into(),
                    started_at: Utc::now(),
                    summary: "summary".into(),
                    files_modified: vec![],
                }],
                important_activities: vec![ActivityBrief {
                    id: Uuid::new_v4(),
                    activity_type: "decision".into(),
                    content: "chose CBOR".into(),
                    timestamp: Utc::now(),
                    importance: 2,
                }],
                recent_errors: vec![],
                active_decisions: vec![],
                memory_md: None,
                repeated_errors: vec![],
                cross_session_insights: vec![],
            },
        };
        let cbor = msg.to_cbor().unwrap();
        let decoded = TeamSyncMessage::from_cbor(&cbor).unwrap();
        match decoded {
            TeamSyncMessage::ContextResponse {
                session_id,
                context,
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(context.recent_summaries.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_cbor_team_sync_ack_roundtrip() {
        let msg = TeamSyncMessage::ActivityAck {
            entry_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            received_by: "dev-2".into(),
        };
        let cbor = msg.to_cbor().unwrap();
        let decoded = TeamSyncMessage::from_cbor(&cbor).unwrap();
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

    #[test]
    fn test_cbor_invalid_data_returns_error() {
        let result = decode_activity_cbor(b"not valid cbor!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_cbor_json_fallback() {
        // Create a JSON-encoded message
        let msg = TeamSyncMessage::ActivityBroadcast {
            entries: vec![sample_entry()],
        };
        let json_bytes = msg.to_bytes().unwrap();

        // decode_auto should fall back to JSON
        let decoded = TeamSyncMessage::decode_auto(&json_bytes).unwrap();
        match decoded {
            TeamSyncMessage::ActivityBroadcast { entries } => {
                assert_eq!(entries.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_cbor_smaller_than_json() {
        let entry = sample_entry();
        let json = serde_json::to_vec(&entry).unwrap();
        let cbor = encode_activity_cbor(&entry).unwrap();
        // CBOR should be smaller (or at least not much larger)
        assert!(
            cbor.len() <= json.len(),
            "CBOR ({}) should be <= JSON ({})",
            cbor.len(),
            json.len()
        );
    }

    #[test]
    fn test_cbor_empty_payload() {
        let msg = TeamSyncMessage::ActivityBroadcast { entries: vec![] };
        let cbor = msg.to_cbor().unwrap();
        let decoded = TeamSyncMessage::from_cbor(&cbor).unwrap();
        match decoded {
            TeamSyncMessage::ActivityBroadcast { entries } => {
                assert!(entries.is_empty());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_cbor_bulk_entries_roundtrip() {
        let entries: Vec<ActivityEntry> = (0..1000).map(|_| sample_entry()).collect();
        let cbor = encode_activities_cbor(&entries).unwrap();
        let decoded = decode_activities_cbor(&cbor).unwrap();
        assert_eq!(decoded.len(), 1000);
    }

    #[test]
    fn test_payload_encoding_from_byte() {
        assert_eq!(PayloadEncoding::from_byte(0), PayloadEncoding::Json);
        assert_eq!(PayloadEncoding::from_byte(1), PayloadEncoding::Cbor);
        assert_eq!(PayloadEncoding::from_byte(99), PayloadEncoding::Json);
    }

    #[test]
    fn test_encode_decode_with_format() {
        let msg = TeamSyncMessage::ActivityBroadcast {
            entries: vec![sample_entry()],
        };

        // JSON path
        let json_bytes = msg.encode(PayloadEncoding::Json).unwrap();
        let decoded_json = TeamSyncMessage::decode(&json_bytes, PayloadEncoding::Json).unwrap();
        assert_eq!(decoded_json.kind(), "activity_broadcast");

        // CBOR path
        let cbor_bytes = msg.encode(PayloadEncoding::Cbor).unwrap();
        let decoded_cbor = TeamSyncMessage::decode(&cbor_bytes, PayloadEncoding::Cbor).unwrap();
        assert_eq!(decoded_cbor.kind(), "activity_broadcast");
    }
}

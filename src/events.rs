//! Event bus for real-time agent event distribution.
//!
//! Provides a broadcast-based [`EventBus`] that distributes [`AgentEvent`] variants
//! to all subscribers (WebSocket clients, loggers, metrics, etc.).
//!
//! # Example
//!
//! ```
//! use edgeclaw_agent::events::{EventBus, AgentEvent};
//!
//! let bus = EventBus::new(256);
//! let mut rx = bus.subscribe();
//! bus.publish(AgentEvent::Heartbeat { uptime_secs: 42 });
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Agent events distributed through the event bus
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum AgentEvent {
    /// Agent status changed (online/offline/degraded)
    StatusChange {
        previous: String,
        current: String,
        reason: String,
    },

    /// Command execution started
    CommandStarted {
        execution_id: String,
        command: String,
        peer_id: String,
        timestamp: DateTime<Utc>,
    },

    /// Incremental command output (streaming stdout/stderr)
    CommandOutput {
        execution_id: String,
        stream: OutputStream,
        data: String,
    },

    /// Command execution completed
    CommandCompleted {
        execution_id: String,
        success: bool,
        exit_code: Option<i32>,
        duration_ms: u64,
    },

    /// New peer connected
    PeerConnected {
        peer_id: String,
        device_name: String,
        address: String,
    },

    /// Peer disconnected
    PeerDisconnected { peer_id: String, reason: String },

    /// Alert / warning
    Alert {
        severity: AlertSeverity,
        message: String,
        source: String,
    },

    /// Periodic heartbeat with system metrics
    Heartbeat { uptime_secs: u64 },

    /// System metric update
    MetricUpdate {
        cpu_percent: f64,
        memory_percent: f64,
        active_connections: u32,
        active_executions: u32,
    },

    /// Audit log entry created
    AuditEntry {
        sequence: u64,
        actor: String,
        capability: String,
        result: String,
    },

    /// AI chat message (for real-time streaming)
    ChatMessage {
        peer_id: String,
        role: String,
        content: String,
    },
}

/// Output stream type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Broadcast-based event bus for distributing agent events
pub struct EventBus {
    sender: broadcast::Sender<AgentEvent>,
}

impl EventBus {
    /// Create a new event bus with the given channel capacity
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publish an event to all subscribers
    pub fn publish(&self, event: AgentEvent) {
        // Ignore error if no subscribers
        let _ = self.sender.send(event);
    }

    /// Subscribe to the event stream
    pub fn subscribe(&self) -> broadcast::Receiver<AgentEvent> {
        self.sender.subscribe()
    }

    /// Get the number of active subscribers
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_bus_create() {
        let bus = EventBus::new(64);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn test_publish_subscribe() {
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);

        bus.publish(AgentEvent::Heartbeat { uptime_secs: 42 });

        let event = rx.recv().await.unwrap();
        match event {
            AgentEvent::Heartbeat { uptime_secs } => assert_eq!(uptime_secs, 42),
            _ => panic!("unexpected event type"),
        }
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let bus = EventBus::new(64);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);

        bus.publish(AgentEvent::StatusChange {
            previous: "offline".into(),
            current: "online".into(),
            reason: "startup".into(),
        });

        // Both subscribers receive the event
        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();

        match (e1, e2) {
            (
                AgentEvent::StatusChange { current: c1, .. },
                AgentEvent::StatusChange { current: c2, .. },
            ) => {
                assert_eq!(c1, "online");
                assert_eq!(c2, "online");
            }
            _ => panic!("unexpected event types"),
        }
    }

    #[test]
    fn test_publish_no_subscribers() {
        // Should not panic when no subscribers
        let bus = EventBus::new(64);
        bus.publish(AgentEvent::Heartbeat { uptime_secs: 1 });
    }

    #[tokio::test]
    async fn test_command_lifecycle_events() {
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();

        bus.publish(AgentEvent::CommandStarted {
            execution_id: "exec-1".into(),
            command: "echo test".into(),
            peer_id: "peer-1".into(),
            timestamp: Utc::now(),
        });

        bus.publish(AgentEvent::CommandOutput {
            execution_id: "exec-1".into(),
            stream: OutputStream::Stdout,
            data: "test\n".into(),
        });

        bus.publish(AgentEvent::CommandCompleted {
            execution_id: "exec-1".into(),
            success: true,
            exit_code: Some(0),
            duration_ms: 50,
        });

        let started = rx.recv().await.unwrap();
        let output = rx.recv().await.unwrap();
        let completed = rx.recv().await.unwrap();

        assert!(matches!(started, AgentEvent::CommandStarted { .. }));
        assert!(matches!(output, AgentEvent::CommandOutput { .. }));
        assert!(matches!(completed, AgentEvent::CommandCompleted { .. }));
    }

    #[tokio::test]
    async fn test_alert_event() {
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();

        bus.publish(AgentEvent::Alert {
            severity: AlertSeverity::Warning,
            message: "disk usage 91%".into(),
            source: "system_monitor".into(),
        });

        match rx.recv().await.unwrap() {
            AgentEvent::Alert {
                severity, message, ..
            } => {
                assert_eq!(severity, AlertSeverity::Warning);
                assert!(message.contains("disk"));
            }
            _ => panic!("expected alert"),
        }
    }

    #[tokio::test]
    async fn test_metric_update_event() {
        let bus = EventBus::new(64);
        let mut rx = bus.subscribe();

        bus.publish(AgentEvent::MetricUpdate {
            cpu_percent: 45.2,
            memory_percent: 62.8,
            active_connections: 3,
            active_executions: 1,
        });

        match rx.recv().await.unwrap() {
            AgentEvent::MetricUpdate {
                cpu_percent,
                memory_percent,
                ..
            } => {
                assert!((cpu_percent - 45.2).abs() < f64::EPSILON);
                assert!((memory_percent - 62.8).abs() < f64::EPSILON);
            }
            _ => panic!("expected metric update"),
        }
    }

    #[test]
    fn test_default_event_bus() {
        let bus = EventBus::default();
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn test_event_serialization() {
        let event = AgentEvent::Heartbeat { uptime_secs: 100 };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("Heartbeat"));
        assert!(json.contains("100"));

        let deserialized: AgentEvent = serde_json::from_str(&json).unwrap();
        match deserialized {
            AgentEvent::Heartbeat { uptime_secs } => assert_eq!(uptime_secs, 100),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_all_event_variants_serialize() {
        // Ensure all variants can serialize/deserialize
        let events = vec![
            AgentEvent::StatusChange {
                previous: "a".into(),
                current: "b".into(),
                reason: "c".into(),
            },
            AgentEvent::CommandStarted {
                execution_id: "e".into(),
                command: "cmd".into(),
                peer_id: "p".into(),
                timestamp: Utc::now(),
            },
            AgentEvent::CommandOutput {
                execution_id: "e".into(),
                stream: OutputStream::Stderr,
                data: "err".into(),
            },
            AgentEvent::CommandCompleted {
                execution_id: "e".into(),
                success: false,
                exit_code: Some(1),
                duration_ms: 100,
            },
            AgentEvent::PeerConnected {
                peer_id: "p".into(),
                device_name: "d".into(),
                address: "a".into(),
            },
            AgentEvent::PeerDisconnected {
                peer_id: "p".into(),
                reason: "r".into(),
            },
            AgentEvent::Alert {
                severity: AlertSeverity::Critical,
                message: "m".into(),
                source: "s".into(),
            },
            AgentEvent::Heartbeat { uptime_secs: 0 },
            AgentEvent::MetricUpdate {
                cpu_percent: 0.0,
                memory_percent: 0.0,
                active_connections: 0,
                active_executions: 0,
            },
            AgentEvent::AuditEntry {
                sequence: 1,
                actor: "a".into(),
                capability: "c".into(),
                result: "r".into(),
            },
            AgentEvent::ChatMessage {
                peer_id: "p".into(),
                role: "user".into(),
                content: "hi".into(),
            },
        ];

        for event in events {
            let json = serde_json::to_string(&event).unwrap();
            let _: AgentEvent = serde_json::from_str(&json).unwrap();
        }
    }
}

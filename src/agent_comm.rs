//! # P1-12: Agent-to-Agent Communication
//!
//! Structured inter-agent message passing for fleet coordination.
//! Supports request/response patterns, broadcast, and delegation.
//!
//! ## Message Types
//! - **Query**: Ask another agent for information
//! - **Delegate**: Forward a task to a specialist agent
//! - **Report**: Send task completion results back
//! - **Broadcast**: Announce to all fleet members
//! - **Sync**: Memory/state synchronization

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Type of inter-agent message
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum A2AMessageType {
    /// Request information from another agent
    Query,
    /// Delegate a task to a specialist
    Delegate,
    /// Report results back to requester
    Report,
    /// Broadcast announcement to all agents
    Broadcast,
    /// Synchronize state/memory
    Sync,
    /// Acknowledgement of receipt
    Ack,
}

/// Priority level for inter-agent messages
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MessagePriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Urgent = 3,
}

/// A structured message between agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AMessage {
    /// Unique message identifier
    pub id: String,
    /// Sender agent ID
    pub from: String,
    /// Recipient agent ID (empty for broadcasts)
    pub to: String,
    /// Message type
    pub msg_type: A2AMessageType,
    /// Priority level
    pub priority: MessagePriority,
    /// Message subject/topic
    pub subject: String,
    /// Message body/payload
    pub body: String,
    /// Optional correlation ID (for request/response pairing)
    pub correlation_id: Option<String>,
    /// Domain context
    pub domain: String,
    /// Timestamp
    pub timestamp: String,
    /// Whether this message has been read/processed
    pub processed: bool,
}

/// An agent's communication mailbox
#[derive(Debug, Default)]
pub struct AgentMailbox {
    /// Incoming messages queue
    inbox: VecDeque<A2AMessage>,
    /// Sent messages history
    sent: Vec<A2AMessage>,
    /// Maximum inbox size
    max_inbox: usize,
}

impl AgentMailbox {
    /// Create a new mailbox with default capacity
    pub fn new() -> Self {
        Self {
            inbox: VecDeque::new(),
            sent: Vec::new(),
            max_inbox: 100,
        }
    }

    /// Receive a message into the inbox
    pub fn receive(&mut self, msg: A2AMessage) {
        // Evict oldest if at capacity
        while self.inbox.len() >= self.max_inbox {
            self.inbox.pop_front();
        }
        self.inbox.push_back(msg);
    }

    /// Record a sent message
    pub fn record_sent(&mut self, msg: A2AMessage) {
        self.sent.push(msg);
    }

    /// Get unprocessed messages count
    pub fn unread_count(&self) -> usize {
        self.inbox.iter().filter(|m| !m.processed).count()
    }

    /// Get all pending (unprocessed) messages, sorted by priority
    pub fn pending(&self) -> Vec<&A2AMessage> {
        let mut msgs: Vec<&A2AMessage> = self.inbox.iter().filter(|m| !m.processed).collect();
        msgs.sort_by(|a, b| b.priority.cmp(&a.priority));
        msgs
    }

    /// Mark a message as processed
    pub fn mark_processed(&mut self, msg_id: &str) -> bool {
        if let Some(msg) = self.inbox.iter_mut().find(|m| m.id == msg_id) {
            msg.processed = true;
            true
        } else {
            false
        }
    }

    /// Get inbox size
    pub fn inbox_size(&self) -> usize {
        self.inbox.len()
    }

    /// Get sent count
    pub fn sent_count(&self) -> usize {
        self.sent.len()
    }
}

/// The Agent Communication Hub manages fleet-wide messaging
pub struct CommunicationHub {
    /// Mailboxes per agent
    mailboxes: HashMap<String, AgentMailbox>,
    /// Total messages ever sent
    total_messages: u64,
    /// Registered agent IDs
    registered_agents: Vec<String>,
}

impl Default for CommunicationHub {
    fn default() -> Self {
        Self::new()
    }
}

impl CommunicationHub {
    /// Create a new communication hub
    pub fn new() -> Self {
        Self {
            mailboxes: HashMap::new(),
            total_messages: 0,
            registered_agents: Vec::new(),
        }
    }

    /// Register an agent with the hub
    pub fn register_agent(&mut self, agent_id: &str) {
        if !self.registered_agents.contains(&agent_id.to_string()) {
            self.registered_agents.push(agent_id.to_string());
            self.mailboxes.entry(agent_id.to_string()).or_default();
        }
    }

    /// Send a direct message between agents
    #[allow(clippy::too_many_arguments)]
    pub fn send_message(
        &mut self,
        from: &str,
        to: &str,
        msg_type: A2AMessageType,
        subject: &str,
        body: &str,
        priority: MessagePriority,
        domain: &str,
        correlation_id: Option<String>,
    ) -> Result<A2AMessage, String> {
        self.total_messages += 1;
        let msg = A2AMessage {
            id: format!("msg-{}", self.total_messages),
            from: from.to_string(),
            to: to.to_string(),
            msg_type,
            priority,
            subject: subject.to_string(),
            body: body.to_string(),
            correlation_id,
            domain: domain.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            processed: false,
        };

        // Deliver to recipient
        let mailbox = self.mailboxes.entry(to.to_string()).or_default();
        mailbox.receive(msg.clone());

        // Record in sender's sent list
        let sender_box = self.mailboxes.entry(from.to_string()).or_default();
        sender_box.record_sent(msg.clone());

        Ok(msg)
    }

    /// Broadcast a message to all registered agents (except sender)
    pub fn broadcast(
        &mut self,
        from: &str,
        subject: &str,
        body: &str,
        priority: MessagePriority,
        domain: &str,
    ) -> Vec<A2AMessage> {
        let targets: Vec<String> = self
            .registered_agents
            .iter()
            .filter(|a| a.as_str() != from)
            .cloned()
            .collect();

        let mut sent = Vec::new();
        for target in targets {
            if let Ok(msg) = self.send_message(
                from,
                &target,
                A2AMessageType::Broadcast,
                subject,
                body,
                priority.clone(),
                domain,
                None,
            ) {
                sent.push(msg);
            }
        }
        sent
    }

    /// Delegate a task to the best specialist agent
    pub fn delegate_task(
        &mut self,
        from: &str,
        to: &str,
        task_description: &str,
        domain: &str,
    ) -> Result<A2AMessage, String> {
        self.send_message(
            from,
            to,
            A2AMessageType::Delegate,
            &format!(
                "Task Delegation: {}",
                &task_description[..task_description.len().min(50)]
            ),
            task_description,
            MessagePriority::High,
            domain,
            None,
        )
    }

    /// Send a report (task completion result) back to requester
    pub fn send_report(
        &mut self,
        from: &str,
        to: &str,
        result: &str,
        original_msg_id: &str,
        domain: &str,
    ) -> Result<A2AMessage, String> {
        self.send_message(
            from,
            to,
            A2AMessageType::Report,
            "Task Report",
            result,
            MessagePriority::Normal,
            domain,
            Some(original_msg_id.to_string()),
        )
    }

    /// Get an agent's mailbox
    pub fn mailbox(&self, agent_id: &str) -> Option<&AgentMailbox> {
        self.mailboxes.get(agent_id)
    }

    /// Get a mutable reference to an agent's mailbox
    pub fn mailbox_mut(&mut self, agent_id: &str) -> Option<&mut AgentMailbox> {
        self.mailboxes.get_mut(agent_id)
    }

    /// Communication hub statistics
    pub fn stats(&self) -> CommunicationStats {
        let total_unread: usize = self.mailboxes.values().map(|m| m.unread_count()).sum();
        CommunicationStats {
            registered_agents: self.registered_agents.len(),
            total_messages: self.total_messages,
            total_unread,
        }
    }
}

/// Communication hub statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationStats {
    pub registered_agents: usize,
    pub total_messages: u64,
    pub total_unread: usize,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_message() {
        let mut hub = CommunicationHub::new();
        hub.register_agent("alice");
        hub.register_agent("bob");

        let msg = hub
            .send_message(
                "alice",
                "bob",
                A2AMessageType::Query,
                "Status?",
                "What is your current workload?",
                MessagePriority::Normal,
                "general",
                None,
            )
            .unwrap();

        assert_eq!(msg.from, "alice");
        assert_eq!(msg.to, "bob");

        let bob_box = hub.mailbox("bob").unwrap();
        assert_eq!(bob_box.unread_count(), 1);
    }

    #[test]
    fn test_broadcast() {
        let mut hub = CommunicationHub::new();
        hub.register_agent("leader");
        hub.register_agent("worker-1");
        hub.register_agent("worker-2");

        let msgs = hub.broadcast(
            "leader",
            "New Mission",
            "Starting fleet operation X",
            MessagePriority::High,
            "orchestration",
        );

        assert_eq!(msgs.len(), 2); // 2 recipients (excludes sender)
    }

    #[test]
    fn test_delegate_task() {
        let mut hub = CommunicationHub::new();
        hub.register_agent("manager");
        hub.register_agent("specialist");

        let msg = hub
            .delegate_task(
                "manager",
                "specialist",
                "Analyze Q1 revenue data and generate insights",
                "business",
            )
            .unwrap();

        assert_eq!(msg.msg_type, A2AMessageType::Delegate);
        assert_eq!(msg.priority, MessagePriority::High);
    }

    #[test]
    fn test_report_with_correlation() {
        let mut hub = CommunicationHub::new();
        hub.register_agent("alice");
        hub.register_agent("bob");

        let query = hub
            .send_message(
                "alice",
                "bob",
                A2AMessageType::Query,
                "Need data",
                "Send me the report",
                MessagePriority::Normal,
                "general",
                None,
            )
            .unwrap();

        let report = hub
            .send_report(
                "bob",
                "alice",
                "Here is the report data",
                &query.id,
                "general",
            )
            .unwrap();

        assert_eq!(report.correlation_id.as_deref(), Some(query.id.as_str()));
    }

    #[test]
    fn test_mark_processed() {
        let mut hub = CommunicationHub::new();
        hub.register_agent("alice");
        hub.register_agent("bob");

        let msg = hub
            .send_message(
                "alice",
                "bob",
                A2AMessageType::Query,
                "Test",
                "Body",
                MessagePriority::Normal,
                "general",
                None,
            )
            .unwrap();

        assert_eq!(hub.mailbox("bob").unwrap().unread_count(), 1);
        hub.mailbox_mut("bob").unwrap().mark_processed(&msg.id);
        assert_eq!(hub.mailbox("bob").unwrap().unread_count(), 0);
    }

    #[test]
    fn test_priority_sorting() {
        let mut hub = CommunicationHub::new();
        hub.register_agent("sender");
        hub.register_agent("receiver");

        hub.send_message(
            "sender",
            "receiver",
            A2AMessageType::Query,
            "Low",
            "body",
            MessagePriority::Low,
            "general",
            None,
        )
        .unwrap();
        hub.send_message(
            "sender",
            "receiver",
            A2AMessageType::Query,
            "Urgent",
            "body",
            MessagePriority::Urgent,
            "general",
            None,
        )
        .unwrap();
        hub.send_message(
            "sender",
            "receiver",
            A2AMessageType::Query,
            "Normal",
            "body",
            MessagePriority::Normal,
            "general",
            None,
        )
        .unwrap();

        let pending = hub.mailbox("receiver").unwrap().pending();
        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0].priority, MessagePriority::Urgent);
        assert_eq!(pending[1].priority, MessagePriority::Normal);
        assert_eq!(pending[2].priority, MessagePriority::Low);
    }

    #[test]
    fn test_mailbox_capacity() {
        let mut mailbox = AgentMailbox::new();
        mailbox.max_inbox = 3;

        for i in 0..5 {
            mailbox.receive(A2AMessage {
                id: format!("msg-{}", i),
                from: "sender".to_string(),
                to: "receiver".to_string(),
                msg_type: A2AMessageType::Query,
                priority: MessagePriority::Normal,
                subject: format!("Msg {}", i),
                body: String::new(),
                correlation_id: None,
                domain: "test".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                processed: false,
            });
        }

        assert_eq!(mailbox.inbox_size(), 3); // Only last 3 kept
    }

    #[test]
    fn test_stats() {
        let mut hub = CommunicationHub::new();
        hub.register_agent("a");
        hub.register_agent("b");
        hub.send_message(
            "a",
            "b",
            A2AMessageType::Query,
            "test",
            "body",
            MessagePriority::Normal,
            "general",
            None,
        )
        .unwrap();

        let stats = hub.stats();
        assert_eq!(stats.registered_agents, 2);
        assert_eq!(stats.total_messages, 1);
        assert_eq!(stats.total_unread, 1);
    }
}

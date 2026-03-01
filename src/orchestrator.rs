//! Task orchestrator — workload distribution across multiple agents.
//!
//! Provides [`Orchestrator`] for dispatching tasks to the best-fit agent
//! based on routing strategy (round-robin, profile-based, priority, manual).

use crate::error::AgentError;
use crate::registry::{AgentInfo, AgentRegistry, AgentStatus};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// Routing strategy for task distribution
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub enum RoutingStrategy {
    /// Distribute tasks evenly across all online agents
    RoundRobin,
    /// Route tasks to agents matching the task's required profile
    #[default]
    ProfileBased,
    /// Route to agents based on task priority
    Priority,
    /// Manually specify target agent
    Manual,
}

/// Task priority levels
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TaskPriority {
    Low = 0,
    #[default]
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// A task to be dispatched to an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub command: String,
    pub required_profile: Option<String>,
    pub target_agent: Option<String>,
    pub priority: TaskPriority,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Result of a dispatched task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub agent_id: String,
    pub success: bool,
    pub output: String,
    pub duration_ms: u64,
}

/// Task orchestrator
pub struct Orchestrator {
    registry: Arc<AgentRegistry>,
    strategy: RoutingStrategy,
    local_agent_id: String,
    round_robin_index: Mutex<usize>,
    task_queue: Mutex<VecDeque<Task>>,
}

impl Orchestrator {
    /// Create a new orchestrator
    pub fn new(
        registry: Arc<AgentRegistry>,
        strategy: RoutingStrategy,
        local_agent_id: &str,
    ) -> Self {
        Self {
            registry,
            strategy,
            local_agent_id: local_agent_id.to_string(),
            round_robin_index: Mutex::new(0),
            task_queue: Mutex::new(VecDeque::new()),
        }
    }

    /// Select the best agent for a given task
    pub fn select_agent(&self, task: &Task) -> Result<AgentInfo, AgentError> {
        // Manual routing — user specified a target
        if let Some(ref target) = task.target_agent {
            if let Some(agent) = self.registry.get(target) {
                if agent.status == AgentStatus::Online {
                    return Ok(agent);
                }
                warn!(agent = %target, "target agent is not online, trying fallback");
            }
        }

        let online = self.registry.list_online();
        if online.is_empty() {
            return Err(AgentError::NotFound("no online agents available".into()));
        }

        match self.strategy {
            RoutingStrategy::RoundRobin => self.select_round_robin(&online),
            RoutingStrategy::ProfileBased => self.select_by_profile(task, &online),
            RoutingStrategy::Priority => self.select_by_priority(&online),
            RoutingStrategy::Manual => Err(AgentError::InvalidParameter(
                "no target agent specified for manual routing".into(),
            )),
        }
    }

    /// Round-robin selection
    fn select_round_robin(&self, agents: &[AgentInfo]) -> Result<AgentInfo, AgentError> {
        if agents.is_empty() {
            return Err(AgentError::NotFound("no agents".into()));
        }
        let mut idx = self.round_robin_index.lock().unwrap();
        let agent = agents[*idx % agents.len()].clone();
        *idx = (*idx + 1) % agents.len();
        Ok(agent)
    }

    /// Profile-based selection with fallback
    fn select_by_profile(
        &self,
        task: &Task,
        agents: &[AgentInfo],
    ) -> Result<AgentInfo, AgentError> {
        if let Some(ref profile) = task.required_profile {
            // Find agents matching the required profile
            let matching: Vec<&AgentInfo> = agents
                .iter()
                .filter(|a| a.profile.eq_ignore_ascii_case(profile))
                .collect();

            if !matching.is_empty() {
                return Ok(matching[0].clone());
            }

            // Fallback: any online agent
            warn!(
                profile = %profile,
                "no agents with matching profile, falling back to first available"
            );
        }

        agents
            .first()
            .cloned()
            .ok_or_else(|| AgentError::NotFound("no agents available".into()))
    }

    /// Priority-based: prefer least busy agent
    fn select_by_priority(&self, agents: &[AgentInfo]) -> Result<AgentInfo, AgentError> {
        // Prefer Online agents over Busy
        let mut sorted = agents.to_vec();
        sorted.sort_by(|a, b| {
            let a_score = if a.status == AgentStatus::Online {
                0
            } else {
                1
            };
            let b_score = if b.status == AgentStatus::Online {
                0
            } else {
                1
            };
            a_score.cmp(&b_score)
        });
        sorted
            .first()
            .cloned()
            .ok_or_else(|| AgentError::NotFound("no agents".into()))
    }

    /// Dispatch a task (selects agent and queues for execution)
    pub fn dispatch(&self, task: Task) -> Result<String, AgentError> {
        let agent = self.select_agent(&task)?;
        let agent_id = agent.id.clone();
        let task_id = task.id.clone();

        info!(
            task_id = %task_id,
            agent_id = %agent_id,
            command = %task.command,
            "dispatching task"
        );

        if let Ok(mut queue) = self.task_queue.lock() {
            queue.push_back(task);
        }

        Ok(agent_id)
    }

    /// Get the current task queue length
    pub fn queue_len(&self) -> usize {
        self.task_queue.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Pop the next task from the queue
    pub fn next_task(&self) -> Option<Task> {
        self.task_queue.lock().ok().and_then(|mut q| q.pop_front())
    }

    /// Get the current routing strategy
    pub fn strategy(&self) -> &RoutingStrategy {
        &self.strategy
    }

    /// Get the local agent ID (for fallback)
    pub fn local_agent_id(&self) -> &str {
        &self.local_agent_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::AgentInfo;
    use chrono::Utc;

    fn make_agent(id: &str, profile: &str, status: AgentStatus) -> AgentInfo {
        AgentInfo {
            id: id.to_string(),
            name: format!("Agent {id}"),
            profile: profile.to_string(),
            address: "127.0.0.1".to_string(),
            port: 9443,
            status,
            capabilities: vec!["status_query".to_string()],
            version: "1.0.0".to_string(),
            last_heartbeat: Utc::now(),
            registered_at: Utc::now(),
        }
    }

    fn make_task(command: &str, profile: Option<&str>) -> Task {
        Task {
            id: uuid::Uuid::new_v4().to_string(),
            command: command.to_string(),
            required_profile: profile.map(|s| s.to_string()),
            target_agent: None,
            priority: TaskPriority::Normal,
            created_at: Utc::now(),
        }
    }

    fn setup_registry(agents: Vec<AgentInfo>) -> Arc<AgentRegistry> {
        let tmp = std::env::temp_dir().join(format!("ectest_orch_{}.json", uuid::Uuid::new_v4()));
        let registry = Arc::new(AgentRegistry::with_path(tmp));
        for agent in agents {
            registry.register(agent).unwrap();
        }
        registry
    }

    #[test]
    fn test_round_robin() {
        let registry = setup_registry(vec![
            make_agent("a1", "System", AgentStatus::Online),
            make_agent("a2", "System", AgentStatus::Online),
        ]);
        let orch = Orchestrator::new(registry, RoutingStrategy::RoundRobin, "local");

        let task1 = make_task("cmd1", None);
        let task2 = make_task("cmd2", None);
        let task3 = make_task("cmd3", None);

        let agent1 = orch.select_agent(&task1).unwrap();
        let agent2 = orch.select_agent(&task2).unwrap();
        let agent3 = orch.select_agent(&task3).unwrap();

        // Should alternate between a1 and a2
        assert_ne!(agent1.id, agent2.id);
        assert_eq!(agent1.id, agent3.id);
    }

    #[test]
    fn test_profile_based() {
        let registry = setup_registry(vec![
            make_agent("a1", "System", AgentStatus::Online),
            make_agent("a2", "SoftwareDev", AgentStatus::Online),
        ]);
        let orch = Orchestrator::new(registry, RoutingStrategy::ProfileBased, "local");

        let task = make_task("cargo build", Some("SoftwareDev"));
        let agent = orch.select_agent(&task).unwrap();
        assert_eq!(agent.id, "a2");
    }

    #[test]
    fn test_profile_fallback() {
        let registry = setup_registry(vec![make_agent("a1", "System", AgentStatus::Online)]);
        let orch = Orchestrator::new(registry, RoutingStrategy::ProfileBased, "local");

        let task = make_task("deploy", Some("DevOps"));
        let agent = orch.select_agent(&task).unwrap();
        // No DevOps agent, falls back to first available
        assert_eq!(agent.id, "a1");
    }

    #[test]
    fn test_no_agents_error() {
        let registry = setup_registry(vec![]);
        let orch = Orchestrator::new(registry, RoutingStrategy::RoundRobin, "local");

        let task = make_task("cmd", None);
        assert!(orch.select_agent(&task).is_err());
    }

    #[test]
    fn test_manual_routing() {
        let registry = setup_registry(vec![make_agent("a1", "System", AgentStatus::Online)]);
        let orch = Orchestrator::new(registry, RoutingStrategy::Manual, "local");

        let mut task = make_task("cmd", None);
        task.target_agent = Some("a1".to_string());
        let agent = orch.select_agent(&task).unwrap();
        assert_eq!(agent.id, "a1");
    }

    #[test]
    fn test_dispatch_and_queue() {
        let registry = setup_registry(vec![make_agent("a1", "System", AgentStatus::Online)]);
        let orch = Orchestrator::new(registry, RoutingStrategy::RoundRobin, "local");

        let task = make_task("echo hello", None);
        let result = orch.dispatch(task);
        assert!(result.is_ok());
        assert_eq!(orch.queue_len(), 1);

        let next = orch.next_task().unwrap();
        assert_eq!(next.command, "echo hello");
        assert_eq!(orch.queue_len(), 0);
    }

    #[test]
    fn test_task_priority_order() {
        assert!(TaskPriority::Low < TaskPriority::Normal);
        assert!(TaskPriority::Normal < TaskPriority::High);
        assert!(TaskPriority::High < TaskPriority::Critical);
    }

    #[test]
    fn test_routing_strategy_default() {
        assert_eq!(RoutingStrategy::default(), RoutingStrategy::ProfileBased);
    }

    #[test]
    fn test_task_serialization() {
        let task = make_task("echo test", Some("System"));
        let json = serde_json::to_string(&task).unwrap();
        assert!(json.contains("echo test"));

        let deserialized: Task = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.command, "echo test");
    }

    #[test]
    fn test_priority_routing() {
        let registry = setup_registry(vec![
            make_agent("a1", "System", AgentStatus::Online),
            make_agent("a2", "System", AgentStatus::Online),
        ]);
        let orch = Orchestrator::new(registry, RoutingStrategy::Priority, "local");
        let task = make_task("monitor", None);
        let agent = orch.select_agent(&task).unwrap();
        // Priority routing prefers Online agents; both are online so first is selected
        assert!(!agent.id.is_empty());
    }

    #[test]
    fn test_manual_no_target_error() {
        let registry = setup_registry(vec![make_agent("a1", "System", AgentStatus::Online)]);
        let orch = Orchestrator::new(registry, RoutingStrategy::Manual, "local");
        let task = make_task("cmd", None);
        let result = orch.select_agent(&task);
        assert!(result.is_err());
    }

    #[test]
    fn test_next_task_empty_queue() {
        let registry = setup_registry(vec![]);
        let orch = Orchestrator::new(registry, RoutingStrategy::RoundRobin, "local");
        assert!(orch.next_task().is_none());
        assert_eq!(orch.queue_len(), 0);
    }

    #[test]
    fn test_strategy_accessor() {
        let registry = setup_registry(vec![]);
        let orch = Orchestrator::new(registry, RoutingStrategy::Priority, "local");
        assert_eq!(*orch.strategy(), RoutingStrategy::Priority);
    }

    #[test]
    fn test_local_agent_id_accessor() {
        let registry = setup_registry(vec![]);
        let orch = Orchestrator::new(registry, RoutingStrategy::RoundRobin, "my-local-id");
        assert_eq!(orch.local_agent_id(), "my-local-id");
    }

    #[test]
    fn test_task_result_serialize() {
        let result = TaskResult {
            task_id: "t1".into(),
            agent_id: "a1".into(),
            success: true,
            output: "done".into(),
            duration_ms: 42,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"success\":true"));
        let parsed: TaskResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.task_id, "t1");
        assert_eq!(parsed.duration_ms, 42);
    }

    #[test]
    fn test_manual_offline_agent_fallback_error() {
        let registry = setup_registry(vec![make_agent("a1", "System", AgentStatus::Offline)]);
        let orch = Orchestrator::new(registry, RoutingStrategy::ProfileBased, "local");
        let mut task = make_task("cmd", None);
        task.target_agent = Some("a1".to_string());
        // a1 is offline, no other online agents → should fail
        let result = orch.select_agent(&task);
        assert!(result.is_err());
    }

    #[test]
    fn test_routing_strategy_serialize() {
        let s = RoutingStrategy::RoundRobin;
        let json = serde_json::to_string(&s).unwrap();
        let parsed: RoutingStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, RoutingStrategy::RoundRobin);
    }

    #[test]
    fn test_task_priority_default() {
        assert_eq!(TaskPriority::default(), TaskPriority::Normal);
    }
}

//! Agent Router — Persona-based A2A task routing.
//!
//! Routes incoming tasks to the best-matching local or remote agent
//! based on their specialization confidence and load (busy status).
//!
//! Flow:
//! 1. Task arrives (capability + description)
//! 2. Router queries persona registry for candidates
//! 3. Score = (specialization_confidence * 0.7) + (reputation_score * 0.3)
//! 4. Top candidate is selected; if all busy, task is queued
//! 5. Delegation contract is created via DelegationEngine

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::delegation::{AgentCandidate, DelegationContract, DelegationEngine};
use crate::error::AgentError;
use crate::persona::AgentPersona;

// ─── Routing Metadata ────────────────────────────────────────────────────────

/// Scoring result for a routing candidate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingScore {
    pub agent_id: String,
    pub agent_name: String,
    pub specialization_confidence: f64,
    pub reputation_score: f64,
    pub total_score: f64,
    pub is_busy: bool,
}

/// A queued task waiting for an available agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedTask {
    pub id: Uuid,
    pub capability: String,
    pub description: String,
    pub escrow_amount: f64,
    pub delegator_id: String,
    pub queued_at: DateTime<Utc>,
    pub priority: u8,
}

// ─── AgentRouter ─────────────────────────────────────────────────────────────

/// Persona-aware task router on top of DelegationEngine
pub struct AgentRouter {
    delegation: DelegationEngine,
    personas: Vec<(String, AgentPersona)>, // (agent_id, persona)
    queue: Vec<QueuedTask>,
    specialization_weight: f64,
    reputation_weight: f64,
}

impl Default for AgentRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentRouter {
    pub fn new() -> Self {
        Self {
            delegation: DelegationEngine::new(),
            personas: Vec::new(),
            queue: Vec::new(),
            specialization_weight: 0.7,
            reputation_weight: 0.3,
        }
    }

    /// Register an agent with its persona (also adds to delegation registry)
    pub fn register_agent(
        &mut self,
        agent_id: &str,
        persona: AgentPersona,
        reputation_score: f64,
        address: &str,
    ) {
        // Extract specialization domains for the delegation registry
        let specializations: Vec<String> = persona
            .top_specializations(5)
            .iter()
            .map(|s| s.domain.clone())
            .collect();

        let candidate = AgentCandidate {
            agent_id: agent_id.to_string(),
            name: persona.name.clone(),
            specializations,
            reputation_score,
            address: address.to_string(),
            busy: false,
        };

        self.delegation.register_candidate(candidate);
        self.personas.push((agent_id.to_string(), persona));
    }

    /// Score all candidates for a given capability domain (including busy)
    pub fn score_candidates(&self, capability: &str) -> Vec<RoutingScore> {
        let key = capability.to_lowercase();
        let candidates = self.delegation.find_all_candidates(&key);

        let mut scores: Vec<RoutingScore> = candidates
            .into_iter()
            .map(|c| {
                // Look up persona for specialization confidence
                let spec_confidence = self
                    .personas
                    .iter()
                    .find(|(id, _)| id == &c.agent_id)
                    .and_then(|(_, persona)| {
                        persona
                            .specializations
                            .iter()
                            .find(|s| s.domain.to_lowercase().contains(&key))
                            .map(|s| s.confidence)
                    })
                    .unwrap_or(0.1); // base confidence if registered but no lessons

                let total = self.specialization_weight * spec_confidence
                    + self.reputation_weight * (c.reputation_score / 100.0);

                RoutingScore {
                    agent_id: c.agent_id.clone(),
                    agent_name: c.name.clone(),
                    specialization_confidence: spec_confidence,
                    reputation_score: c.reputation_score,
                    total_score: total,
                    is_busy: c.busy,
                }
            })
            .collect();

        scores.sort_by(|a, b| {
            b.total_score
                .partial_cmp(&a.total_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        scores
    }

    /// Route a task to the best available agent.
    /// Returns a DelegationContract on success, or queues the task if all busy.
    pub fn route(
        &mut self,
        delegator_id: &str,
        capability: &str,
        description: &str,
        escrow_amount: f64,
    ) -> Result<RoutingResult, AgentError> {
        let scores = self.score_candidates(capability);

        if scores.is_empty() {
            return Err(AgentError::NotFound(format!(
                "No agents registered for capability: {capability}"
            )));
        }

        // Find first available (not busy)
        let best = scores.iter().find(|s| !s.is_busy);

        match best {
            Some(_candidate) => {
                let contract = self.delegation.delegate_task(
                    delegator_id,
                    capability,
                    description,
                    escrow_amount,
                )?;
                Ok(RoutingResult::Delegated(contract))
            }
            None => {
                // All busy → queue
                let task = QueuedTask {
                    id: Uuid::new_v4(),
                    capability: capability.to_string(),
                    description: description.to_string(),
                    escrow_amount,
                    delegator_id: delegator_id.to_string(),
                    queued_at: Utc::now(),
                    priority: 1,
                };
                let id = task.id;
                self.queue.push(task);
                Ok(RoutingResult::Queued(id))
            }
        }
    }

    /// Dequeue and route the next pending task if any agent is now available.
    pub fn flush_queue(&mut self) -> Vec<RoutingResult> {
        let mut results = Vec::new();
        let mut remaining = Vec::new();

        for task in std::mem::take(&mut self.queue) {
            match self.delegation.delegate_task(
                &task.delegator_id.clone(),
                &task.capability.clone(),
                &task.description.clone(),
                task.escrow_amount,
            ) {
                Ok(contract) => results.push(RoutingResult::Delegated(contract)),
                Err(_) => remaining.push(task),
            }
        }

        self.queue = remaining;
        results
    }

    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    pub fn delegation_mut(&mut self) -> &mut DelegationEngine {
        &mut self.delegation
    }
}

/// Result of a routing attempt
#[derive(Debug)]
pub enum RoutingResult {
    Delegated(DelegationContract),
    Queued(Uuid),
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persona::{AgentPersona, PersonaPreset};

    fn make_router_with_agents() -> AgentRouter {
        let mut router = AgentRouter::new();

        // Agent Alpha: Executor persona, specializes in Rust + DevOps
        let mut alpha = AgentPersona::from_preset("Alpha", PersonaPreset::Executor);
        for _ in 0..10 {
            alpha.record_task_completion("rust");
        }
        for _ in 0..5 {
            alpha.record_lesson_applied("rust");
        }
        router.register_agent("agent_alpha", alpha, 88.0, "localhost:9001");

        // Agent Beta: Analyst persona, specializes in Python + Data
        let mut beta = AgentPersona::from_preset("Beta", PersonaPreset::Analyst);
        for _ in 0..8 {
            beta.record_task_completion("python");
        }
        router.register_agent("agent_beta", beta, 75.0, "localhost:9002");

        router
    }

    #[test]
    fn test_score_candidates_for_rust() {
        let router = make_router_with_agents();
        let scores = router.score_candidates("rust");
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].agent_id, "agent_alpha");
        assert!(scores[0].total_score > 0.0);
    }

    #[test]
    fn test_score_candidates_for_python() {
        let router = make_router_with_agents();
        let scores = router.score_candidates("python");
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].agent_id, "agent_beta");
    }

    #[test]
    fn test_route_delegates_to_best_agent() {
        let mut router = make_router_with_agents();
        let result = router
            .route("delegator_1", "rust", "Write parser", 50.0)
            .unwrap();

        match result {
            RoutingResult::Delegated(contract) => {
                assert_eq!(contract.delegate_id, "agent_alpha");
            }
            RoutingResult::Queued(_) => panic!("Expected delegation, got queued"),
        }
    }

    #[test]
    fn test_route_queues_when_agent_busy() {
        let mut router = make_router_with_agents();

        // First task — delegates alpha
        router.route("d1", "rust", "Task 1", 50.0).unwrap();

        // Second task — alpha is busy, should queue
        let result = router.route("d1", "rust", "Task 2", 50.0).unwrap();
        match result {
            RoutingResult::Queued(_) => {}
            RoutingResult::Delegated(_) => panic!("Expected queue, got delegation"),
        }

        assert_eq!(router.queue_len(), 1);
    }

    #[test]
    fn test_route_no_agent_for_capability() {
        let mut router = make_router_with_agents();
        let result = router.route("d1", "blockchain", "Deploy", 10.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_flush_queue_dispatches_pending() {
        let mut router = make_router_with_agents();

        // Busy alpha
        router.route("d1", "rust", "Task 1", 50.0).unwrap();
        // Queue task 2
        router.route("d1", "rust", "Task 2", 50.0).unwrap();
        assert_eq!(router.queue_len(), 1);

        // Simulate alpha finishing (direct delegation engine access)
        if let Some(c) = router
            .delegation
            .candidates
            .iter_mut()
            .find(|c| c.agent_id == "agent_alpha")
        {
            c.busy = false;
        }

        let results = router.flush_queue();
        assert_eq!(results.len(), 1);
        assert_eq!(router.queue_len(), 0);

        match &results[0] {
            RoutingResult::Delegated(contract) => {
                assert_eq!(contract.delegate_id, "agent_alpha");
            }
            RoutingResult::Queued(_) => panic!("Expected delegation after flush"),
        }
    }

    #[test]
    fn test_specialization_confidence_affects_score() {
        // Alpha has high specialization confidence for rust (10 tasks + 5 lessons)
        // Score = 0.7 * confidence + 0.3 * (rep/100)
        let router = make_router_with_agents();
        let scores = router.score_candidates("rust");
        let alpha_score = &scores[0];

        // 10 * 0.05 + 5 * 0.1 = 1.0 (capped)
        assert!((alpha_score.specialization_confidence - 1.0).abs() < 0.001);
        // total = 0.7 * 1.0 + 0.3 * 0.88 = 0.964
        assert!((alpha_score.total_score - 0.964).abs() < 0.01);
    }
}

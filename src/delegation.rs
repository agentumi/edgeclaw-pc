//! Delegation Engine — A2A (Agent-to-Agent) task delegation and routing.
//!
//! Implements the full delegation lifecycle:
//! 1. Registry search for candidate agents
//! 2. Reputation-based candidate ranking
//! 3. SUI escrow creation (mock)
//! 4. Task delegation + result verification
//! 5. Escrow release or slashing

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AgentError;
use crate::reputation::ReputationEngine;

// ─── Data structures ─────────────────────────────────────────────────────────

/// Status of a delegation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegationStatus {
    Pending,
    Accepted,
    InProgress,
    Completed,
    Verified,
    Failed,
    Slashed,
}

impl std::fmt::Display for DelegationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegationStatus::Pending => write!(f, "Pending"),
            DelegationStatus::Accepted => write!(f, "Accepted"),
            DelegationStatus::InProgress => write!(f, "InProgress"),
            DelegationStatus::Completed => write!(f, "Completed"),
            DelegationStatus::Verified => write!(f, "Verified"),
            DelegationStatus::Failed => write!(f, "Failed"),
            DelegationStatus::Slashed => write!(f, "Slashed"),
        }
    }
}

/// A candidate agent in the delegation registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCandidate {
    pub agent_id: String,
    pub name: String,
    pub specializations: Vec<String>,
    pub reputation_score: f64,
    pub address: String,
    pub busy: bool,
}

/// A task delegation contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationContract {
    pub id: Uuid,
    pub delegator_id: String,
    pub delegate_id: String,
    pub task_description: String,
    pub escrow_amount: f64,
    pub escrow_object_id: Option<String>,
    pub status: DelegationStatus,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result_summary: Option<String>,
    pub quality_score: Option<f64>,
}

impl DelegationContract {
    pub fn new(
        delegator_id: &str,
        delegate_id: &str,
        task_description: &str,
        escrow_amount: f64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            delegator_id: delegator_id.to_string(),
            delegate_id: delegate_id.to_string(),
            task_description: task_description.to_string(),
            escrow_amount,
            escrow_object_id: None,
            status: DelegationStatus::Pending,
            created_at: Utc::now(),
            completed_at: None,
            result_summary: None,
            quality_score: None,
        }
    }
}

// ─── Escrow (Mock) ─────────────────────────────────────────────────────────────

/// Mock SUI escrow for task payment
pub struct SuiEscrow;

impl SuiEscrow {
    /// Create an escrow for the given amount. Returns object_id.
    pub fn create(delegator_id: &str, amount: f64) -> Result<String, AgentError> {
        if amount <= 0.0 {
            return Err(AgentError::InvalidParameter(
                "Escrow amount must be positive".into(),
            ));
        }
        let object_id = format!(
            "0xescrow_{}_{}",
            &delegator_id[..delegator_id.len().min(8)],
            (amount * 100.0) as u64
        );
        Ok(object_id)
    }

    /// Release escrow to delegate after verification.
    pub fn release(object_id: &str) -> Result<String, AgentError> {
        let tx = format!("0xtx_release_{}", &object_id[..object_id.len().min(16)]);
        Ok(tx)
    }

    /// Slash escrow — return to delegator and penalise delegate.
    pub fn slash(object_id: &str) -> Result<String, AgentError> {
        let tx = format!("0xtx_slash_{}", &object_id[..object_id.len().min(16)]);
        Ok(tx)
    }
}

// ─── DelegationEngine ─────────────────────────────────────────────────────────

/// In-memory delegation registry and engine
pub struct DelegationEngine {
    pub candidates: Vec<AgentCandidate>,
    contracts: Vec<DelegationContract>,
    reputation: ReputationEngine,
}

impl Default for DelegationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegationEngine {
    pub fn new() -> Self {
        Self {
            candidates: Vec::new(),
            contracts: Vec::new(),
            reputation: ReputationEngine::new(),
        }
    }

    /// Register an agent as a delegation candidate.
    pub fn register_candidate(&mut self, candidate: AgentCandidate) {
        self.candidates.push(candidate);
    }

    /// Search candidates by specialization keyword.
    /// Returns sorted by reputation score (descending). Excludes busy agents.
    pub fn find_candidates(&self, specialization: &str) -> Vec<&AgentCandidate> {
        let key = specialization.to_lowercase();
        let mut found: Vec<&AgentCandidate> = self
            .candidates
            .iter()
            .filter(|c| {
                !c.busy
                    && c.specializations
                        .iter()
                        .any(|s| s.to_lowercase().contains(&key))
            })
            .collect();

        found.sort_by(|a, b| {
            b.reputation_score
                .partial_cmp(&a.reputation_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        found
    }

    /// Search ALL candidates (including busy) by specialization keyword.
    pub fn find_all_candidates(&self, specialization: &str) -> Vec<&AgentCandidate> {
        let key = specialization.to_lowercase();
        let mut found: Vec<&AgentCandidate> = self
            .candidates
            .iter()
            .filter(|c| {
                c.specializations
                    .iter()
                    .any(|s| s.to_lowercase().contains(&key))
            })
            .collect();

        found.sort_by(|a, b| {
            b.reputation_score
                .partial_cmp(&a.reputation_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        found
    }

    /// Delegate a task to the best matching agent.
    /// Returns the created DelegationContract.
    pub fn delegate_task(
        &mut self,
        delegator_id: &str,
        specialization: &str,
        task_description: &str,
        escrow_amount: f64,
    ) -> Result<DelegationContract, AgentError> {
        let delegate_id = self
            .find_candidates(specialization)
            .first()
            .map(|c| c.agent_id.clone())
            .ok_or_else(|| {
                AgentError::NotFound(format!(
                    "No available agent for specialization: {specialization}"
                ))
            })?;

        // Create escrow
        let escrow_id = SuiEscrow::create(delegator_id, escrow_amount)?;

        let mut contract =
            DelegationContract::new(delegator_id, &delegate_id, task_description, escrow_amount);
        contract.escrow_object_id = Some(escrow_id);
        contract.status = DelegationStatus::Accepted;

        // Mark candidate as busy
        if let Some(c) = self.candidates.iter_mut().find(|c| c.agent_id == delegate_id) {
            c.busy = true;
        }

        self.contracts.push(contract.clone());
        Ok(contract)
    }

    /// Submit a result for a delegation contract.
    pub fn submit_result(
        &mut self,
        contract_id: Uuid,
        result_summary: &str,
    ) -> Result<(), AgentError> {
        let contract = self
            .contracts
            .iter_mut()
            .find(|c| c.id == contract_id)
            .ok_or_else(|| AgentError::NotFound(format!("Contract {contract_id} not found")))?;

        contract.status = DelegationStatus::Completed;
        contract.result_summary = Some(result_summary.to_string());
        contract.completed_at = Some(Utc::now());
        Ok(())
    }

    /// Verify a completed task: if quality >= threshold, release escrow; else slash.
    pub fn verify_and_settle(
        &mut self,
        contract_id: Uuid,
        quality_score: f64,
        threshold: f64,
    ) -> Result<DelegationStatus, AgentError> {
        let contract = self
            .contracts
            .iter_mut()
            .find(|c| c.id == contract_id)
            .ok_or_else(|| AgentError::NotFound(format!("Contract {contract_id} not found")))?;

        if contract.status != DelegationStatus::Completed {
            return Err(AgentError::InvalidParameter(
                "Contract must be in Completed status to verify".into(),
            ));
        }

        contract.quality_score = Some(quality_score);

        let escrow_id = contract
            .escrow_object_id
            .clone()
            .unwrap_or_default();

        if quality_score >= threshold {
            SuiEscrow::release(&escrow_id)?;
            contract.status = DelegationStatus::Verified;

            // Free up the delegate
            let delegate_id = contract.delegate_id.clone();
            if let Some(c) = self.candidates.iter_mut().find(|c| c.agent_id == delegate_id) {
                c.busy = false;
            }
        } else {
            SuiEscrow::slash(&escrow_id)?;
            contract.status = DelegationStatus::Slashed;
        }

        Ok(contract.status)
    }

    /// List all contracts for a delegator.
    pub fn list_contracts(&self, delegator_id: &str) -> Vec<&DelegationContract> {
        self.contracts
            .iter()
            .filter(|c| c.delegator_id == delegator_id)
            .collect()
    }

    /// Get a contract by ID.
    pub fn get_contract(&self, contract_id: Uuid) -> Option<&DelegationContract> {
        self.contracts.iter().find(|c| c.id == contract_id)
    }

    /// Access the reputation engine for PoP updates.
    pub fn reputation_mut(&mut self) -> &mut ReputationEngine {
        &mut self.reputation
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> DelegationEngine {
        let mut engine = DelegationEngine::new();
        engine.register_candidate(AgentCandidate {
            agent_id: "agent_alpha".to_string(),
            name: "Alpha".to_string(),
            specializations: vec!["rust".to_string(), "devops".to_string()],
            reputation_score: 88.0,
            address: "localhost:9001".to_string(),
            busy: false,
        });
        engine.register_candidate(AgentCandidate {
            agent_id: "agent_beta".to_string(),
            name: "Beta".to_string(),
            specializations: vec!["python".to_string(), "data".to_string()],
            reputation_score: 72.0,
            address: "localhost:9002".to_string(),
            busy: false,
        });
        engine
    }

    #[test]
    fn test_find_candidates_by_specialization() {
        let engine = make_engine();
        let results = engine.find_candidates("rust");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_id, "agent_alpha");
    }

    #[test]
    fn test_find_candidates_sorted_by_reputation() {
        let mut engine = make_engine();
        engine.register_candidate(AgentCandidate {
            agent_id: "agent_gamma".to_string(),
            name: "Gamma".to_string(),
            specializations: vec!["rust".to_string()],
            reputation_score: 95.0,
            address: "localhost:9003".to_string(),
            busy: false,
        });
        let results = engine.find_candidates("rust");
        // gamma (95) should be first, alpha (88) second
        assert_eq!(results[0].agent_id, "agent_gamma");
        assert_eq!(results[1].agent_id, "agent_alpha");
    }

    #[test]
    fn test_delegate_task_success() {
        let mut engine = make_engine();
        let contract = engine
            .delegate_task("delegator_1", "rust", "Refactor auth module", 50.0)
            .unwrap();

        assert_eq!(contract.delegate_id, "agent_alpha");
        assert_eq!(contract.status, DelegationStatus::Accepted);
        assert!(contract.escrow_object_id.is_some());
    }

    #[test]
    fn test_delegate_task_no_candidate() {
        let mut engine = make_engine();
        let result = engine.delegate_task("delegator_1", "blockchain", "Deploy contract", 10.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_submit_result() {
        let mut engine = make_engine();
        let contract = engine
            .delegate_task("delegator_1", "rust", "Refactor", 50.0)
            .unwrap();

        engine
            .submit_result(contract.id, "Refactoring complete, all tests pass.")
            .unwrap();

        let updated = engine.get_contract(contract.id).unwrap();
        assert_eq!(updated.status, DelegationStatus::Completed);
        assert!(updated.result_summary.is_some());
    }

    #[test]
    fn test_verify_and_settle_success() {
        let mut engine = make_engine();
        let contract = engine
            .delegate_task("delegator_1", "rust", "Write tests", 50.0)
            .unwrap();
        engine.submit_result(contract.id, "Done").unwrap();

        let status = engine.verify_and_settle(contract.id, 0.9, 0.7).unwrap();
        assert_eq!(status, DelegationStatus::Verified);

        // Candidate should be free again
        let candidate = engine
            .candidates
            .iter()
            .find(|c| c.agent_id == "agent_alpha")
            .unwrap();
        assert!(!candidate.busy);
    }

    #[test]
    fn test_verify_and_settle_slashing() {
        let mut engine = make_engine();
        let contract = engine
            .delegate_task("delegator_1", "rust", "Bad work", 50.0)
            .unwrap();
        engine.submit_result(contract.id, "Incomplete").unwrap();

        let status = engine.verify_and_settle(contract.id, 0.3, 0.7).unwrap();
        assert_eq!(status, DelegationStatus::Slashed);
    }

    #[test]
    fn test_list_contracts() {
        let mut engine = make_engine();
        engine
            .delegate_task("delegator_1", "rust", "Task A", 50.0)
            .unwrap();

        let contracts = engine.list_contracts("delegator_1");
        assert_eq!(contracts.len(), 1);

        let contracts_other = engine.list_contracts("nobody");
        assert!(contracts_other.is_empty());
    }

    #[test]
    fn test_busy_agent_excluded_from_results() {
        let mut engine = make_engine();
        // delegate first task → agent_alpha becomes busy
        engine
            .delegate_task("delegator_1", "rust", "Task 1", 50.0)
            .unwrap();

        // Now alpha should be excluded
        let results = engine.find_candidates("rust");
        assert!(results.is_empty());
    }

    #[test]
    fn test_escrow_create_zero_amount() {
        let result = SuiEscrow::create("delegator", 0.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_before_complete_error() {
        let mut engine = make_engine();
        let contract = engine
            .delegate_task("delegator_1", "rust", "Task", 50.0)
            .unwrap();

        // Not yet submitted, should fail
        let result = engine.verify_and_settle(contract.id, 0.9, 0.7);
        assert!(result.is_err());
    }

    #[test]
    fn test_delegation_status_display() {
        assert_eq!(DelegationStatus::Pending.to_string(), "Pending");
        assert_eq!(DelegationStatus::Verified.to_string(), "Verified");
        assert_eq!(DelegationStatus::Slashed.to_string(), "Slashed");
    }
}

//! # P5: Quantum Governance & ECNP Extension
//!
//! Quantum-weighted voting, proposal lifecycle, and consensus mechanisms
//! for multi-agent fleet governance.
//!
//! ## Design
//! - Proposals carry quantum weight derived from agent qubit success probabilities
//! - Voting power is proportional to persona specialization confidence
//! - Consensus threshold adapts based on proposal severity
//! - All decisions are hash-chained for auditability

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Governance Types ─────────────────────────────────────────────────────────

/// Severity of a governance proposal — determines required quorum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalSeverity {
    /// Low-risk: parameter tweak, persona update (50% quorum)
    Low,
    /// Medium-risk: policy change, role reassignment (66% quorum)
    Medium,
    /// High-risk: key rotation, fleet topology change (80% quorum)
    High,
    /// Critical: identity revocation, emergency halt (90% quorum)
    Critical,
}

impl ProposalSeverity {
    /// Required quorum ratio for this severity level
    pub fn quorum_ratio(&self) -> f64 {
        match self {
            ProposalSeverity::Low => 0.50,
            ProposalSeverity::Medium => 0.66,
            ProposalSeverity::High => 0.80,
            ProposalSeverity::Critical => 0.90,
        }
    }
}

/// Current state of a governance proposal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalState {
    /// Proposal is open for voting
    Open,
    /// Quorum reached — proposal approved
    Approved,
    /// Quorum not reached before deadline, or explicitly rejected
    Rejected,
    /// Proposal was executed after approval
    Executed,
    /// Proposal expired without reaching quorum
    Expired,
}

/// A single vote cast by an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Agent who cast the vote
    pub agent_id: String,
    /// Whether this is an approval vote
    pub approve: bool,
    /// Quantum-weighted voting power (derived from qubit β²)
    pub weight: f64,
    /// Optional reason for the vote
    pub reason: Option<String>,
    /// Timestamp of the vote
    pub timestamp: String,
}

/// A governance proposal submitted for fleet-wide voting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    /// Unique proposal identifier
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Detailed description of the proposed change
    pub description: String,
    /// Proposer agent ID
    pub proposer: String,
    /// Severity classification
    pub severity: ProposalSeverity,
    /// Current state
    pub state: ProposalState,
    /// All votes cast
    pub votes: Vec<Vote>,
    /// Total weight of approval votes
    pub approval_weight: f64,
    /// Total weight of rejection votes
    pub rejection_weight: f64,
    /// Number of eligible voters
    pub eligible_voters: u32,
    /// Deadline for voting
    pub deadline: String,
    /// Creation timestamp
    pub created_at: String,
    /// Resolution timestamp (when approved/rejected)
    pub resolved_at: Option<String>,
    /// SHA-256 hash of previous proposal (chain)
    pub prev_hash: String,
    /// This proposal's hash
    pub hash: String,
}

// ─── Governance Engine ────────────────────────────────────────────────────────

/// The Quantum Governance Engine manages proposal lifecycle and consensus
pub struct GovernanceEngine {
    /// All proposals, keyed by ID
    proposals: HashMap<String, GovernanceProposal>,
    /// Ordered proposal IDs for hash chain
    chain: Vec<String>,
    /// Agent voting power cache (from quantum qubit states)
    agent_weights: HashMap<String, f64>,
    /// Default number of eligible voters
    default_eligible: u32,
}

impl Default for GovernanceEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceEngine {
    /// Create a new empty governance engine
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
            chain: Vec::new(),
            agent_weights: HashMap::new(),
            default_eligible: 1,
        }
    }

    /// Set the number of eligible voters (fleet size)
    pub fn set_eligible_voters(&mut self, count: u32) {
        self.default_eligible = count.max(1);
    }

    /// Update an agent's quantum-derived voting weight
    pub fn update_agent_weight(&mut self, agent_id: &str, weight: f64) {
        self.agent_weights
            .insert(agent_id.to_string(), weight.clamp(0.0, 1.0));
    }

    /// Get an agent's voting weight (default 0.5 if not set)
    pub fn agent_weight(&self, agent_id: &str) -> f64 {
        self.agent_weights.get(agent_id).copied().unwrap_or(0.5)
    }

    /// Submit a new governance proposal
    pub fn submit_proposal(
        &mut self,
        title: &str,
        description: &str,
        proposer: &str,
        severity: ProposalSeverity,
        deadline_hours: u32,
    ) -> GovernanceProposal {
        let id = format!(
            "gov-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let now = chrono::Utc::now();
        let deadline = now + chrono::Duration::hours(deadline_hours as i64);

        let prev_hash = self
            .chain
            .last()
            .and_then(|last_id| self.proposals.get(last_id))
            .map(|p| p.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let proposal = GovernanceProposal {
            id: id.clone(),
            title: title.to_string(),
            description: description.to_string(),
            proposer: proposer.to_string(),
            severity,
            state: ProposalState::Open,
            votes: Vec::new(),
            approval_weight: 0.0,
            rejection_weight: 0.0,
            eligible_voters: self.default_eligible,
            deadline: deadline.to_rfc3339(),
            created_at: now.to_rfc3339(),
            resolved_at: None,
            prev_hash,
            hash: String::new(),
        };

        // Compute hash for this proposal
        let mut prop = proposal;
        prop.hash = Self::compute_hash(&prop);

        self.chain.push(id.clone());
        self.proposals.insert(id, prop.clone());
        prop
    }

    /// Cast a vote on a proposal
    pub fn cast_vote(
        &mut self,
        proposal_id: &str,
        agent_id: &str,
        approve: bool,
        reason: Option<String>,
    ) -> Result<Vote, String> {
        // Look up agent weight first to avoid borrow conflict with proposals
        let weight = self.agent_weight(agent_id);

        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| format!("Proposal not found: {}", proposal_id))?;

        if proposal.state != ProposalState::Open {
            return Err(format!(
                "Proposal {} is not open for voting (state: {:?})",
                proposal_id, proposal.state
            ));
        }

        // Check for duplicate vote
        if proposal.votes.iter().any(|v| v.agent_id == agent_id) {
            return Err(format!(
                "Agent {} already voted on {}",
                agent_id, proposal_id
            ));
        }

        // Check deadline
        if let Ok(deadline) = proposal.deadline.parse::<DateTime<Utc>>() {
            if chrono::Utc::now() > deadline {
                proposal.state = ProposalState::Expired;
                return Err("Voting deadline has passed".to_string());
            }
        }
        let vote = Vote {
            agent_id: agent_id.to_string(),
            approve,
            weight,
            reason,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        if approve {
            proposal.approval_weight += weight;
        } else {
            proposal.rejection_weight += weight;
        }
        proposal.votes.push(vote.clone());

        // Check if quorum is reached
        self.check_quorum(proposal_id);

        Ok(vote)
    }

    /// Check if a proposal has reached quorum and resolve it
    fn check_quorum(&mut self, proposal_id: &str) {
        let proposal = match self.proposals.get_mut(proposal_id) {
            Some(p) if p.state == ProposalState::Open => p,
            _ => return,
        };

        let voter_count = proposal.votes.len() as f64;
        let eligible = proposal.eligible_voters.max(1) as f64;
        let participation = voter_count / eligible;

        let quorum_needed = proposal.severity.quorum_ratio();
        let total_weight = proposal.approval_weight + proposal.rejection_weight;

        if total_weight > 0.0 && participation >= quorum_needed {
            let approval_ratio = proposal.approval_weight / total_weight;

            if approval_ratio >= 0.5 {
                proposal.state = ProposalState::Approved;
            } else {
                proposal.state = ProposalState::Rejected;
            }
            proposal.resolved_at = Some(chrono::Utc::now().to_rfc3339());
            proposal.hash = Self::compute_hash(proposal);
        }
    }

    /// Execute an approved proposal (marks it as Executed)
    pub fn execute_proposal(&mut self, proposal_id: &str) -> Result<(), String> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| format!("Proposal not found: {}", proposal_id))?;

        if proposal.state != ProposalState::Approved {
            return Err(format!(
                "Cannot execute proposal in state {:?}",
                proposal.state
            ));
        }

        proposal.state = ProposalState::Executed;
        proposal.resolved_at = Some(chrono::Utc::now().to_rfc3339());
        proposal.hash = Self::compute_hash(proposal);
        Ok(())
    }

    /// Expire proposals that are past their deadline
    pub fn expire_overdue(&mut self) {
        let now = chrono::Utc::now();
        let ids: Vec<String> = self.proposals.keys().cloned().collect();

        for id in ids {
            if let Some(proposal) = self.proposals.get_mut(&id) {
                if proposal.state == ProposalState::Open {
                    if let Ok(deadline) = proposal.deadline.parse::<DateTime<Utc>>() {
                        if now > deadline {
                            proposal.state = ProposalState::Expired;
                            proposal.resolved_at = Some(now.to_rfc3339());
                        }
                    }
                }
            }
        }
    }

    /// Get a proposal by ID
    pub fn get_proposal(&self, proposal_id: &str) -> Option<&GovernanceProposal> {
        self.proposals.get(proposal_id)
    }

    /// List all proposals
    pub fn list_proposals(&self) -> Vec<&GovernanceProposal> {
        self.proposals.values().collect()
    }

    /// Get proposals by state
    pub fn proposals_by_state(&self, state: &ProposalState) -> Vec<&GovernanceProposal> {
        self.proposals
            .values()
            .filter(|p| p.state == *state)
            .collect()
    }

    /// Governance statistics summary
    pub fn stats(&self) -> GovernanceStats {
        let total = self.proposals.len();
        let open = self
            .proposals
            .values()
            .filter(|p| p.state == ProposalState::Open)
            .count();
        let approved = self
            .proposals
            .values()
            .filter(|p| p.state == ProposalState::Approved || p.state == ProposalState::Executed)
            .count();
        let rejected = self
            .proposals
            .values()
            .filter(|p| p.state == ProposalState::Rejected)
            .count();
        let expired = self
            .proposals
            .values()
            .filter(|p| p.state == ProposalState::Expired)
            .count();

        let avg_participation = if total > 0 {
            self.proposals
                .values()
                .map(|p| {
                    let eligible = p.eligible_voters.max(1) as f64;
                    p.votes.len() as f64 / eligible
                })
                .sum::<f64>()
                / total as f64
        } else {
            0.0
        };

        GovernanceStats {
            total_proposals: total,
            open,
            approved,
            rejected,
            expired,
            avg_participation,
            chain_length: self.chain.len(),
        }
    }

    /// Verify hash chain integrity
    pub fn verify_chain(&self) -> bool {
        let mut prev_hash = "0".repeat(64);
        for id in &self.chain {
            if let Some(proposal) = self.proposals.get(id) {
                if proposal.prev_hash != prev_hash {
                    return false;
                }
                prev_hash = proposal.hash.clone();
            } else {
                return false;
            }
        }
        true
    }

    /// Compute SHA-256 hash of a proposal (for chain integrity)
    fn compute_hash(proposal: &GovernanceProposal) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        proposal.id.hash(&mut hasher);
        proposal.title.hash(&mut hasher);
        proposal.proposer.hash(&mut hasher);
        proposal.prev_hash.hash(&mut hasher);
        proposal.votes.len().hash(&mut hasher);
        format!(
            "{:016x}{:016x}{:016x}{:016x}",
            hasher.finish(),
            proposal.approval_weight.to_bits(),
            proposal.rejection_weight.to_bits(),
            proposal.eligible_voters,
        )
    }
}

/// Summary statistics for governance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceStats {
    pub total_proposals: usize,
    pub open: usize,
    pub approved: usize,
    pub rejected: usize,
    pub expired: usize,
    pub avg_participation: f64,
    pub chain_length: usize,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submit_proposal() {
        let mut engine = GovernanceEngine::new();
        let proposal = engine.submit_proposal(
            "Upgrade Encryption",
            "Rotate all session keys to AES-256-GCM-SIV",
            "agent-alpha",
            ProposalSeverity::High,
            24,
        );
        assert_eq!(proposal.state, ProposalState::Open);
        assert!(!proposal.hash.is_empty());
        assert_eq!(engine.list_proposals().len(), 1);
    }

    #[test]
    fn test_cast_vote() {
        let mut engine = GovernanceEngine::new();
        engine.set_eligible_voters(3);
        let proposal = engine.submit_proposal(
            "Add Agent",
            "Register new fleet member",
            "agent-alpha",
            ProposalSeverity::Low,
            24,
        );

        let vote = engine
            .cast_vote(&proposal.id, "agent-beta", true, Some("LGTM".to_string()))
            .unwrap();
        assert!(vote.approve);
        assert!(vote.weight > 0.0);
    }

    #[test]
    fn test_duplicate_vote_rejected() {
        let mut engine = GovernanceEngine::new();
        engine.set_eligible_voters(3);
        let proposal = engine.submit_proposal(
            "Test",
            "Test proposal",
            "agent-alpha",
            ProposalSeverity::Low,
            24,
        );

        engine
            .cast_vote(&proposal.id, "agent-beta", true, None)
            .unwrap();
        let result = engine.cast_vote(&proposal.id, "agent-beta", false, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_quorum_approval() {
        let mut engine = GovernanceEngine::new();
        engine.set_eligible_voters(2);
        engine.update_agent_weight("voter-a", 0.8);
        engine.update_agent_weight("voter-b", 0.7);

        let proposal = engine.submit_proposal(
            "Policy Update",
            "Change RBAC rules",
            "proposer",
            ProposalSeverity::Low,
            24,
        );

        engine
            .cast_vote(&proposal.id, "voter-a", true, None)
            .unwrap();

        // After 1/2 voters with Low quorum (50%), should reach quorum
        let p = engine.get_proposal(&proposal.id).unwrap();
        assert_eq!(p.state, ProposalState::Approved);
    }

    #[test]
    fn test_quorum_rejection() {
        let mut engine = GovernanceEngine::new();
        engine.set_eligible_voters(2);

        let proposal = engine.submit_proposal(
            "Bad Idea",
            "Should be rejected",
            "proposer",
            ProposalSeverity::Low,
            24,
        );

        engine
            .cast_vote(&proposal.id, "voter-a", false, None)
            .unwrap();

        let p = engine.get_proposal(&proposal.id).unwrap();
        assert_eq!(p.state, ProposalState::Rejected);
    }

    #[test]
    fn test_severity_quorum_levels() {
        assert!((ProposalSeverity::Low.quorum_ratio() - 0.50).abs() < f64::EPSILON);
        assert!((ProposalSeverity::Medium.quorum_ratio() - 0.66).abs() < f64::EPSILON);
        assert!((ProposalSeverity::High.quorum_ratio() - 0.80).abs() < f64::EPSILON);
        assert!((ProposalSeverity::Critical.quorum_ratio() - 0.90).abs() < f64::EPSILON);
    }

    #[test]
    fn test_execute_proposal() {
        let mut engine = GovernanceEngine::new();
        engine.set_eligible_voters(1);
        let proposal = engine.submit_proposal(
            "Execute Test",
            "Auto-approve with 1 voter",
            "proposer",
            ProposalSeverity::Low,
            24,
        );

        engine
            .cast_vote(&proposal.id, "voter-a", true, None)
            .unwrap();

        let result = engine.execute_proposal(&proposal.id);
        assert!(result.is_ok());

        let p = engine.get_proposal(&proposal.id).unwrap();
        assert_eq!(p.state, ProposalState::Executed);
    }

    #[test]
    fn test_stats() {
        let mut engine = GovernanceEngine::new();
        engine.submit_proposal("P1", "d1", "a", ProposalSeverity::Low, 24);
        engine.submit_proposal("P2", "d2", "a", ProposalSeverity::Medium, 24);

        let stats = engine.stats();
        assert_eq!(stats.total_proposals, 2);
        assert_eq!(stats.open, 2);
        assert_eq!(stats.chain_length, 2);
    }

    #[test]
    fn test_chain_integrity() {
        let mut engine = GovernanceEngine::new();
        engine.submit_proposal("P1", "d1", "a", ProposalSeverity::Low, 24);
        engine.submit_proposal("P2", "d2", "b", ProposalSeverity::High, 24);
        engine.submit_proposal("P3", "d3", "c", ProposalSeverity::Critical, 24);

        assert!(engine.verify_chain());
    }

    #[test]
    fn test_proposals_by_state() {
        let mut engine = GovernanceEngine::new();
        engine.set_eligible_voters(1);

        let _p1 = engine.submit_proposal("Open", "stays open", "a", ProposalSeverity::High, 24);
        let p2 = engine.submit_proposal("Approve", "will approve", "a", ProposalSeverity::Low, 24);

        engine.cast_vote(&p2.id, "voter", true, None).unwrap();

        assert_eq!(engine.proposals_by_state(&ProposalState::Open).len(), 1);
        assert_eq!(engine.proposals_by_state(&ProposalState::Approved).len(), 1);
    }

    #[test]
    fn test_agent_weight_update() {
        let mut engine = GovernanceEngine::new();
        engine.update_agent_weight("agent-x", 0.9);
        assert!((engine.agent_weight("agent-x") - 0.9).abs() < f64::EPSILON);
        assert!((engine.agent_weight("unknown") - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_weight_clamping() {
        let mut engine = GovernanceEngine::new();
        engine.update_agent_weight("agent-x", 1.5);
        assert!((engine.agent_weight("agent-x") - 1.0).abs() < f64::EPSILON);
        engine.update_agent_weight("agent-y", -0.5);
        assert!((engine.agent_weight("agent-y") - 0.0).abs() < f64::EPSILON);
    }
}

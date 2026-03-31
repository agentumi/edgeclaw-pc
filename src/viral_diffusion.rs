//! # P3-08: Viral Diffusion Loop
//!
//! Propagates successful patterns and failure insights across the fleet.
//! Each insight carries a "viral score" that determines diffusion velocity.
//!
//! ## Algorithm
//! 1. Agent discovers a pattern (success or failure insight)
//! 2. Pattern is scored for viral potential: novelty × applicability × urgency
//! 3. Patterns above threshold are broadcast to entangled agents
//! 4. Receiving agents incorporate the pattern, increasing diffusion_count
//! 5. High-diffusion patterns become part of collective M365 memory

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A diffusible knowledge packet (pattern or insight)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffusionPacket {
    /// Unique packet identifier
    pub id: String,
    /// Source agent that originated this packet
    pub origin_agent: String,
    /// Content of the knowledge
    pub content: String,
    /// Domain this knowledge applies to
    pub domain: String,
    /// Type of knowledge
    pub packet_type: PacketType,
    /// Viral score: how rapidly this should spread (0.0 — 1.0)
    pub viral_score: f64,
    /// Number of agents that have received this packet
    pub diffusion_count: u32,
    /// Maximum hop count (prevents infinite propagation)
    pub max_hops: u32,
    /// Current hop count
    pub current_hops: u32,
    /// Timestamp of creation
    pub created_at: String,
    /// Agents that have already received this packet
    pub received_by: Vec<String>,
}

/// Type of diffusible knowledge
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PacketType {
    /// A successful pattern that others should replicate
    SuccessPattern,
    /// A failure insight that others should learn from
    FailureInsight,
    /// A new technique or approach discovered
    Innovation,
    /// An urgent warning about a failure mode
    Warning,
}

/// Viral score factors for computing diffusion velocity
#[derive(Debug, Clone)]
pub struct ViralScoreFactors {
    /// How novel is this knowledge? (0.0 = well-known, 1.0 = completely new)
    pub novelty: f64,
    /// How widely applicable? (0.0 = niche, 1.0 = universal)
    pub applicability: f64,
    /// How urgent is dissemination? (0.0 = informational, 1.0 = critical)
    pub urgency: f64,
    /// Success rate of the underlying pattern
    pub success_rate: f64,
}

impl ViralScoreFactors {
    /// Compute composite viral score
    pub fn compute(&self) -> f64 {
        let raw = self.novelty * 0.3
            + self.applicability * 0.3
            + self.urgency * 0.2
            + self.success_rate * 0.2;
        raw.clamp(0.0, 1.0)
    }
}

/// The Viral Diffusion Engine manages knowledge propagation
pub struct DiffusionEngine {
    /// Active packets in the diffusion network
    packets: HashMap<String, DiffusionPacket>,
    /// Diffusion threshold: packets below this score are not propagated
    threshold: f64,
    /// Default maximum hops
    default_max_hops: u32,
    /// Total packets ever created
    total_created: u64,
    /// Total successful diffusions
    total_diffusions: u64,
}

impl Default for DiffusionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DiffusionEngine {
    /// Create a new diffusion engine with default settings
    pub fn new() -> Self {
        Self {
            packets: HashMap::new(),
            threshold: 0.3,
            default_max_hops: 5,
            total_created: 0,
            total_diffusions: 0,
        }
    }

    /// Set the viral score threshold for diffusion
    pub fn set_threshold(&mut self, threshold: f64) {
        self.threshold = threshold.clamp(0.0, 1.0);
    }

    /// Create a new diffusion packet from a success pattern
    pub fn create_success_packet(
        &mut self,
        origin_agent: &str,
        content: &str,
        domain: &str,
        success_rate: f64,
    ) -> DiffusionPacket {
        let factors = ViralScoreFactors {
            novelty: 0.7,
            applicability: if domain == "general" { 0.9 } else { 0.5 },
            urgency: 0.3,
            success_rate,
        };
        self.create_packet(
            origin_agent,
            content,
            domain,
            PacketType::SuccessPattern,
            factors,
        )
    }

    /// Create a new diffusion packet from a failure insight
    pub fn create_failure_packet(
        &mut self,
        origin_agent: &str,
        content: &str,
        domain: &str,
    ) -> DiffusionPacket {
        let factors = ViralScoreFactors {
            novelty: 0.8,
            applicability: 0.6,
            urgency: 0.7,
            success_rate: 0.0,
        };
        self.create_packet(
            origin_agent,
            content,
            domain,
            PacketType::FailureInsight,
            factors,
        )
    }

    /// Create a new diffusion packet from an innovation
    pub fn create_innovation_packet(
        &mut self,
        origin_agent: &str,
        content: &str,
        domain: &str,
    ) -> DiffusionPacket {
        let factors = ViralScoreFactors {
            novelty: 1.0,
            applicability: 0.7,
            urgency: 0.4,
            success_rate: 0.5,
        };
        self.create_packet(
            origin_agent,
            content,
            domain,
            PacketType::Innovation,
            factors,
        )
    }

    /// Create a warning packet (high urgency)
    pub fn create_warning_packet(
        &mut self,
        origin_agent: &str,
        content: &str,
        domain: &str,
    ) -> DiffusionPacket {
        let factors = ViralScoreFactors {
            novelty: 0.5,
            applicability: 0.9,
            urgency: 1.0,
            success_rate: 0.0,
        };
        self.create_packet(origin_agent, content, domain, PacketType::Warning, factors)
    }

    /// Internal: create a packet with computed viral score
    fn create_packet(
        &mut self,
        origin_agent: &str,
        content: &str,
        domain: &str,
        packet_type: PacketType,
        factors: ViralScoreFactors,
    ) -> DiffusionPacket {
        self.total_created += 1;
        let id = format!("diff-{}", self.total_created);

        let packet = DiffusionPacket {
            id: id.clone(),
            origin_agent: origin_agent.to_string(),
            content: content.to_string(),
            domain: domain.to_string(),
            packet_type,
            viral_score: factors.compute(),
            diffusion_count: 0,
            max_hops: self.default_max_hops,
            current_hops: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            received_by: vec![origin_agent.to_string()],
        };

        self.packets.insert(id, packet.clone());
        packet
    }

    /// Attempt to diffuse a packet to a target agent
    /// Returns true if the packet was accepted (not already received, below max hops)
    pub fn diffuse_to(&mut self, packet_id: &str, target_agent: &str) -> bool {
        let packet = match self.packets.get_mut(packet_id) {
            Some(p) => p,
            None => return false,
        };

        // Check if already received
        if packet.received_by.contains(&target_agent.to_string()) {
            return false;
        }

        // Check hop limit
        if packet.current_hops >= packet.max_hops {
            return false;
        }

        // Check viral threshold
        if packet.viral_score < self.threshold {
            return false;
        }

        packet.received_by.push(target_agent.to_string());
        packet.diffusion_count += 1;
        packet.current_hops += 1;
        self.total_diffusions += 1;
        true
    }

    /// Get packets that should be diffused to a given agent
    /// (packets they haven't received yet, above threshold, within hop limit)
    pub fn pending_for_agent(&self, agent_id: &str) -> Vec<&DiffusionPacket> {
        self.packets
            .values()
            .filter(|p| {
                !p.received_by.contains(&agent_id.to_string())
                    && p.current_hops < p.max_hops
                    && p.viral_score >= self.threshold
            })
            .collect()
    }

    /// Get all active packets
    pub fn active_packets(&self) -> Vec<&DiffusionPacket> {
        self.packets.values().collect()
    }

    /// Get packets sorted by viral score (most viral first)
    pub fn top_viral(&self, limit: usize) -> Vec<&DiffusionPacket> {
        let mut packets: Vec<&DiffusionPacket> = self.packets.values().collect();
        packets.sort_by(|a, b| {
            b.viral_score
                .partial_cmp(&a.viral_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        packets.truncate(limit);
        packets
    }

    /// Engine statistics
    pub fn stats(&self) -> DiffusionStats {
        let active = self.packets.len();
        let total_diffusions = self.total_diffusions;
        let avg_viral = if active > 0 {
            self.packets.values().map(|p| p.viral_score).sum::<f64>() / active as f64
        } else {
            0.0
        };
        let max_viral = self
            .packets
            .values()
            .map(|p| p.viral_score)
            .fold(0.0_f64, f64::max);

        DiffusionStats {
            active_packets: active,
            total_created: self.total_created,
            total_diffusions,
            avg_viral_score: avg_viral,
            max_viral_score: max_viral,
            threshold: self.threshold,
        }
    }
}

/// Diffusion engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffusionStats {
    pub active_packets: usize,
    pub total_created: u64,
    pub total_diffusions: u64,
    pub avg_viral_score: f64,
    pub max_viral_score: f64,
    pub threshold: f64,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_success_packet() {
        let mut engine = DiffusionEngine::new();
        let packet =
            engine.create_success_packet("agent-a", "Pattern X works well", "business", 0.9);
        assert!(!packet.id.is_empty());
        assert_eq!(packet.origin_agent, "agent-a");
        assert!(packet.viral_score > 0.0);
        assert_eq!(packet.packet_type, PacketType::SuccessPattern);
    }

    #[test]
    fn test_create_failure_packet() {
        let mut engine = DiffusionEngine::new();
        let packet = engine.create_failure_packet("agent-b", "API timeout issue", "infrastructure");
        assert_eq!(packet.packet_type, PacketType::FailureInsight);
        assert!(packet.viral_score > 0.3); // Should be above default threshold
    }

    #[test]
    fn test_diffuse_to_agent() {
        let mut engine = DiffusionEngine::new();
        let packet = engine.create_success_packet("agent-a", "Good pattern", "general", 0.8);

        assert!(engine.diffuse_to(&packet.id, "agent-b"));
        assert!(!engine.diffuse_to(&packet.id, "agent-b")); // Duplicate rejected
        assert!(!engine.diffuse_to(&packet.id, "agent-a")); // Origin already has it
    }

    #[test]
    fn test_hop_limit() {
        let mut engine = DiffusionEngine::new();
        engine.default_max_hops = 2;
        let packet = engine.create_success_packet("agent-a", "Limited hops", "general", 0.9);

        assert!(engine.diffuse_to(&packet.id, "agent-b"));
        assert!(engine.diffuse_to(&packet.id, "agent-c"));
        assert!(!engine.diffuse_to(&packet.id, "agent-d")); // Exceeded max hops
    }

    #[test]
    fn test_threshold_filter() {
        let mut engine = DiffusionEngine::new();
        engine.set_threshold(0.95); // Very high threshold
        let packet = engine.create_success_packet("agent-a", "Normal pattern", "niche", 0.1);

        // Viral score should be below threshold
        assert!(!engine.diffuse_to(&packet.id, "agent-b"));
    }

    #[test]
    fn test_pending_for_agent() {
        let mut engine = DiffusionEngine::new();
        engine.create_success_packet("agent-a", "Pattern 1", "general", 0.9);
        engine.create_failure_packet("agent-b", "Failure 1", "general");

        let pending = engine.pending_for_agent("agent-c");
        assert_eq!(pending.len(), 2); // Both packets pending for agent-c
    }

    #[test]
    fn test_top_viral() {
        let mut engine = DiffusionEngine::new();
        engine.create_success_packet("a", "Low viral", "niche", 0.1);
        engine.create_warning_packet("b", "High urgency!", "general");

        let top = engine.top_viral(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].packet_type, PacketType::Warning);
    }

    #[test]
    fn test_viral_score_computation() {
        let factors = ViralScoreFactors {
            novelty: 1.0,
            applicability: 1.0,
            urgency: 1.0,
            success_rate: 1.0,
        };
        assert!((factors.compute() - 1.0).abs() < f64::EPSILON);

        let zero = ViralScoreFactors {
            novelty: 0.0,
            applicability: 0.0,
            urgency: 0.0,
            success_rate: 0.0,
        };
        assert!((zero.compute() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_stats() {
        let mut engine = DiffusionEngine::new();
        engine.create_success_packet("a", "p1", "general", 0.9);
        engine.create_failure_packet("b", "f1", "general");

        let stats = engine.stats();
        assert_eq!(stats.active_packets, 2);
        assert_eq!(stats.total_created, 2);
        assert!(stats.avg_viral_score > 0.0);
    }

    #[test]
    fn test_innovation_packet() {
        let mut engine = DiffusionEngine::new();
        let packet = engine.create_innovation_packet("agent-x", "New approach", "ml");
        assert_eq!(packet.packet_type, PacketType::Innovation);
        assert!(packet.viral_score > 0.5); // Innovations should have high novelty
    }
}

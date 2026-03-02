//! Blockchain anchoring for activity log integrity.
//!
//! Anchors batches of [`ActivityEntry`] records on-chain by computing a
//! Merkle root and storing it via the multi-chain client. Supports
//! per-entry Merkle proof verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use tracing::info;
use uuid::Uuid;

use crate::activity_log::ActivityEntry;

// ─── Anchor Policy ────────────────────────────────────────

/// Configuration for automatic anchoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorPolicy {
    /// Minimum importance level to anchor (0-3)
    pub min_importance: u8,
    /// Activity types that are always anchored (e.g. "decision")
    pub anchor_types: Vec<String>,
    /// Number of entries per anchor batch
    pub batch_size: usize,
    /// Maximum seconds between anchors
    pub interval_secs: u64,
    /// Primary chain to use (e.g. "sui", "eth", "sol")
    pub primary_chain: String,
}

impl Default for AnchorPolicy {
    fn default() -> Self {
        Self {
            min_importance: 2,
            anchor_types: vec!["decision".to_string()],
            batch_size: 100,
            interval_secs: 3600,
            primary_chain: "sui".to_string(),
        }
    }
}

// ─── Merkle Tree ──────────────────────────────────────────

/// A simple binary Merkle tree for anchoring.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Leaf hashes (SHA-256 of each entry)
    leaves: Vec<[u8; 32]>,
    /// Tree layers (bottom-up). Last element is root.
    layers: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a Merkle tree from activity entry hashes.
    pub fn from_entries(entries: &[ActivityEntry]) -> Self {
        let leaves: Vec<[u8; 32]> = entries
            .iter()
            .map(|e| {
                let mut hasher = Sha256::new();
                hasher.update(e.hash.as_bytes());
                hasher.update(e.id.as_bytes());
                let result = hasher.finalize();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&result);
                arr
            })
            .collect();

        let layers = Self::build_layers(&leaves);
        Self { leaves, layers }
    }

    /// Build from raw hashes.
    pub fn from_hashes(hashes: &[[u8; 32]]) -> Self {
        let leaves = hashes.to_vec();
        let layers = Self::build_layers(&leaves);
        Self { leaves, layers }
    }

    fn build_layers(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
        if leaves.is_empty() {
            return vec![vec![]];
        }

        let mut layers = vec![leaves.to_vec()];
        let mut current = leaves.to_vec();

        while current.len() > 1 {
            let mut next = Vec::new();
            for chunk in current.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(chunk[1]);
                } else {
                    // Odd leaf — duplicate
                    hasher.update(chunk[0]);
                }
                let result = hasher.finalize();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&result);
                next.push(arr);
            }
            layers.push(next.clone());
            current = next;
        }

        layers
    }

    /// Get the Merkle root hash.
    pub fn root(&self) -> [u8; 32] {
        if self.layers.is_empty() || self.layers.last().unwrap().is_empty() {
            [0u8; 32]
        } else {
            *self.layers.last().unwrap().first().unwrap()
        }
    }

    /// Get the Merkle root as hex string.
    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    /// Generate a Merkle proof for the entry at `index`.
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut directions = Vec::new();
        let mut idx = index;

        for layer in &self.layers[..self.layers.len().saturating_sub(1)] {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            let sibling = if sibling_idx < layer.len() {
                layer[sibling_idx]
            } else {
                layer[idx] // duplicate for odd
            };
            siblings.push(sibling);
            directions.push(idx.is_multiple_of(2)); // true = left, false = right
            idx /= 2;
        }

        Some(MerkleProof {
            leaf: self.leaves[index],
            siblings,
            directions,
            root: self.root(),
        })
    }

    /// Number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
}

/// A Merkle inclusion proof for a single entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The leaf hash
    pub leaf: [u8; 32],
    /// Sibling hashes along the path
    pub siblings: Vec<[u8; 32]>,
    /// Direction flags: true = leaf is on left, false = leaf is on right
    pub directions: Vec<bool>,
    /// Expected root
    pub root: [u8; 32],
}

impl MerkleProof {
    /// Verify this proof leads to the expected root.
    pub fn verify(&self) -> bool {
        let mut current = self.leaf;

        for (sibling, is_left) in self.siblings.iter().zip(self.directions.iter()) {
            let mut hasher = Sha256::new();
            if *is_left {
                hasher.update(current);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(current);
            }
            let result = hasher.finalize();
            current.copy_from_slice(&result);
        }

        current == self.root
    }
}

// ─── Anchor Record ────────────────────────────────────────

/// Record of an on-chain anchor event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorRecord {
    /// Unique anchor ID
    pub id: Uuid,
    /// Merkle root hash (hex)
    pub merkle_root: String,
    /// Number of entries in this batch
    pub entry_count: usize,
    /// Entry IDs included in this anchor
    pub entry_ids: Vec<Uuid>,
    /// Chain used (e.g. "sui")
    pub chain: String,
    /// Transaction digest/hash (hex)
    pub tx_digest: String,
    /// When the anchor was created
    pub anchored_at: chrono::DateTime<chrono::Utc>,
}

// ─── Activity Anchor ──────────────────────────────────────

/// Manages periodic on-chain anchoring of activity entries.
pub struct ActivityAnchor {
    policy: AnchorPolicy,
    pending: VecDeque<ActivityEntry>,
    anchors: Vec<AnchorRecord>,
}

impl ActivityAnchor {
    /// Create a new anchor manager with the given policy.
    pub fn new(policy: AnchorPolicy) -> Self {
        Self {
            policy,
            pending: VecDeque::new(),
            anchors: Vec::new(),
        }
    }

    /// Add an entry to the pending queue (if it meets the anchor policy).
    pub fn maybe_queue(&mut self, entry: &ActivityEntry) -> bool {
        let dominated_by_importance = entry.importance >= self.policy.min_importance;
        let dominated_by_type = self
            .policy
            .anchor_types
            .contains(&entry.activity_type.type_tag().to_string());

        if dominated_by_importance || dominated_by_type {
            self.pending.push_back(entry.clone());
            true
        } else {
            false
        }
    }

    /// Check if a batch anchor should be triggered.
    pub fn should_anchor(&self) -> bool {
        self.pending.len() >= self.policy.batch_size
    }

    /// Create an anchor batch from pending entries.
    ///
    /// Returns the Merkle root and the entries included. The actual
    /// on-chain transaction is handled by the caller (MultiChainClient).
    pub fn prepare_batch(&mut self) -> Option<(String, Vec<ActivityEntry>)> {
        if self.pending.is_empty() {
            return None;
        }

        let batch_size = self.policy.batch_size.min(self.pending.len());
        let batch: Vec<ActivityEntry> = self.pending.drain(..batch_size).collect();
        let tree = MerkleTree::from_entries(&batch);
        let root = tree.root_hex();

        info!(
            entries = batch.len(),
            root = %root,
            "Anchor batch prepared"
        );

        Some((root, batch))
    }

    /// Record a completed anchor.
    pub fn record_anchor(
        &mut self,
        merkle_root: String,
        entry_ids: Vec<Uuid>,
        chain: &str,
        tx_digest: &str,
    ) {
        self.anchors.push(AnchorRecord {
            id: Uuid::new_v4(),
            merkle_root,
            entry_count: entry_ids.len(),
            entry_ids,
            chain: chain.to_string(),
            tx_digest: tx_digest.to_string(),
            anchored_at: chrono::Utc::now(),
        });
    }

    /// Get all anchor records.
    pub fn anchors(&self) -> &[AnchorRecord] {
        &self.anchors
    }

    /// Get pending queue length.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Get the policy.
    pub fn policy(&self) -> &AnchorPolicy {
        &self.policy
    }

    /// Check if auto-anchor should trigger based on elapsed time.
    pub fn should_anchor_by_time(&self, last_anchor_secs_ago: u64) -> bool {
        !self.pending.is_empty() && last_anchor_secs_ago >= self.policy.interval_secs
    }

    /// Convenience: verify a single entry against an anchor record.
    ///
    /// Rebuilds the Merkle tree from the anchor's entries and checks
    /// whether the given entry can be proven.
    pub fn verify_entry(
        &self,
        entry: &ActivityEntry,
        anchor: &AnchorRecord,
        all_entries: &[ActivityEntry],
    ) -> bool {
        // Collect entries that belong to this anchor
        let batch: Vec<&ActivityEntry> = all_entries
            .iter()
            .filter(|e| anchor.entry_ids.contains(&e.id))
            .collect();

        if batch.is_empty() {
            return false;
        }

        // Find the entry's index in the anchor batch
        let entry_idx = batch.iter().position(|e| e.id == entry.id);
        let Some(idx) = entry_idx else {
            return false;
        };

        let owned_batch: Vec<ActivityEntry> = batch.into_iter().cloned().collect();
        let tree = MerkleTree::from_entries(&owned_batch);

        // Verify root matches anchor record
        if tree.root_hex() != anchor.merkle_root {
            return false;
        }

        // Verify Merkle proof
        tree.proof(idx).map(|p| p.verify()).unwrap_or(false)
    }

    /// Select the chain to use for anchoring, respecting the configuration
    /// priority. Returns the primary chain from the policy.
    pub fn select_chain(&self, available_chains: &[&str]) -> String {
        // If the configured primary chain is available, use it
        if available_chains.contains(&self.policy.primary_chain.as_str()) {
            return self.policy.primary_chain.clone();
        }
        // Otherwise, pick the first available chain
        available_chains
            .first()
            .map(|c| c.to_string())
            .unwrap_or_else(|| self.policy.primary_chain.clone())
    }

    /// Check whether an automatic anchor should be triggered based on
    /// both batch size and elapsed time. This is the main scheduling
    /// decision method.
    pub fn should_auto_anchor(&self, last_anchor_secs_ago: u64) -> bool {
        self.should_anchor() || self.should_anchor_by_time(last_anchor_secs_ago)
    }
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity_log::ActivityType;
    use chrono::Utc;

    fn make_entry(content: &str, importance: u8, type_tag: &str) -> ActivityEntry {
        let activity_type = match type_tag {
            "decision" => ActivityType::Decision {
                title: "test".into(),
                chosen: "A".into(),
                rationale: "because".into(),
                alternatives: vec!["B".into()],
            },
            _ => ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 1,
            },
        };
        ActivityEntry {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            agent_id: "dev-1".into(),
            agent_role: "admin".into(),
            agent_name: "agent-1".into(),
            activity_type,
            project: "edgeclaw".into(),
            file_path: None,
            content: content.into(),
            tags: vec![],
            importance,
            timestamp: Utc::now(),
            lamport_clock: 1,
            prev_hash: "0".repeat(64),
            hash: format!("hash_{}", content),
            signature: String::new(),
        }
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let entries = vec![make_entry("one", 2, "file_edit")];
        let tree = MerkleTree::from_entries(&entries);
        assert_eq!(tree.leaf_count(), 1);
        assert_ne!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_merkle_tree_even_leaves() {
        let entries = vec![
            make_entry("a", 2, "file_edit"),
            make_entry("b", 2, "file_edit"),
            make_entry("c", 2, "file_edit"),
            make_entry("d", 2, "file_edit"),
        ];
        let tree = MerkleTree::from_entries(&entries);
        assert_eq!(tree.leaf_count(), 4);
        assert!(!tree.root_hex().is_empty());
    }

    #[test]
    fn test_merkle_tree_odd_leaves() {
        let entries = vec![
            make_entry("a", 2, "file_edit"),
            make_entry("b", 2, "file_edit"),
            make_entry("c", 2, "file_edit"),
        ];
        let tree = MerkleTree::from_entries(&entries);
        assert_eq!(tree.leaf_count(), 3);
    }

    #[test]
    fn test_merkle_proof_verify() {
        let entries = vec![
            make_entry("a", 2, "file_edit"),
            make_entry("b", 2, "file_edit"),
            make_entry("c", 2, "file_edit"),
            make_entry("d", 2, "file_edit"),
        ];
        let tree = MerkleTree::from_entries(&entries);

        for i in 0..entries.len() {
            let proof = tree.proof(i).unwrap();
            assert!(proof.verify(), "Proof failed for index {}", i);
        }
    }

    #[test]
    fn test_merkle_proof_invalid_index() {
        let entries = vec![make_entry("a", 2, "file_edit")];
        let tree = MerkleTree::from_entries(&entries);
        assert!(tree.proof(5).is_none());
    }

    #[test]
    fn test_merkle_proof_tampered() {
        let entries = vec![
            make_entry("a", 2, "file_edit"),
            make_entry("b", 2, "file_edit"),
        ];
        let tree = MerkleTree::from_entries(&entries);

        let mut proof = tree.proof(0).unwrap();
        proof.leaf = [0xFFu8; 32]; // tamper
        assert!(!proof.verify());
    }

    #[test]
    fn test_anchor_policy_filtering() {
        let mut anchor = ActivityAnchor::new(AnchorPolicy::default());

        // Low importance, non-decision → should NOT be queued
        let e1 = make_entry("noise", 0, "file_edit");
        assert!(!anchor.maybe_queue(&e1));

        // High importance → should be queued
        let e2 = make_entry("important fix", 2, "file_edit");
        assert!(anchor.maybe_queue(&e2));

        // Decision type → should be queued regardless of importance
        let e3 = make_entry("chose CBOR", 0, "decision");
        assert!(anchor.maybe_queue(&e3));

        assert_eq!(anchor.pending_count(), 2);
    }

    #[test]
    fn test_anchor_batch_trigger() {
        let policy = AnchorPolicy {
            batch_size: 3,
            ..Default::default()
        };
        let mut anchor = ActivityAnchor::new(policy);

        for i in 0..3 {
            let e = make_entry(&format!("entry {}", i), 2, "file_edit");
            anchor.maybe_queue(&e);
        }

        assert!(anchor.should_anchor());
        let (root, batch) = anchor.prepare_batch().unwrap();
        assert_eq!(batch.len(), 3);
        assert!(!root.is_empty());
        assert_eq!(anchor.pending_count(), 0);
    }

    #[test]
    fn test_empty_batch_returns_none() {
        let mut anchor = ActivityAnchor::new(AnchorPolicy::default());
        assert!(anchor.prepare_batch().is_none());
    }

    #[test]
    fn test_anchor_record() {
        let mut anchor = ActivityAnchor::new(AnchorPolicy::default());
        let ids = vec![Uuid::new_v4(), Uuid::new_v4()];
        anchor.record_anchor("root123".into(), ids.clone(), "sui", "tx_abc");

        assert_eq!(anchor.anchors().len(), 1);
        assert_eq!(anchor.anchors()[0].chain, "sui");
        assert_eq!(anchor.anchors()[0].entry_count, 2);
    }

    #[test]
    fn test_anchor_config_serialization() {
        let policy = AnchorPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: AnchorPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.batch_size, 100);
        assert_eq!(decoded.primary_chain, "sui");
    }

    #[test]
    fn test_should_anchor_by_time() {
        let policy = AnchorPolicy {
            interval_secs: 3600,
            ..Default::default()
        };
        let mut anchor = ActivityAnchor::new(policy);

        // Empty pending → false regardless of time
        assert!(!anchor.should_anchor_by_time(9999));

        // Add entry
        let e = make_entry("important", 2, "file_edit");
        anchor.maybe_queue(&e);

        // Not enough time → false
        assert!(!anchor.should_anchor_by_time(1800));

        // Enough time → true
        assert!(anchor.should_anchor_by_time(3600));
        assert!(anchor.should_anchor_by_time(7200));
    }

    #[test]
    fn test_verify_entry_against_anchor() {
        let entries = vec![
            make_entry("a", 2, "file_edit"),
            make_entry("b", 2, "file_edit"),
            make_entry("c", 2, "file_edit"),
        ];

        let tree = MerkleTree::from_entries(&entries);
        let anchor_record = AnchorRecord {
            id: Uuid::new_v4(),
            merkle_root: tree.root_hex(),
            entry_count: entries.len(),
            entry_ids: entries.iter().map(|e| e.id).collect(),
            chain: "sui".into(),
            tx_digest: "tx_test".into(),
            anchored_at: Utc::now(),
        };

        let anchor = ActivityAnchor::new(AnchorPolicy::default());

        // Valid entry verification
        assert!(anchor.verify_entry(&entries[0], &anchor_record, &entries));
        assert!(anchor.verify_entry(&entries[1], &anchor_record, &entries));
        assert!(anchor.verify_entry(&entries[2], &anchor_record, &entries));

        // Entry not in anchor → false
        let outside = make_entry("outside", 2, "file_edit");
        assert!(!anchor.verify_entry(&outside, &anchor_record, &entries));
    }

    #[test]
    fn test_select_chain_primary_available() {
        let policy = AnchorPolicy {
            primary_chain: "sui".into(),
            ..Default::default()
        };
        let anchor = ActivityAnchor::new(policy);
        let chain = anchor.select_chain(&["eth", "sui", "sol"]);
        assert_eq!(chain, "sui");
    }

    #[test]
    fn test_select_chain_primary_unavailable() {
        let policy = AnchorPolicy {
            primary_chain: "sui".into(),
            ..Default::default()
        };
        let anchor = ActivityAnchor::new(policy);
        let chain = anchor.select_chain(&["eth", "sol"]);
        assert_eq!(chain, "eth", "should fall back to first available");
    }

    #[test]
    fn test_should_auto_anchor_by_batch() {
        let policy = AnchorPolicy {
            batch_size: 2,
            interval_secs: 9999,
            ..Default::default()
        };
        let mut anchor = ActivityAnchor::new(policy);
        anchor.maybe_queue(&make_entry("a", 3, "file_edit"));
        anchor.maybe_queue(&make_entry("b", 3, "file_edit"));

        // Batch full → auto-anchor even though not enough time
        assert!(anchor.should_auto_anchor(0));
    }

    #[test]
    fn test_should_auto_anchor_by_time() {
        let policy = AnchorPolicy {
            batch_size: 999,
            interval_secs: 100,
            ..Default::default()
        };
        let mut anchor = ActivityAnchor::new(policy);
        anchor.maybe_queue(&make_entry("a", 3, "file_edit"));

        // Not enough entries for batch, but enough time passed
        assert!(!anchor.should_auto_anchor(50));
        assert!(anchor.should_auto_anchor(100));
    }
}

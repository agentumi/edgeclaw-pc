//! Audit logging with hash-chained integrity.
//!
//! Every operation is logged with a SHA-256 hash chain, making the audit trail
//! tamper-evident. If any entry is modified or deleted, the chain breaks.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use tracing::info;

/// A single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence number
    pub sequence: u64,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Device ID that performed the action
    pub device_id: String,
    /// Role of the actor
    pub actor_role: String,
    /// Capability invoked
    pub capability: String,
    /// Command or action description
    pub action: String,
    /// Result (success/failure)
    pub result: String,
    /// Additional details
    pub details: Option<String>,
    /// SHA-256 hash of previous entry
    pub prev_hash: String,
    /// SHA-256 hash of this entry
    pub hash: String,
}

/// Hash-chained audit log
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    current_sequence: u64,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog {
    /// Create a new empty audit log
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            current_sequence: 0,
        }
    }

    /// Add an entry to the audit log
    pub fn log(
        &mut self,
        device_id: &str,
        actor_role: &str,
        capability: &str,
        action: &str,
        result: &str,
        details: Option<&str>,
    ) -> AuditEntry {
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        self.current_sequence += 1;

        let mut entry = AuditEntry {
            sequence: self.current_sequence,
            timestamp: Utc::now().to_rfc3339(),
            device_id: device_id.to_string(),
            actor_role: actor_role.to_string(),
            capability: capability.to_string(),
            action: action.to_string(),
            result: result.to_string(),
            details: details.map(|s| s.to_string()),
            prev_hash,
            hash: String::new(),
        };

        entry.hash = Self::compute_hash(&entry);
        self.entries.push(entry.clone());

        info!(
            seq = entry.sequence,
            capability = entry.capability,
            result = entry.result,
            "audit: logged"
        );

        entry
    }

    /// Compute SHA-256 hash for an entry
    fn compute_hash(entry: &AuditEntry) -> String {
        let mut hasher = Sha256::new();
        hasher.update(entry.sequence.to_le_bytes());
        hasher.update(entry.timestamp.as_bytes());
        hasher.update(entry.device_id.as_bytes());
        hasher.update(entry.actor_role.as_bytes());
        hasher.update(entry.capability.as_bytes());
        hasher.update(entry.action.as_bytes());
        hasher.update(entry.result.as_bytes());
        if let Some(ref details) = entry.details {
            hasher.update(details.as_bytes());
        }
        hasher.update(entry.prev_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify the integrity of the entire audit chain
    pub fn verify_chain(&self) -> Result<bool, String> {
        if self.entries.is_empty() {
            return Ok(true);
        }

        let genesis_hash = "0".repeat(64);

        for (i, entry) in self.entries.iter().enumerate() {
            // Check sequence
            if entry.sequence != (i as u64 + 1) {
                return Err(format!(
                    "Sequence break at index {}: expected {}, got {}",
                    i,
                    i + 1,
                    entry.sequence
                ));
            }

            // Check prev_hash link
            let expected_prev = if i == 0 {
                &genesis_hash
            } else {
                &self.entries[i - 1].hash
            };
            if entry.prev_hash != *expected_prev {
                return Err(format!(
                    "Chain broken at sequence {}: prev_hash mismatch",
                    entry.sequence
                ));
            }

            // Verify hash
            let computed = Self::compute_hash(entry);
            if entry.hash != computed {
                return Err(format!(
                    "Hash mismatch at sequence {}: entry tampered",
                    entry.sequence
                ));
            }
        }

        Ok(true)
    }

    /// Get all entries
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Get entry count
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get last N entries
    pub fn last_n(&self, n: usize) -> &[AuditEntry] {
        let start = self.entries.len().saturating_sub(n);
        &self.entries[start..]
    }

    /// Export as JSON
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.entries)
    }
}

/// Thread-safe audit log wrapper
pub struct AuditManager {
    log: Mutex<AuditLog>,
}

impl Default for AuditManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditManager {
    /// Create a new audit manager
    pub fn new() -> Self {
        Self {
            log: Mutex::new(AuditLog::new()),
        }
    }

    /// Log an audit entry
    pub fn log(
        &self,
        device_id: &str,
        actor_role: &str,
        capability: &str,
        action: &str,
        result: &str,
        details: Option<&str>,
    ) -> AuditEntry {
        let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.log(device_id, actor_role, capability, action, result, details)
    }

    /// Verify chain integrity
    pub fn verify(&self) -> Result<bool, String> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.verify_chain()
    }

    /// Get entry count
    pub fn count(&self) -> usize {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.len()
    }

    /// Get last N entries
    pub fn last_entries(&self, n: usize) -> Vec<AuditEntry> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.last_n(n).to_vec()
    }

    /// Export full log as JSON
    pub fn export(&self) -> Result<String, serde_json::Error> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.export_json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_log_verification() {
        let log = AuditLog::new();
        assert!(log.verify_chain().unwrap());
        assert!(log.is_empty());
    }

    #[test]
    fn test_single_entry() {
        let mut log = AuditLog::new();
        let entry = log.log("dev-1", "admin", "shell_exec", "ls -la", "success", None);
        assert_eq!(entry.sequence, 1);
        assert_eq!(entry.prev_hash, "0".repeat(64));
        assert!(!entry.hash.is_empty());
        assert!(log.verify_chain().unwrap());
    }

    #[test]
    fn test_chain_integrity() {
        let mut log = AuditLog::new();
        log.log("dev-1", "admin", "shell_exec", "ls", "success", None);
        log.log("dev-1", "admin", "file_read", "/etc/hosts", "success", None);
        log.log("dev-1", "viewer", "status_query", "status", "success", None);

        assert_eq!(log.len(), 3);
        assert!(log.verify_chain().unwrap());

        // Verify chain links
        assert_eq!(log.entries[1].prev_hash, log.entries[0].hash);
        assert_eq!(log.entries[2].prev_hash, log.entries[1].hash);
    }

    #[test]
    fn test_tamper_detection() {
        let mut log = AuditLog::new();
        log.log("dev-1", "admin", "shell_exec", "ls", "success", None);
        log.log("dev-1", "admin", "shell_exec", "rm -rf /", "success", None);

        // Tamper with the second entry
        log.entries[1].action = "echo hello".to_string();

        let result = log.verify_chain();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("tampered"));
    }

    #[test]
    fn test_chain_break_detection() {
        let mut log = AuditLog::new();
        log.log("dev-1", "admin", "a", "b", "ok", None);
        log.log("dev-1", "admin", "c", "d", "ok", None);
        log.log("dev-1", "admin", "e", "f", "ok", None);

        // Break the chain
        log.entries[1].prev_hash = "deadbeef".repeat(8);

        let result = log.verify_chain();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Chain broken"));
    }

    #[test]
    fn test_sequence_break_detection() {
        let mut log = AuditLog::new();
        log.log("dev-1", "admin", "a", "b", "ok", None);
        log.log("dev-1", "admin", "c", "d", "ok", None);

        // Break sequence
        log.entries[1].sequence = 99;

        let result = log.verify_chain();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Sequence break"));
    }

    #[test]
    fn test_audit_manager_thread_safe() {
        let manager = AuditManager::new();
        manager.log("dev-1", "admin", "shell_exec", "ls", "success", None);
        manager.log("dev-1", "admin", "file_read", "/etc", "success", None);

        assert_eq!(manager.count(), 2);
        assert!(manager.verify().unwrap());
    }

    #[test]
    fn test_last_entries() {
        let manager = AuditManager::new();
        for i in 0..10 {
            manager.log("dev-1", "admin", "test", &format!("cmd-{}", i), "ok", None);
        }

        let last_3 = manager.last_entries(3);
        assert_eq!(last_3.len(), 3);
        assert_eq!(last_3[0].sequence, 8);
        assert_eq!(last_3[2].sequence, 10);
    }

    #[test]
    fn test_export_json() {
        let manager = AuditManager::new();
        manager.log("dev-1", "admin", "test", "cmd", "ok", Some("details here"));

        let json = manager.export().unwrap();
        assert!(json.contains("dev-1"));
        assert!(json.contains("details here"));
    }

    #[test]
    fn test_details_optional() {
        let mut log = AuditLog::new();
        log.log("dev-1", "admin", "a", "b", "ok", None);
        log.log("dev-1", "admin", "a", "b", "ok", Some("extra info"));
        assert!(log.verify_chain().unwrap());
    }
}

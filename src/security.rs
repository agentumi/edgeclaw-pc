//! Security module — Rate limiting, input sanitization, and connection security.
//!
//! Implements STRIDE mitigations:
//! - **Spoofing**: Identity verification enforced at session layer
//! - **Tampering**: AES-256-GCM integrity + audit hash chain
//! - **Repudiation**: Hash-chained audit log (audit.rs)
//! - **Information Disclosure**: Sensitive keyword filtering (ai.rs)
//! - **Denial of Service**: Rate limiting + connection limits (this module)
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
        let dangerous_patterns = [
            "$(", "`", "&&", "||", ";", "|", ">", "<", ">>", "<<", "\\n", "\n", "\r", "../", "..\\",
        ];

        for pattern in &dangerous_patterns {
            if input.contains(pattern) {
                return true;
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
}

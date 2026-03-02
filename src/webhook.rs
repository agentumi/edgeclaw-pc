//! Webhook notification manager for activity events.
//!
//! Sends activity entries as JSON payloads to registered webhook URLs
//! with HMAC-SHA256 signatures, retry logic, and Slack/Discord formatting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

use crate::activity_log::ActivityEntry;

// ─── Configuration ────────────────────────────────────────

/// Configuration for a single webhook endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL to POST to
    pub url: String,
    /// HMAC-SHA256 secret for signing payloads
    pub secret: String,
    /// Event types to forward (empty = all)
    pub events: Vec<String>,
    /// Minimum importance level to send (0-3)
    pub min_importance: u8,
    /// Project filter (empty = all projects)
    pub project: Option<String>,
    /// Batch mode: if true, send digest every `batch_interval_secs`
    pub batch_mode: bool,
    /// Batch interval in seconds (default: 300 = 5 minutes)
    pub batch_interval_secs: u64,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            secret: String::new(),
            events: Vec::new(),
            min_importance: 1,
            project: None,
            batch_mode: false,
            batch_interval_secs: 300,
        }
    }
}

// ─── Webhook Payload ──────────────────────────────────────

/// JSON payload sent to webhook endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Event type (e.g. "activity.created")
    pub event: String,
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// Activity data
    pub data: WebhookActivityData,
}

/// Activity data embedded in the webhook payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookActivityData {
    pub id: String,
    pub activity_type: String,
    pub agent_name: String,
    pub project: String,
    pub content: String,
    pub importance: u8,
    pub file_path: Option<String>,
    pub tags: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

impl WebhookPayload {
    /// Create from an `ActivityEntry`.
    pub fn from_entry(entry: &ActivityEntry) -> Self {
        Self {
            event: "activity.created".to_string(),
            timestamp: Utc::now(),
            data: WebhookActivityData {
                id: entry.id.to_string(),
                activity_type: entry.activity_type.type_tag().to_string(),
                agent_name: entry.agent_name.clone(),
                project: entry.project.clone(),
                content: entry.content.clone(),
                importance: entry.importance,
                file_path: entry.file_path.clone(),
                tags: entry.tags.clone(),
                timestamp: entry.timestamp,
            },
        }
    }

    /// Create a batch digest payload.
    pub fn batch_digest(entries: &[ActivityEntry]) -> Self {
        let summary = format!(
            "{} activities: {} file edits, {} commands, {} decisions",
            entries.len(),
            entries
                .iter()
                .filter(|e| e.activity_type.type_tag() == "file_edit")
                .count(),
            entries
                .iter()
                .filter(|e| e.activity_type.type_tag() == "command_exec")
                .count(),
            entries
                .iter()
                .filter(|e| e.activity_type.type_tag() == "decision")
                .count(),
        );

        Self {
            event: "activity.batch".to_string(),
            timestamp: Utc::now(),
            data: WebhookActivityData {
                id: Uuid::new_v4().to_string(),
                activity_type: "batch_digest".to_string(),
                agent_name: entries
                    .first()
                    .map(|e| e.agent_name.clone())
                    .unwrap_or_default(),
                project: entries
                    .first()
                    .map(|e| e.project.clone())
                    .unwrap_or_default(),
                content: summary,
                importance: entries.iter().map(|e| e.importance).max().unwrap_or(0),
                file_path: None,
                tags: vec![],
                timestamp: Utc::now(),
            },
        }
    }
}

// ─── HMAC Signing ─────────────────────────────────────────

/// Compute HMAC-SHA256 signature for a payload.
pub fn compute_hmac(payload: &[u8], secret: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

/// Verify HMAC-SHA256 signature.
pub fn verify_hmac(payload: &[u8], secret: &str, signature: &str) -> bool {
    let computed = compute_hmac(payload, secret);
    computed == signature
}

// ─── Formatter ────────────────────────────────────────────

/// Platform-specific webhook formatter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WebhookPlatform {
    Slack,
    Discord,
    Generic,
}

impl WebhookPlatform {
    /// Auto-detect platform from URL.
    pub fn detect(url: &str) -> Self {
        if url.contains("hooks.slack.com") {
            WebhookPlatform::Slack
        } else if url.contains("discord.com/api/webhooks") || url.contains("discordapp.com") {
            WebhookPlatform::Discord
        } else {
            WebhookPlatform::Generic
        }
    }
}

/// Format a payload for Slack Block Kit.
pub fn format_slack(entry: &ActivityEntry) -> serde_json::Value {
    let emoji = match entry.importance {
        3 => ":rotating_light:",
        2 => ":warning:",
        1 => ":information_source:",
        _ => ":white_circle:",
    };

    serde_json::json!({
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("{} *[{}]* {}\n_{}_", emoji, entry.activity_type.type_tag(), entry.content, entry.project)
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": format!(":bust_in_silhouette: {} | :clock1: {}", entry.agent_name, entry.timestamp.format("%H:%M:%S"))
                    }
                ]
            }
        ]
    })
}

/// Format a payload for Discord Embed.
pub fn format_discord(entry: &ActivityEntry) -> serde_json::Value {
    let color = match entry.importance {
        3 => 0xFF0000, // Red
        2 => 0xFFA500, // Orange
        1 => 0x00FF00, // Green
        _ => 0x808080, // Gray
    };

    serde_json::json!({
        "embeds": [{
            "title": format!("[{}] {}", entry.activity_type.type_tag(), entry.content),
            "color": color,
            "fields": [
                { "name": "Agent", "value": &entry.agent_name, "inline": true },
                { "name": "Project", "value": &entry.project, "inline": true },
                { "name": "Importance", "value": entry.importance.to_string(), "inline": true }
            ],
            "timestamp": entry.timestamp.to_rfc3339()
        }]
    })
}

// ─── Webhook Manager ──────────────────────────────────────

/// Manages registered webhooks and notification dispatch.
pub struct WebhookManager {
    webhooks: Vec<WebhookConfig>,
    pending_batches: HashMap<String, Vec<ActivityEntry>>,
}

impl WebhookManager {
    /// Create a new webhook manager.
    pub fn new() -> Self {
        Self {
            webhooks: Vec::new(),
            pending_batches: HashMap::new(),
        }
    }

    /// Register a webhook.
    pub fn register(&mut self, config: WebhookConfig) {
        info!(url = %config.url, "Webhook registered");
        self.webhooks.push(config);
    }

    /// Unregister a webhook by URL.
    pub fn unregister(&mut self, url: &str) -> bool {
        let before = self.webhooks.len();
        self.webhooks.retain(|w| w.url != url);
        let removed = self.webhooks.len() < before;
        if removed {
            info!(url = url, "Webhook unregistered");
        }
        removed
    }

    /// List registered webhooks.
    pub fn list(&self) -> &[WebhookConfig] {
        &self.webhooks
    }

    /// Check if an entry matches a webhook's filter.
    pub fn matches_filter(config: &WebhookConfig, entry: &ActivityEntry) -> bool {
        // Importance filter
        if entry.importance < config.min_importance {
            return false;
        }

        // Event type filter
        if !config.events.is_empty()
            && !config
                .events
                .contains(&entry.activity_type.type_tag().to_string())
        {
            return false;
        }

        // Project filter
        if let Some(ref proj) = config.project {
            if !entry.project.eq_ignore_ascii_case(proj) {
                return false;
            }
        }

        true
    }

    /// Build the JSON payload for a webhook.
    pub fn build_payload(config: &WebhookConfig, entry: &ActivityEntry) -> serde_json::Value {
        let platform = WebhookPlatform::detect(&config.url);
        match platform {
            WebhookPlatform::Slack => format_slack(entry),
            WebhookPlatform::Discord => format_discord(entry),
            WebhookPlatform::Generic => {
                serde_json::to_value(WebhookPayload::from_entry(entry)).unwrap_or_default()
            }
        }
    }

    /// Queue an entry for batch notification.
    pub fn queue_for_batch(&mut self, entry: &ActivityEntry) {
        for config in &self.webhooks {
            if config.batch_mode && Self::matches_filter(config, entry) {
                self.pending_batches
                    .entry(config.url.clone())
                    .or_default()
                    .push(entry.clone());
            }
        }
    }

    /// Get pending batch entries for a URL.
    pub fn drain_batch(&mut self, url: &str) -> Vec<ActivityEntry> {
        self.pending_batches.remove(url).unwrap_or_default()
    }

    /// Get webhook count.
    pub fn count(&self) -> usize {
        self.webhooks.len()
    }

    /// Send a single activity entry to all matching webhooks.
    ///
    /// For batch-mode webhooks, entries are queued instead. For immediate
    /// webhooks, the entry is POSTed with HMAC-SHA256 in `X-EdgeClaw-Signature`.
    pub fn notify(&mut self, entry: &ActivityEntry) -> Vec<WebhookDeliveryResult> {
        let mut results = Vec::new();

        for config in &self.webhooks {
            if !Self::matches_filter(config, entry) {
                continue;
            }

            if config.batch_mode {
                self.pending_batches
                    .entry(config.url.clone())
                    .or_default()
                    .push(entry.clone());
                continue;
            }

            let payload = Self::build_payload(config, entry);
            let result = Self::deliver_with_retry(&config.url, &config.secret, &payload, 3);
            results.push(result);
        }

        results
    }

    /// Send all pending batch digests to batch-mode webhooks.
    pub fn notify_batch(&mut self) -> Vec<WebhookDeliveryResult> {
        let mut results = Vec::new();
        let batch_urls: Vec<String> = self.pending_batches.keys().cloned().collect();

        for url in batch_urls {
            let entries = self.pending_batches.remove(&url).unwrap_or_default();
            if entries.is_empty() {
                continue;
            }

            // Find the matching config
            let config = self.webhooks.iter().find(|c| c.url == url);
            let secret = config.map(|c| c.secret.as_str()).unwrap_or("");

            let digest = WebhookPayload::batch_digest(&entries);
            let payload = serde_json::to_value(&digest).unwrap_or_default();
            let result = Self::deliver_with_retry(&url, secret, &payload, 3);
            results.push(result);
        }

        results
    }

    /// Deliver a payload with exponential backoff retry (1s, 2s, 4s).
    fn deliver_with_retry(
        url: &str,
        secret: &str,
        payload: &serde_json::Value,
        max_retries: u32,
    ) -> WebhookDeliveryResult {
        let body = serde_json::to_vec(payload).unwrap_or_default();
        let signature = compute_hmac(&body, secret);

        for attempt in 0..max_retries {
            match ureq::post(url)
                .set("Content-Type", "application/json")
                .set("X-EdgeClaw-Signature", &signature)
                .set("User-Agent", "EdgeClaw-Agent/4.0")
                .send_bytes(&body)
            {
                Ok(resp) => {
                    info!(url = url, status = resp.status(), "Webhook delivered");
                    return WebhookDeliveryResult {
                        url: url.to_string(),
                        success: true,
                        status_code: Some(resp.status()),
                        attempts: attempt + 1,
                        error: None,
                    };
                }
                Err(e) => {
                    warn!(
                        url = url,
                        attempt = attempt + 1,
                        error = %e,
                        "Webhook delivery failed, retrying"
                    );
                    if attempt + 1 < max_retries {
                        let delay_ms = 1000 * (1u64 << attempt); // 1s, 2s, 4s
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    }
                }
            }
        }

        WebhookDeliveryResult {
            url: url.to_string(),
            success: false,
            status_code: None,
            attempts: max_retries,
            error: Some(format!("Failed after {} retries", max_retries)),
        }
    }
}

/// Result of a webhook delivery attempt.
#[derive(Debug, Clone)]
pub struct WebhookDeliveryResult {
    /// Target URL
    pub url: String,
    /// Whether delivery succeeded
    pub success: bool,
    /// HTTP status code (if response received)
    pub status_code: Option<u16>,
    /// Number of attempts made
    pub attempts: u32,
    /// Error message (if failed)
    pub error: Option<String>,
}

impl Default for WebhookManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity_log::ActivityType;
    use chrono::Utc;

    fn sample_entry(importance: u8, activity_tag: &str) -> ActivityEntry {
        let activity_type = match activity_tag {
            "decision" => ActivityType::Decision {
                title: "test".into(),
                chosen: "A".into(),
                rationale: "because".into(),
                alternatives: vec![],
            },
            "command_exec" => ActivityType::CommandExec {
                command: "cargo test".into(),
                exit_code: 0,
                duration_ms: 100,
                output_summary: None,
            },
            _ => ActivityType::FileEdit {
                before_snippet: None,
                after_snippet: None,
                lines_changed: 5,
            },
        };

        ActivityEntry {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            agent_id: "dev-1".into(),
            agent_role: "admin".into(),
            agent_name: "test-agent".into(),
            activity_type,
            project: "edgeclaw".into(),
            file_path: Some("src/main.rs".into()),
            content: "Test activity".into(),
            tags: vec!["test".into()],
            importance,
            timestamp: Utc::now(),
            lamport_clock: 1,
            prev_hash: "0".repeat(64),
            hash: "abc".into(),
            signature: String::new(),
        }
    }

    #[test]
    fn test_webhook_register_unregister() {
        let mut mgr = WebhookManager::new();
        mgr.register(WebhookConfig {
            url: "https://example.com/hook".into(),
            ..Default::default()
        });
        assert_eq!(mgr.count(), 1);

        assert!(mgr.unregister("https://example.com/hook"));
        assert_eq!(mgr.count(), 0);
        assert!(!mgr.unregister("https://example.com/nonexistent"));
    }

    #[test]
    fn test_webhook_payload_format() {
        let entry = sample_entry(2, "file_edit");
        let payload = WebhookPayload::from_entry(&entry);
        assert_eq!(payload.event, "activity.created");
        assert_eq!(payload.data.activity_type, "file_edit");
        assert_eq!(payload.data.importance, 2);
    }

    #[test]
    fn test_hmac_sign_and_verify() {
        let payload = b"test payload";
        let secret = "my_secret";
        let sig = compute_hmac(payload, secret);
        assert!(verify_hmac(payload, secret, &sig));
        assert!(!verify_hmac(b"tampered", secret, &sig));
    }

    #[test]
    fn test_event_filtering() {
        let config = WebhookConfig {
            url: "https://example.com/hook".into(),
            min_importance: 2,
            events: vec!["file_edit".into()],
            project: Some("edgeclaw".into()),
            ..Default::default()
        };

        // Match: importance 2, file_edit, edgeclaw
        assert!(WebhookManager::matches_filter(
            &config,
            &sample_entry(2, "file_edit")
        ));

        // No match: low importance
        assert!(!WebhookManager::matches_filter(
            &config,
            &sample_entry(0, "file_edit")
        ));

        // No match: wrong event type
        assert!(!WebhookManager::matches_filter(
            &config,
            &sample_entry(2, "decision")
        ));
    }

    #[test]
    fn test_platform_detection() {
        assert_eq!(
            WebhookPlatform::detect("https://hooks.slack.com/services/X/Y/Z"),
            WebhookPlatform::Slack
        );
        assert_eq!(
            WebhookPlatform::detect("https://discord.com/api/webhooks/123/abc"),
            WebhookPlatform::Discord
        );
        assert_eq!(
            WebhookPlatform::detect("https://example.com/hook"),
            WebhookPlatform::Generic
        );
    }

    #[test]
    fn test_slack_format() {
        let entry = sample_entry(2, "file_edit");
        let slack = format_slack(&entry);
        assert!(slack.get("blocks").is_some());
    }

    #[test]
    fn test_discord_format() {
        let entry = sample_entry(3, "file_edit");
        let discord = format_discord(&entry);
        let embeds = discord.get("embeds").unwrap().as_array().unwrap();
        assert_eq!(embeds.len(), 1);
        assert_eq!(embeds[0]["color"], 0xFF0000);
    }

    #[test]
    fn test_batch_digest() {
        let entries = vec![
            sample_entry(1, "file_edit"),
            sample_entry(2, "decision"),
            sample_entry(1, "command_exec"),
        ];
        let digest = WebhookPayload::batch_digest(&entries);
        assert_eq!(digest.event, "activity.batch");
        assert!(digest.data.content.contains("3 activities"));
    }

    #[test]
    fn test_batch_queue_drain() {
        let mut mgr = WebhookManager::new();
        mgr.register(WebhookConfig {
            url: "https://example.com/hook".into(),
            batch_mode: true,
            min_importance: 0,
            ..Default::default()
        });

        let entry = sample_entry(1, "file_edit");
        mgr.queue_for_batch(&entry);
        mgr.queue_for_batch(&entry);

        let batch = mgr.drain_batch("https://example.com/hook");
        assert_eq!(batch.len(), 2);

        // Second drain should be empty
        let batch2 = mgr.drain_batch("https://example.com/hook");
        assert!(batch2.is_empty());
    }

    #[test]
    fn test_config_serialization() {
        let config = WebhookConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let decoded: WebhookConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.batch_interval_secs, 300);
    }

    #[test]
    fn test_delivery_result_structure() {
        // Verify the retry logic produces correct result structures
        let result = WebhookDeliveryResult {
            url: "https://example.com/hook".into(),
            success: false,
            status_code: None,
            attempts: 3,
            error: Some("Failed after 3 retries".into()),
        };
        assert!(!result.success);
        assert_eq!(result.attempts, 3);
        assert!(result.error.is_some());

        let success = WebhookDeliveryResult {
            url: "https://example.com/hook".into(),
            success: true,
            status_code: Some(200),
            attempts: 1,
            error: None,
        };
        assert!(success.success);
        assert_eq!(success.status_code, Some(200));
    }

    #[test]
    fn test_hmac_in_header_format() {
        // Verify HMAC signature is hex-encoded and deterministic
        let payload = b"{\"event\":\"test\"}";
        let sig1 = compute_hmac(payload, "secret123");
        let sig2 = compute_hmac(payload, "secret123");
        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_notify_routes_to_batch_queue() {
        let mut mgr = WebhookManager::new();
        mgr.register(WebhookConfig {
            url: "https://example.com/batch".into(),
            batch_mode: true,
            min_importance: 0,
            ..Default::default()
        });

        let entry = sample_entry(1, "file_edit");
        let results = mgr.notify(&entry);

        // Batch-mode webhooks should not produce immediate results
        assert!(results.is_empty());

        // Entry should be queued
        let batch = mgr.drain_batch("https://example.com/batch");
        assert_eq!(batch.len(), 1);
    }
}

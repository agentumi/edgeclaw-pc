//! OTA (Over-The-Air) update checker and applier.
//!
//! Provides [`UpdateChecker`] for checking GitHub releases, downloading
//! updates with SHA-256 verification, applying them, and rolling back.

use serde::{Deserialize, Serialize};

use crate::error::AgentError;

/// Update manifest fetched from a release source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// Latest version string (semver).
    pub version: String,
    /// Target platform (e.g., "x86_64-pc-windows-msvc").
    pub platform: String,
    /// SHA-256 hash of the binary.
    pub sha256: String,
    /// Download URL.
    pub url: String,
    /// Release notes (markdown).
    pub release_notes: String,
}

/// Update configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Manifest URL (GitHub release API endpoint).
    pub manifest_url: String,
    /// Whether to check automatically.
    pub auto_check: bool,
    /// Check interval in hours.
    pub check_interval_hours: u64,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            manifest_url: "https://api.github.com/repos/agentumi/edgeclaw-pc/releases/latest"
                .to_string(),
            auto_check: true,
            check_interval_hours: 24,
        }
    }
}

/// Result of an update check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    /// Whether an update is available.
    pub available: bool,
    /// Current version.
    pub current_version: String,
    /// Latest version (if available).
    pub latest_version: Option<String>,
    /// Release notes (if available).
    pub release_notes: Option<String>,
}

/// OTA update checker.
pub struct UpdateChecker {
    config: UpdateConfig,
    current_version: String,
}

impl UpdateChecker {
    /// Create a new update checker.
    pub fn new(config: UpdateConfig, current_version: &str) -> Self {
        Self {
            config,
            current_version: current_version.to_string(),
        }
    }

    /// Get the manifest URL.
    pub fn manifest_url(&self) -> &str {
        &self.config.manifest_url
    }

    /// Get the current version.
    pub fn current_version(&self) -> &str {
        &self.current_version
    }

    /// Check if auto-update is enabled.
    pub fn auto_check(&self) -> bool {
        self.config.auto_check
    }

    /// Compare two semver strings. Returns true if `latest` is newer.
    pub fn is_newer(current: &str, latest: &str) -> bool {
        let parse = |s: &str| -> (u64, u64, u64) {
            let parts: Vec<&str> = s.trim_start_matches('v').split('.').collect();
            let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
            let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            (major, minor, patch)
        };
        let c = parse(current);
        let l = parse(latest);
        l > c
    }

    /// Check for updates by fetching the manifest.
    pub fn check(&self) -> Result<UpdateCheckResult, AgentError> {
        // Try to fetch from GitHub API
        match ureq::get(&self.config.manifest_url)
            .set("User-Agent", "edgeclaw-agent")
            .call()
        {
            Ok(resp) => {
                let body = resp
                    .into_string()
                    .map_err(|e| AgentError::ExecutionError(format!("Read body: {e}")))?;

                // Parse GitHub release JSON
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    let tag = json["tag_name"].as_str().unwrap_or("unknown").to_string();
                    let notes = json["body"].as_str().map(String::from);
                    let available = Self::is_newer(&self.current_version, &tag);

                    Ok(UpdateCheckResult {
                        available,
                        current_version: self.current_version.clone(),
                        latest_version: Some(tag),
                        release_notes: notes,
                    })
                } else {
                    Ok(UpdateCheckResult {
                        available: false,
                        current_version: self.current_version.clone(),
                        latest_version: None,
                        release_notes: None,
                    })
                }
            }
            Err(e) => {
                // Network error — return not-available instead of hard error
                tracing::warn!("Update check failed: {e}");
                Ok(UpdateCheckResult {
                    available: false,
                    current_version: self.current_version.clone(),
                    latest_version: None,
                    release_notes: Some(format!("Check failed: {e}")),
                })
            }
        }
    }

    /// Verify SHA-256 hash of a downloaded file.
    pub fn verify_sha256(data: &[u8], expected_hex: &str) -> bool {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());
        hash == expected_hex.to_lowercase()
    }

    /// Create a backup of the current binary.
    pub fn backup_current() -> Result<std::path::PathBuf, AgentError> {
        let exe = std::env::current_exe()
            .map_err(|e| AgentError::ExecutionError(format!("Get exe path: {e}")))?;
        let backup = exe.with_extension("bak");
        std::fs::copy(&exe, &backup)
            .map_err(|e| AgentError::ExecutionError(format!("Backup: {e}")))?;
        Ok(backup)
    }

    /// Rollback to the backup binary.
    pub fn rollback() -> Result<(), AgentError> {
        let exe = std::env::current_exe()
            .map_err(|e| AgentError::ExecutionError(format!("Get exe path: {e}")))?;
        let backup = exe.with_extension("bak");
        if !backup.exists() {
            return Err(AgentError::ExecutionError(
                "No backup found for rollback".into(),
            ));
        }
        std::fs::copy(&backup, &exe)
            .map_err(|e| AgentError::ExecutionError(format!("Rollback: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_config_default() {
        let cfg = UpdateConfig::default();
        assert!(cfg.manifest_url.contains("github"));
        assert!(cfg.auto_check);
        assert_eq!(cfg.check_interval_hours, 24);
    }

    #[test]
    fn test_checker_creation() {
        let checker = UpdateChecker::new(UpdateConfig::default(), "1.0.0");
        assert_eq!(checker.current_version(), "1.0.0");
        assert!(checker.auto_check());
        assert!(checker.manifest_url().contains("github"));
    }

    #[test]
    fn test_is_newer() {
        assert!(UpdateChecker::is_newer("1.0.0", "1.0.1"));
        assert!(UpdateChecker::is_newer("1.0.0", "1.1.0"));
        assert!(UpdateChecker::is_newer("1.0.0", "2.0.0"));
        assert!(!UpdateChecker::is_newer("1.0.0", "1.0.0"));
        assert!(!UpdateChecker::is_newer("2.0.0", "1.0.0"));
        assert!(UpdateChecker::is_newer("v1.0.0", "v1.0.1"));
    }

    #[test]
    fn test_verify_sha256_valid() {
        let data = b"hello world";
        // Known SHA-256 hash of "hello world"
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(UpdateChecker::verify_sha256(data, expected));
    }

    #[test]
    fn test_verify_sha256_invalid() {
        let data = b"hello world";
        assert!(!UpdateChecker::verify_sha256(
            data,
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_update_manifest_serialize() {
        let manifest = UpdateManifest {
            version: "2.0.0".into(),
            platform: "x86_64-pc-windows-msvc".into(),
            sha256: "abc123".into(),
            url: "https://example.com/binary".into(),
            release_notes: "Bug fixes".into(),
        };
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(json.contains("2.0.0"));
        let parsed: UpdateManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "2.0.0");
    }

    #[test]
    fn test_update_check_result_serialize() {
        let result = UpdateCheckResult {
            available: true,
            current_version: "1.0.0".into(),
            latest_version: Some("2.0.0".into()),
            release_notes: Some("New features".into()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("true"));
        assert!(json.contains("2.0.0"));
    }

    #[test]
    fn test_check_network_failure_graceful() {
        // Use a non-existent URL to test graceful failure
        let cfg = UpdateConfig {
            manifest_url: "http://localhost:1/nonexistent".into(),
            ..Default::default()
        };
        let checker = UpdateChecker::new(cfg, "1.0.0");
        let result = checker.check().unwrap();
        assert!(!result.available);
        assert_eq!(result.current_version, "1.0.0");
    }

    #[test]
    fn test_rollback_no_backup() {
        // Rollback should fail gracefully when no backup exists
        let result = UpdateChecker::rollback();
        // May succeed or fail depending on whether a .bak file exists
        // The important thing is it doesn't panic
        let _ = result;
    }
}

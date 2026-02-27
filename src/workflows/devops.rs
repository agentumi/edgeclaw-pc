//! DevOps automation workflows.
//!
//! Provides [`InfraMonitor`] for Docker/disk/service checks and
//! [`AutoResponse`] for automated remediation (cleanup, restart, cert check).

use chrono::Utc;

use crate::error::AgentError;

// ─── InfraMonitor ──────────────────────────────────────────

/// Infrastructure monitoring helper.
pub struct InfraMonitor;

/// Docker container status.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DockerContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
}

/// Disk usage snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiskUsage {
    pub mount: String,
    pub total_gb: f64,
    pub used_gb: f64,
    pub usage_percent: f64,
    pub alert: bool,
}

/// Service status.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub state: String,
    pub running: bool,
}

impl InfraMonitor {
    /// List running Docker containers via `docker ps`.
    pub fn check_docker() -> Result<Vec<DockerContainerInfo>, AgentError> {
        let output = std::process::Command::new("docker")
            .args([
                "ps",
                "--format",
                "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}",
            ])
            .output()
            .map_err(|e| AgentError::ExecutionError(format!("docker: {e}")))?;

        let text = String::from_utf8_lossy(&output.stdout);
        let containers: Vec<DockerContainerInfo> = text
            .lines()
            .filter(|l| !l.is_empty())
            .filter_map(|line| {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 4 {
                    Some(DockerContainerInfo {
                        id: parts[0].to_string(),
                        name: parts[1].to_string(),
                        image: parts[2].to_string(),
                        status: parts[3].to_string(),
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(containers)
    }

    /// Check disk usage using `sysinfo` crate data.
    pub fn check_disk(threshold_percent: f64) -> Vec<DiskUsage> {
        let sys = sysinfo::System::new_all();
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let _ = sys; // keep compiler happy

        disks
            .iter()
            .map(|d| {
                let total = d.total_space() as f64 / 1_073_741_824.0;
                let avail = d.available_space() as f64 / 1_073_741_824.0;
                let used = total - avail;
                let pct = if total > 0.0 {
                    (used / total) * 100.0
                } else {
                    0.0
                };
                DiskUsage {
                    mount: d.mount_point().to_string_lossy().to_string(),
                    total_gb: (total * 10.0).round() / 10.0,
                    used_gb: (used * 10.0).round() / 10.0,
                    usage_percent: (pct * 10.0).round() / 10.0,
                    alert: pct >= threshold_percent,
                }
            })
            .collect()
    }

    /// Check service status (Windows: `Get-Service`, Linux: `systemctl`).
    pub fn check_services() -> Result<Vec<ServiceStatus>, AgentError> {
        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("powershell")
                .args(["-Command", "Get-Service | Where-Object {$_.Status -ne 'Running'} | Select-Object -First 10 Name,Status | Format-Table -HideTableHeaders"])
                .output()
                .map_err(|e| AgentError::ExecutionError(format!("Get-Service: {e}")))?;

            let text = String::from_utf8_lossy(&output.stdout);
            let services: Vec<ServiceStatus> = text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|line| {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        Some(ServiceStatus {
                            name: parts[0].to_string(),
                            state: parts[1].to_string(),
                            running: parts[1] == "Running",
                        })
                    } else {
                        None
                    }
                })
                .collect();
            Ok(services)
        }

        #[cfg(not(target_os = "windows"))]
        {
            let output = std::process::Command::new("systemctl")
                .args(["list-units", "--failed", "--no-pager", "--no-legend"])
                .output()
                .map_err(|e| AgentError::ExecutionError(format!("systemctl: {e}")))?;

            let text = String::from_utf8_lossy(&output.stdout);
            let services: Vec<ServiceStatus> = text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|line| {
                    let name = line.split_whitespace().next().unwrap_or("unknown");
                    ServiceStatus {
                        name: name.to_string(),
                        state: "failed".to_string(),
                        running: false,
                    }
                })
                .collect();
            Ok(services)
        }
    }

    /// Collect last N lines of system logs.
    pub fn collect_logs(lines: usize) -> Result<String, AgentError> {
        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("powershell")
                .args([
                    "-Command",
                    &format!(
                        "Get-EventLog -LogName System -Newest {} | Format-List TimeGenerated,EntryType,Message",
                        lines
                    ),
                ])
                .output()
                .map_err(|e| AgentError::ExecutionError(format!("Get-EventLog: {e}")))?;
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        }

        #[cfg(not(target_os = "windows"))]
        {
            let output = std::process::Command::new("journalctl")
                .args(["--no-pager", "-n", &lines.to_string()])
                .output()
                .map_err(|e| AgentError::ExecutionError(format!("journalctl: {e}")))?;
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        }
    }
}

// ─── AutoResponse ──────────────────────────────────────────

/// Automated remediation actions for common infrastructure issues.
pub struct AutoResponse;

/// Cleanup result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CleanupResult {
    pub temp_files_removed: usize,
    pub docker_pruned: bool,
    pub bytes_freed: u64,
    pub output: String,
}

/// SSL certificate info.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CertInfo {
    pub host: String,
    pub valid: bool,
    pub expires_in_days: Option<i64>,
    pub output: String,
}

impl AutoResponse {
    /// Attempt cleanup: temp files + docker prune.
    pub fn disk_cleanup() -> CleanupResult {
        let mut total_removed = 0usize;
        let mut output_parts = Vec::new();

        // Clean temp directory
        let temp = std::env::temp_dir();
        if let Ok(entries) = std::fs::read_dir(&temp) {
            let cutoff = chrono::Utc::now() - chrono::Duration::days(7);
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        let mod_time: chrono::DateTime<Utc> = modified.into();
                        if mod_time < cutoff
                            && meta.is_file()
                            && std::fs::remove_file(entry.path()).is_ok()
                        {
                            total_removed += 1;
                        }
                    }
                }
            }
        }
        output_parts.push(format!("Removed {total_removed} old temp files"));

        // Docker system prune (non-interactive)
        let docker_pruned = if let Ok(out) = std::process::Command::new("docker")
            .args(["system", "prune", "-f"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            output_parts.push(text);
            out.status.success()
        } else {
            output_parts.push("Docker not available".into());
            false
        };

        CleanupResult {
            temp_files_removed: total_removed,
            docker_pruned,
            bytes_freed: 0, // Would need per-file size tracking
            output: output_parts.join("\n"),
        }
    }

    /// Restart a system service by name.
    pub fn restart_service(name: &str) -> Result<String, AgentError> {
        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("powershell")
                .args([
                    "-Command",
                    &format!("Restart-Service -Name '{}' -Force", name),
                ])
                .output()
                .map_err(|e| AgentError::ExecutionError(format!("Restart-Service: {e}")))?;
            let text = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Ok(format!("{text}\n{stderr}").trim().to_string())
        }

        #[cfg(not(target_os = "windows"))]
        {
            let output = std::process::Command::new("systemctl")
                .args(["restart", name])
                .output()
                .map_err(|e| AgentError::ExecutionError(format!("systemctl restart: {e}")))?;
            let text = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(text)
        }
    }

    /// Check SSL certificate expiry for a host using openssl s_client.
    pub fn cert_check(host: &str) -> CertInfo {
        let output = std::process::Command::new("openssl")
            .args([
                "s_client",
                "-connect",
                &format!("{host}:443"),
                "-servername",
                host,
            ])
            .stdin(std::process::Stdio::null())
            .output();

        match output {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).to_string();
                // Try to parse dates — simplified
                let valid = text.contains("Verify return code: 0");
                CertInfo {
                    host: host.to_string(),
                    valid,
                    expires_in_days: None, // Would need x509 parsing
                    output: text.chars().take(500).collect(),
                }
            }
            Err(e) => CertInfo {
                host: host.to_string(),
                valid: false,
                expires_in_days: None,
                output: format!("openssl not available: {e}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_container_info_serialize() {
        let info = DockerContainerInfo {
            id: "abc123".into(),
            name: "web".into(),
            image: "nginx:latest".into(),
            status: "Up 2 hours".into(),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("nginx"));
    }

    #[test]
    fn test_disk_usage_alert() {
        let du = DiskUsage {
            mount: "C:\\".into(),
            total_gb: 100.0,
            used_gb: 95.0,
            usage_percent: 95.0,
            alert: true,
        };
        assert!(du.alert);
        assert!(du.usage_percent > 90.0);
    }

    #[test]
    fn test_check_disk() {
        let disks = InfraMonitor::check_disk(90.0);
        // Should return at least the system drive
        assert!(!disks.is_empty());
        for d in &disks {
            assert!(d.total_gb > 0.0);
        }
    }

    #[test]
    fn test_cleanup_result_serialize() {
        let r = CleanupResult {
            temp_files_removed: 5,
            docker_pruned: true,
            bytes_freed: 1024,
            output: "ok".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("temp_files_removed"));
    }

    #[test]
    fn test_cert_info_serialize() {
        let c = CertInfo {
            host: "example.com".into(),
            valid: true,
            expires_in_days: Some(90),
            output: "ok".into(),
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("example.com"));
    }

    #[test]
    fn test_service_status_serialize() {
        let s = ServiceStatus {
            name: "nginx".into(),
            state: "running".into(),
            running: true,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("nginx"));
    }

    #[test]
    fn test_cert_check_invalid_host() {
        let info = AutoResponse::cert_check("invalid-host-that-does-not-exist.local");
        assert!(!info.valid);
    }
}

use sysinfo::System;

/// System information snapshot
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub arch: String,
    pub cpu_count: usize,
    pub cpu_brand: String,
    pub cpu_usage: f32,
    pub total_memory_mb: u64,
    pub used_memory_mb: u64,
    pub memory_usage_percent: f32,
    pub total_disk_gb: f64,
    pub used_disk_gb: f64,
    pub uptime_secs: u64,
}

/// Collect current system information
pub fn collect_system_info() -> SystemInfo {
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu_count = sys.cpus().len();
    let cpu_brand = sys
        .cpus()
        .first()
        .map(|c| c.brand().to_string())
        .unwrap_or_default();
    let cpu_usage = sys.global_cpu_usage();

    let total_memory_mb = sys.total_memory() / (1024 * 1024);
    let used_memory_mb = sys.used_memory() / (1024 * 1024);
    let memory_usage_percent = if total_memory_mb > 0 {
        (used_memory_mb as f32 / total_memory_mb as f32) * 100.0
    } else {
        0.0
    };

    let mut total_disk_bytes: u64 = 0;
    let mut used_disk_bytes: u64 = 0;
    for disk in sysinfo::Disks::new_with_refreshed_list().iter() {
        total_disk_bytes += disk.total_space();
        used_disk_bytes += disk.total_space() - disk.available_space();
    }

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    SystemInfo {
        hostname,
        os_name: System::name().unwrap_or_else(|| "unknown".to_string()),
        os_version: System::os_version().unwrap_or_else(|| "unknown".to_string()),
        arch: std::env::consts::ARCH.to_string(),
        cpu_count,
        cpu_brand,
        cpu_usage,
        total_memory_mb,
        used_memory_mb,
        memory_usage_percent,
        total_disk_gb: total_disk_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
        used_disk_gb: used_disk_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
        uptime_secs: System::uptime(),
    }
}

/// Get the list of running processes
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_usage: f32,
    pub memory_kb: u64,
}

/// List running processes (top N by CPU usage)
pub fn list_processes(limit: usize) -> Vec<ProcessInfo> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut processes: Vec<ProcessInfo> = sys
        .processes()
        .iter()
        .map(|(pid, proc_)| ProcessInfo {
            pid: pid.as_u32(),
            name: proc_.name().to_string_lossy().to_string(),
            cpu_usage: proc_.cpu_usage(),
            memory_kb: proc_.memory() / 1024,
        })
        .collect();

    processes.sort_by(|a, b| {
        b.cpu_usage
            .partial_cmp(&a.cpu_usage)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    processes.truncate(limit);
    processes
}

/// Detect available capabilities based on the current OS
pub fn detect_capabilities() -> Vec<String> {
    let mut caps = vec![
        "status_query".to_string(),
        "heartbeat".to_string(),
        "peer_list".to_string(),
        "system_info".to_string(),
        "file_read".to_string(),
        "log_view".to_string(),
        "process_list".to_string(),
    ];

    // Check shell availability
    #[cfg(target_os = "windows")]
    {
        caps.push("shell_exec".to_string()); // PowerShell always available
        if which_exists("docker") {
            caps.push("docker_manage".to_string());
        }
        if which_exists("wsl") {
            caps.push("wsl_exec".to_string());
        }
    }

    #[cfg(target_os = "macos")]
    {
        caps.push("shell_exec".to_string()); // bash/zsh available
        if which_exists("docker") {
            caps.push("docker_manage".to_string());
        }
    }

    #[cfg(target_os = "linux")]
    {
        caps.push("shell_exec".to_string()); // bash available
        if which_exists("docker") {
            caps.push("docker_manage".to_string());
        }
        if which_exists("systemctl") {
            caps.push("process_manage".to_string());
        }
    }

    // Common capabilities
    caps.push("file_write".to_string());
    caps.push("config_edit".to_string());
    caps.push("network_scan".to_string());
    caps.push("system_reboot".to_string());
    caps.push("firmware_update".to_string());
    caps.push("security_config".to_string());

    caps
}

/// Check if a command exists in PATH
fn which_exists(cmd: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("where")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("which")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_system_info() {
        let info = collect_system_info();
        assert!(!info.hostname.is_empty());
        assert!(info.cpu_count > 0);
        assert!(info.total_memory_mb > 0);
    }

    #[test]
    fn test_list_processes() {
        let procs = list_processes(10);
        // Should have at least a few processes on any OS
        assert!(!procs.is_empty());
    }

    #[test]
    fn test_detect_capabilities() {
        let caps = detect_capabilities();
        assert!(caps.contains(&"status_query".to_string()));
        assert!(caps.contains(&"heartbeat".to_string()));
        assert!(caps.contains(&"system_info".to_string()));
        assert!(caps.len() >= 10);
    }
}

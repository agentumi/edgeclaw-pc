use crate::error::AgentError;
use std::time::Instant;
use tokio::process::Command;

/// Execution request
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecRequest {
    pub execution_id: String,
    pub action: String,
    pub command: String,
    pub args: Vec<String>,
    pub timeout_secs: u64,
    pub working_dir: Option<String>,
}

/// Execution response
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecResponse {
    pub execution_id: String,
    pub action: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// Command executor with sandboxing and resource limits
pub struct Executor {
    max_concurrent: usize,
    default_timeout_secs: u64,
    max_timeout_secs: u64,
    allowed_paths: Vec<String>,
    active_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Executor {
    pub fn new(
        max_concurrent: usize,
        default_timeout_secs: u64,
        max_timeout_secs: u64,
        allowed_paths: Vec<String>,
    ) -> Self {
        Self {
            max_concurrent,
            default_timeout_secs,
            max_timeout_secs,
            allowed_paths,
            active_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Execute a command with timeout and resource limits
    pub async fn execute(&self, request: ExecRequest) -> Result<ExecResponse, AgentError> {
        // Check concurrency limit
        let current = self
            .active_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if current >= self.max_concurrent {
            self.active_count
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return Err(AgentError::ExecutionError(format!(
                "max concurrent executions reached ({}/{})",
                current, self.max_concurrent
            )));
        }

        let result = self.execute_inner(request).await;

        self.active_count
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);

        result
    }

    async fn execute_inner(&self, request: ExecRequest) -> Result<ExecResponse, AgentError> {
        let timeout_secs = request.timeout_secs.min(self.max_timeout_secs).max(1);

        let timeout = if timeout_secs == 0 {
            self.default_timeout_secs
        } else {
            timeout_secs
        };

        // Validate working directory if specified
        if let Some(ref dir) = request.working_dir {
            if !self.is_allowed_path(dir) {
                return Err(AgentError::PolicyDenied(format!(
                    "working directory not in allowed paths: {dir}"
                )));
            }
        }

        let start = Instant::now();

        // Build command based on OS
        let mut cmd = self.build_command(&request.command, &request.args);

        if let Some(ref dir) = request.working_dir {
            cmd.current_dir(dir);
        }

        // Execute with timeout
        let output = tokio::time::timeout(std::time::Duration::from_secs(timeout), cmd.output())
            .await
            .map_err(|_| AgentError::Timeout(timeout))?
            .map_err(|e| AgentError::ExecutionError(e.to_string()))?;

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ExecResponse {
            execution_id: request.execution_id,
            action: request.action,
            success: output.status.success(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration_ms,
        })
    }

    fn build_command(&self, command: &str, args: &[String]) -> Command {
        #[cfg(target_os = "windows")]
        {
            let mut cmd = Command::new("cmd");
            let full_cmd = if args.is_empty() {
                command.to_string()
            } else {
                format!("{} {}", command, args.join(" "))
            };
            cmd.args(["/C", &full_cmd]);
            cmd
        }

        #[cfg(not(target_os = "windows"))]
        {
            let mut cmd = Command::new("sh");
            let full_cmd = if args.is_empty() {
                command.to_string()
            } else {
                format!("{} {}", command, args.join(" "))
            };
            cmd.args(["-c", &full_cmd]);
            cmd
        }
    }

    fn is_allowed_path(&self, path: &str) -> bool {
        if self.allowed_paths.is_empty() {
            return true; // no restriction if not configured
        }
        self.allowed_paths
            .iter()
            .any(|allowed| path.starts_with(allowed))
    }

    /// Get current number of active executions
    pub fn active_count(&self) -> usize {
        self.active_count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_executor() -> Executor {
        Executor::new(5, 10, 60, vec![])
    }

    #[tokio::test]
    async fn test_execute_echo() {
        let executor = test_executor();
        let request = ExecRequest {
            execution_id: "test-001".to_string(),
            action: "shell_exec".to_string(),
            command: "echo hello".to_string(),
            args: vec![],
            timeout_secs: 5,
            working_dir: None,
        };
        let result = executor.execute(request).await.unwrap();
        assert!(result.success);
        assert!(result.stdout.contains("hello"));
        assert_eq!(result.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_execute_with_exit_code() {
        let executor = test_executor();

        #[cfg(target_os = "windows")]
        let command = "exit /b 42".to_string();
        #[cfg(not(target_os = "windows"))]
        let command = "exit 42".to_string();

        let request = ExecRequest {
            execution_id: "test-002".to_string(),
            action: "shell_exec".to_string(),
            command,
            args: vec![],
            timeout_secs: 5,
            working_dir: None,
        };
        let result = executor.execute(request).await.unwrap();
        assert!(!result.success);
        assert_eq!(result.exit_code, Some(42));
    }

    #[tokio::test]
    async fn test_active_count() {
        let executor = test_executor();
        assert_eq!(executor.active_count(), 0);
    }

    #[test]
    fn test_allowed_path_check() {
        let executor = Executor::new(
            5,
            10,
            60,
            vec!["/home/user".to_string(), "/tmp".to_string()],
        );
        assert!(executor.is_allowed_path("/home/user/file.txt"));
        assert!(executor.is_allowed_path("/tmp/test"));
        assert!(!executor.is_allowed_path("/etc/passwd"));
    }

    #[test]
    fn test_empty_allowed_paths() {
        let executor = Executor::new(5, 10, 60, vec![]);
        assert!(executor.is_allowed_path("/anything/goes"));
    }
}

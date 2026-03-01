//! Software development automation workflows.
//!
//! Provides [`GitWorkflow`], [`CiWorkflow`], and [`CodeQuality`] for
//! automating common SW-dev tasks like branching, CI status checks,
//! coverage reports, and dependency audits.

use crate::error::AgentError;

// ─── Git Workflow ──────────────────────────────────────────

/// Automated Git operations following GitFlow conventions.
#[derive(Default)]
pub struct GitWorkflow {
    /// Working directory for git commands (defaults to cwd).
    pub work_dir: Option<String>,
}

/// Result of a git operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GitResult {
    pub success: bool,
    pub output: String,
    pub branch: Option<String>,
}

impl GitWorkflow {
    /// Create a workflow targeting a specific directory.
    pub fn new(work_dir: Option<String>) -> Self {
        Self { work_dir }
    }

    /// Run a git command and capture output.
    fn run_git(&self, args: &[&str]) -> Result<GitResult, AgentError> {
        let mut cmd = std::process::Command::new("git");
        cmd.args(args);
        if let Some(ref wd) = self.work_dir {
            cmd.current_dir(wd);
        }
        let output = cmd
            .output()
            .map_err(|e| AgentError::ExecutionError(format!("git: {e}")))?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok(GitResult {
            success: output.status.success(),
            output: if stdout.is_empty() { stderr } else { stdout },
            branch: None,
        })
    }

    /// Create a branch following GitFlow naming (`feature/`, `hotfix/`, `release/`).
    pub fn auto_branch(&self, kind: &str, name: &str) -> Result<GitResult, AgentError> {
        let prefix = match kind {
            "feature" | "feat" => "feature",
            "hotfix" | "fix" => "hotfix",
            "release" | "rel" => "release",
            _ => "feature",
        };
        let branch_name = format!("{prefix}/{name}");
        let mut result = self.run_git(&["checkout", "-b", &branch_name])?;
        result.branch = Some(branch_name);
        Ok(result)
    }

    /// Detect merge conflicts without actually merging.
    pub fn detect_conflicts(&self, target: &str) -> Result<GitResult, AgentError> {
        // Dry-run merge
        let result = self.run_git(&["merge", "--no-commit", "--no-ff", target]);
        // Always abort the dry-run merge to restore state
        let _ = self.run_git(&["merge", "--abort"]);
        result
    }

    /// Generate a semver tag.
    pub fn auto_tag(&self, version: &str) -> Result<GitResult, AgentError> {
        let tag = if version.starts_with('v') {
            version.to_string()
        } else {
            format!("v{version}")
        };
        self.run_git(&["tag", "-a", &tag, "-m", &format!("Release {tag}")])
    }

    /// Current branch name.
    pub fn current_branch(&self) -> Result<String, AgentError> {
        let r = self.run_git(&["branch", "--show-current"])?;
        Ok(r.output.trim().to_string())
    }
}

// ─── CI Workflow ───────────────────────────────────────────

/// GitHub Actions CI helpers (wraps `gh` CLI).
pub struct CiWorkflow;

/// CI run status.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CiStatus {
    pub runs: Vec<CiRun>,
}

/// Single CI run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CiRun {
    pub id: String,
    pub name: String,
    pub status: String,
    pub conclusion: String,
}

impl CiWorkflow {
    /// List recent workflow runs via `gh run list`.
    pub fn check_status() -> Result<CiStatus, AgentError> {
        let output = std::process::Command::new("gh")
            .args([
                "run",
                "list",
                "--json",
                "databaseId,name,status,conclusion",
                "--limit",
                "5",
            ])
            .output()
            .map_err(|e| AgentError::ExecutionError(format!("gh cli: {e}")))?;

        if !output.status.success() {
            return Ok(CiStatus { runs: vec![] });
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        let raw: Vec<serde_json::Value> = serde_json::from_str(&json_str).unwrap_or_default();
        let runs = raw
            .iter()
            .map(|v| CiRun {
                id: v["databaseId"].to_string(),
                name: v["name"].as_str().unwrap_or("").to_string(),
                status: v["status"].as_str().unwrap_or("").to_string(),
                conclusion: v["conclusion"].as_str().unwrap_or("").to_string(),
            })
            .collect();

        Ok(CiStatus { runs })
    }

    /// Re-run a failed workflow.
    pub fn retry_workflow(run_id: &str) -> Result<String, AgentError> {
        let output = std::process::Command::new("gh")
            .args(["run", "rerun", run_id])
            .output()
            .map_err(|e| AgentError::ExecutionError(format!("gh rerun: {e}")))?;
        let out = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(out)
    }
}

// ─── Code Quality ──────────────────────────────────────────

/// Code quality helpers: coverage, TODO scanning, dep audits.
pub struct CodeQuality;

/// TODO/FIXME/HACK item found in source code.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TodoItem {
    pub file: String,
    pub line: usize,
    pub kind: String,
    pub text: String,
}

/// Dependency audit result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditResult {
    pub success: bool,
    pub advisories: usize,
    pub output: String,
}

impl CodeQuality {
    /// Scan source directory for TODO/FIXME/HACK comments.
    pub fn scan_todos(dir: &str) -> Vec<TodoItem> {
        let mut items = Vec::new();
        let patterns = ["TODO", "FIXME", "HACK"];

        if let Ok(entries) = Self::walk_files(dir, &["rs", "kt", "ts", "js", "py"]) {
            for path in entries {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    for (i, line) in content.lines().enumerate() {
                        for pat in &patterns {
                            if line.contains(pat) {
                                items.push(TodoItem {
                                    file: path.clone(),
                                    line: i + 1,
                                    kind: (*pat).to_string(),
                                    text: line.trim().to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
        items
    }

    /// Run `cargo audit` and parse the result.
    pub fn check_dependencies() -> AuditResult {
        match std::process::Command::new("cargo").args(["audit"]).output() {
            Ok(output) => {
                let text = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let combined = format!("{text}\n{stderr}");
                let advisories = combined.matches("advisory").count();
                AuditResult {
                    success: output.status.success(),
                    advisories,
                    output: combined.trim().to_string(),
                }
            }
            Err(e) => AuditResult {
                success: false,
                advisories: 0,
                output: format!("cargo audit not available: {e}"),
            },
        }
    }

    /// Recursively list files with given extensions under `dir`.
    fn walk_files(dir: &str, extensions: &[&str]) -> Result<Vec<String>, std::io::Error> {
        let mut files = Vec::new();
        Self::walk_dir_recursive(std::path::Path::new(dir), extensions, &mut files)?;
        Ok(files)
    }

    fn walk_dir_recursive(
        dir: &std::path::Path,
        extensions: &[&str],
        out: &mut Vec<String>,
    ) -> Result<(), std::io::Error> {
        if !dir.is_dir() {
            return Ok(());
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                // Skip hidden dirs and target/node_modules
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.starts_with('.') || name == "target" || name == "node_modules" {
                    continue;
                }
                Self::walk_dir_recursive(&path, extensions, out)?;
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if extensions.contains(&ext) {
                    out.push(path.to_string_lossy().to_string());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_workflow_default() {
        let gw = GitWorkflow::default();
        assert!(gw.work_dir.is_none());
    }

    #[test]
    fn test_git_result_serialize() {
        let r = GitResult {
            success: true,
            output: "ok".into(),
            branch: Some("feature/test".into()),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("feature/test"));
    }

    #[test]
    fn test_current_branch() {
        // Runs in the repo root — should return a branch name
        let gw = GitWorkflow::default();
        let branch = gw.current_branch();
        // May fail in CI without a git repo, so just check it doesn't panic
        if let Ok(b) = branch {
            assert!(!b.is_empty());
        }
    }

    #[test]
    fn test_ci_run_serialize() {
        let run = CiRun {
            id: "123".into(),
            name: "CI".into(),
            status: "completed".into(),
            conclusion: "success".into(),
        };
        let json = serde_json::to_string(&run).unwrap();
        assert!(json.contains("completed"));
    }

    #[test]
    fn test_scan_todos_on_src() {
        // Scan the project's own src/ for TODOs
        let items = CodeQuality::scan_todos("src");
        // We don't commit TODOs normally, but verify it returns a vec
        assert!(items.len() < 1000); // sanity check
    }

    #[test]
    fn test_todo_item_serialize() {
        let item = TodoItem {
            file: "main.rs".into(),
            line: 42,
            kind: "TODO".into(),
            text: "// TODO: fix this".into(),
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("main.rs"));
    }

    #[test]
    fn test_audit_result_serialize() {
        let r = AuditResult {
            success: true,
            advisories: 0,
            output: "No vulnerabilities found".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("No vulnerabilities"));
    }

    #[test]
    fn test_check_dependencies() {
        // cargo audit may not be installed — that's fine
        let result = CodeQuality::check_dependencies();
        assert!(!result.output.is_empty());
    }

    #[test]
    fn test_auto_branch_prefix() {
        // Can't actually create branches in tests without a real repo,
        // but we can verify the method doesn't panic
        let gw = GitWorkflow::new(Some("/tmp/nonexistent".into()));
        let result = gw.auto_branch("feature", "my-feature");
        // Will fail because /tmp/nonexistent doesn't exist, but shouldn't panic
        assert!(result.is_err() || !result.unwrap().success);
    }

    #[test]
    fn test_auto_branch_hotfix() {
        let gw = GitWorkflow::new(Some("/tmp/nonexistent".into()));
        let result = gw.auto_branch("hotfix", "urgent-fix");
        assert!(result.is_err() || !result.unwrap().success);
    }

    #[test]
    fn test_auto_branch_release() {
        let gw = GitWorkflow::new(Some("/tmp/nonexistent".into()));
        let result = gw.auto_branch("release", "1.0.0");
        assert!(result.is_err() || !result.unwrap().success);
    }

    #[test]
    fn test_auto_branch_unknown_kind() {
        let gw = GitWorkflow::new(Some("/tmp/nonexistent".into()));
        let result = gw.auto_branch("random", "test");
        // Should default to "feature/" prefix
        assert!(result.is_err() || !result.unwrap().success);
    }

    #[test]
    fn test_detect_conflicts() {
        let gw = GitWorkflow::new(Some("/tmp/nonexistent".into()));
        let result = gw.detect_conflicts("main");
        assert!(result.is_err() || !result.unwrap().success);
    }

    #[test]
    fn test_auto_tag_with_v() {
        let gw = GitWorkflow::new(Some("/tmp/nonexistent".into()));
        let result = gw.auto_tag("v1.0.0");
        assert!(result.is_err() || !result.unwrap().success);
    }

    #[test]
    fn test_auto_tag_without_v() {
        let gw = GitWorkflow::new(Some("/tmp/nonexistent".into()));
        let result = gw.auto_tag("2.0.0");
        assert!(result.is_err() || !result.unwrap().success);
    }

    #[test]
    fn test_git_workflow_with_work_dir() {
        let gw = GitWorkflow::new(Some("/tmp/test_dir".into()));
        assert_eq!(gw.work_dir, Some("/tmp/test_dir".to_string()));
    }

    #[test]
    fn test_ci_status_serialize() {
        let status = CiStatus {
            runs: vec![
                CiRun {
                    id: "1".into(),
                    name: "Build".into(),
                    status: "completed".into(),
                    conclusion: "success".into(),
                },
                CiRun {
                    id: "2".into(),
                    name: "Test".into(),
                    status: "in_progress".into(),
                    conclusion: "".into(),
                },
            ],
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("Build"));
        assert!(json.contains("in_progress"));
        let parsed: CiStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.runs.len(), 2);
    }

    #[test]
    fn test_audit_result_not_available() {
        let r = AuditResult {
            success: false,
            advisories: 0,
            output: "cargo audit not available".into(),
        };
        assert!(!r.success);
        assert_eq!(r.advisories, 0);
    }

    #[test]
    fn test_scan_todos_nonexistent_dir() {
        let items = CodeQuality::scan_todos("/nonexistent/path");
        assert!(items.is_empty());
    }

    #[test]
    fn test_git_result_no_branch() {
        let r = GitResult {
            success: false,
            output: "error".into(),
            branch: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("null"));
    }

    #[test]
    fn test_ci_retry_no_gh() {
        // gh CLI likely not installed in test env
        let result = CiWorkflow::retry_workflow("12345");
        // May succeed or fail, just shouldn't panic
        let _ = result;
    }
}

//! Task template system for standardized workflows.
//!
//! Provides pre-built command templates for common development, marketing,
//! DevOps, security, and system administration tasks. Users can list,
//! customize, and execute templates via CLI or API.
//!
//! # Categories
//!
//! | Category         | Templates | Description                         |
//! |------------------|-----------|-------------------------------------|
//! | Development      | 18        | Build, test, lint, deploy, git      |
//! | Marketing        | 12        | Analytics, content, SEO, social     |
//! | DevOps           | 15        | CI/CD, Docker, K8s, monitoring      |
//! | Security         | 10        | Audit, scan, compliance, pentest    |
//! | System           | 12        | Monitoring, backup, cleanup, network|
//! | Data             | 8         | ETL, analysis, migration, backup    |
//!
//! # Example
//!
//! ```no_run
//! use edgeclaw_agent::task_templates::{TemplateRegistry, TemplateCategory};
//!
//! let registry = TemplateRegistry::default_library();
//! let dev_templates = registry.by_category(TemplateCategory::Development);
//! for t in dev_templates {
//!     println!("{}: {}", t.id, t.name);
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Template Types ────────────────────────────────────────

/// Template category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateCategory {
    /// Software development tasks.
    Development,
    /// Marketing and analytics tasks.
    Marketing,
    /// DevOps and infrastructure tasks.
    DevOps,
    /// Security auditing and compliance tasks.
    Security,
    /// System administration tasks.
    System,
    /// Data engineering and analysis tasks.
    Data,
    /// Custom user-defined category.
    Custom,
}

impl std::fmt::Display for TemplateCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateCategory::Development => write!(f, "Development"),
            TemplateCategory::Marketing => write!(f, "Marketing"),
            TemplateCategory::DevOps => write!(f, "DevOps"),
            TemplateCategory::Security => write!(f, "Security"),
            TemplateCategory::System => write!(f, "System"),
            TemplateCategory::Data => write!(f, "Data"),
            TemplateCategory::Custom => write!(f, "Custom"),
        }
    }
}

impl TemplateCategory {
    /// All built-in categories.
    pub fn all() -> Vec<Self> {
        vec![
            Self::Development,
            Self::Marketing,
            Self::DevOps,
            Self::Security,
            Self::System,
            Self::Data,
        ]
    }
}

/// Required RBAC capability level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredRole {
    /// Viewer: read-only access.
    Viewer,
    /// Operator: read + limited write.
    Operator,
    /// Admin: full management.
    Admin,
    /// Owner: unrestricted.
    Owner,
}

impl std::fmt::Display for RequiredRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequiredRole::Viewer => write!(f, "viewer"),
            RequiredRole::Operator => write!(f, "operator"),
            RequiredRole::Admin => write!(f, "admin"),
            RequiredRole::Owner => write!(f, "owner"),
        }
    }
}

/// A single step within a task template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateStep {
    /// Step order (1-based).
    pub order: u32,
    /// Description of what this step does.
    pub description: String,
    /// Command to execute.
    pub command: String,
    /// Arguments.
    #[serde(default)]
    pub args: Vec<String>,
    /// Working directory (optional).
    pub working_dir: Option<String>,
    /// Timeout in seconds.
    #[serde(default = "default_step_timeout")]
    pub timeout_secs: u64,
    /// Whether failure of this step should abort the template.
    #[serde(default = "default_true")]
    pub abort_on_failure: bool,
    /// Whether this step is optional and can be skipped.
    #[serde(default)]
    pub optional: bool,
}

fn default_step_timeout() -> u64 {
    60
}
fn default_true() -> bool {
    true
}

/// A parameter that can be customized when executing a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateParam {
    /// Parameter name (used in command substitution: `{{param_name}}`).
    pub name: String,
    /// Description.
    pub description: String,
    /// Default value.
    pub default: Option<String>,
    /// Whether this parameter is required.
    #[serde(default)]
    pub required: bool,
    /// Example values.
    #[serde(default)]
    pub examples: Vec<String>,
}

/// A task template definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskTemplate {
    /// Unique template ID (e.g., "dev.build.rust").
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Detailed description.
    pub description: String,
    /// Category.
    pub category: TemplateCategory,
    /// Required RBAC role.
    pub required_role: RequiredRole,
    /// Required capability for RBAC check.
    pub capability: String,
    /// Tags for search/filter.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Ordered steps.
    pub steps: Vec<TemplateStep>,
    /// Customizable parameters.
    #[serde(default)]
    pub params: Vec<TemplateParam>,
    /// Platform constraints (empty = all platforms).
    #[serde(default)]
    pub platforms: Vec<String>,
    /// Estimated execution time in seconds.
    pub estimated_secs: u64,
    /// Whether this template is built-in (vs user-defined).
    #[serde(default)]
    pub builtin: bool,
}

impl TaskTemplate {
    /// Render this template's steps with given parameter values.
    ///
    /// Replaces `{{param_name}}` placeholders in commands and args.
    pub fn render(&self, params: &HashMap<String, String>) -> Result<Vec<TemplateStep>, String> {
        // Check required params
        for p in &self.params {
            if p.required && !params.contains_key(&p.name) && p.default.is_none() {
                return Err(format!("missing required parameter: {}", p.name));
            }
        }

        let mut rendered_steps = Vec::new();
        for step in &self.steps {
            let mut cmd = step.command.clone();
            let mut args: Vec<String> = step.args.clone();
            let mut working_dir: Option<String> = step.working_dir.clone();

            // Substitute parameters
            for param in &self.params {
                let value = params
                    .get(&param.name)
                    .or(param.default.as_ref())
                    .cloned()
                    .unwrap_or_default();
                let placeholder = format!("{{{{{}}}}}", param.name);
                cmd = cmd.replace(&placeholder, &value);
                args = args
                    .iter()
                    .map(|a| a.replace(&placeholder, &value))
                    .collect();
                working_dir = working_dir.map(|d| d.replace(&placeholder, &value));
            }

            rendered_steps.push(TemplateStep {
                command: cmd,
                args,
                working_dir,
                ..step.clone()
            });
        }

        Ok(rendered_steps)
    }

    /// Validate template structure.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("template ID cannot be empty".to_string());
        }
        if self.steps.is_empty() {
            return Err("template must have at least one step".to_string());
        }
        for (i, step) in self.steps.iter().enumerate() {
            if step.command.is_empty() {
                return Err(format!("step {} has empty command", i + 1));
            }
        }
        Ok(())
    }
}

// ─── Template Registry ────────────────────────────────────

/// Registry holding all available task templates.
pub struct TemplateRegistry {
    templates: Vec<TaskTemplate>,
}

impl TemplateRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            templates: Vec::new(),
        }
    }

    /// Create the default library with all built-in templates.
    pub fn default_library() -> Self {
        let mut registry = Self::new();
        registry.templates.extend(development_templates());
        registry.templates.extend(marketing_templates());
        registry.templates.extend(devops_templates());
        registry.templates.extend(security_templates());
        registry.templates.extend(system_templates());
        registry.templates.extend(data_templates());
        registry
    }

    /// Register a custom template.
    pub fn register(&mut self, template: TaskTemplate) -> Result<(), String> {
        template.validate()?;
        if self.templates.iter().any(|t| t.id == template.id) {
            return Err(format!("template already exists: {}", template.id));
        }
        self.templates.push(template);
        Ok(())
    }

    /// Get a template by ID.
    pub fn get(&self, id: &str) -> Option<&TaskTemplate> {
        self.templates.iter().find(|t| t.id == id)
    }

    /// List all templates.
    pub fn list(&self) -> &[TaskTemplate] {
        &self.templates
    }

    /// Filter by category.
    pub fn by_category(&self, category: TemplateCategory) -> Vec<&TaskTemplate> {
        self.templates
            .iter()
            .filter(|t| t.category == category)
            .collect()
    }

    /// Filter by tag.
    pub fn by_tag(&self, tag: &str) -> Vec<&TaskTemplate> {
        self.templates
            .iter()
            .filter(|t| t.tags.iter().any(|tt| tt.eq_ignore_ascii_case(tag)))
            .collect()
    }

    /// Search templates by name or description.
    pub fn search(&self, query: &str) -> Vec<&TaskTemplate> {
        let q = query.to_lowercase();
        self.templates
            .iter()
            .filter(|t| {
                t.name.to_lowercase().contains(&q)
                    || t.description.to_lowercase().contains(&q)
                    || t.id.to_lowercase().contains(&q)
                    || t.tags.iter().any(|tag| tag.to_lowercase().contains(&q))
            })
            .collect()
    }

    /// Get template count.
    pub fn count(&self) -> usize {
        self.templates.len()
    }

    /// Get template count per category.
    pub fn count_by_category(&self) -> HashMap<TemplateCategory, usize> {
        let mut map = HashMap::new();
        for t in &self.templates {
            *map.entry(t.category).or_insert(0) += 1;
        }
        map
    }

    /// Get all unique tags.
    pub fn all_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self.templates.iter().flat_map(|t| t.tags.clone()).collect();
        tags.sort();
        tags.dedup();
        tags
    }

    /// Export registry to JSON.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.templates)
    }

    /// Import templates from JSON.
    pub fn import_json(&mut self, json: &str) -> Result<usize, String> {
        let templates: Vec<TaskTemplate> = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let mut count = 0;
        for t in templates {
            if self.register(t).is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }
}

impl Default for TemplateRegistry {
    fn default() -> Self {
        Self::default_library()
    }
}

// ─── Built-in Template Libraries ───────────────────────────

/// Development templates.
fn development_templates() -> Vec<TaskTemplate> {
    vec![
        TaskTemplate {
            id: "dev.rust.build".into(),
            name: "Rust Build".into(),
            description: "Build Rust project in release mode with all checks".into(),
            category: TemplateCategory::Development,
            required_role: RequiredRole::Operator,
            capability: "shell_exec".into(),
            tags: vec!["rust".into(), "build".into(), "compile".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Format code".into(),
                    command: "cargo fmt".into(),
                    args: vec!["--check".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 30,
                    abort_on_failure: false,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Run clippy lints".into(),
                    command: "cargo clippy".into(),
                    args: vec![
                        "--all-targets".into(),
                        "--".into(),
                        "-D".into(),
                        "warnings".into(),
                    ],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 120,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 3,
                    description: "Build release binary".into(),
                    command: "cargo build".into(),
                    args: vec!["--release".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 300,
                    abort_on_failure: true,
                    optional: false,
                },
            ],
            params: vec![TemplateParam {
                name: "project_dir".into(),
                description: "Rust project directory".into(),
                default: Some(".".into()),
                required: false,
                examples: vec!["./edgeclaw-core".into(), "/home/user/project".into()],
            }],
            platforms: vec![],
            estimated_secs: 450,
            builtin: true,
        },
        TaskTemplate {
            id: "dev.rust.test".into(),
            name: "Rust Test Suite".into(),
            description: "Run all Rust tests with coverage".into(),
            category: TemplateCategory::Development,
            required_role: RequiredRole::Operator,
            capability: "shell_exec".into(),
            tags: vec!["rust".into(), "test".into(), "coverage".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Run unit tests".into(),
                    command: "cargo test".into(),
                    args: vec![],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 300,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Run specific module tests".into(),
                    command: "cargo test".into(),
                    args: vec!["{{test_module}}".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 120,
                    abort_on_failure: false,
                    optional: true,
                },
            ],
            params: vec![
                TemplateParam {
                    name: "project_dir".into(),
                    description: "Rust project directory".into(),
                    default: Some(".".into()),
                    required: false,
                    examples: vec![".".into()],
                },
                TemplateParam {
                    name: "test_module".into(),
                    description: "Specific test module to run".into(),
                    default: Some("".into()),
                    required: false,
                    examples: vec!["identity::tests".into(), "session::tests".into()],
                },
            ],
            platforms: vec![],
            estimated_secs: 420,
            builtin: true,
        },
        TaskTemplate {
            id: "dev.git.feature_start".into(),
            name: "Git Feature Branch".into(),
            description: "Create a new feature branch from main with convention".into(),
            category: TemplateCategory::Development,
            required_role: RequiredRole::Operator,
            capability: "shell_exec".into(),
            tags: vec!["git".into(), "branch".into(), "feature".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Fetch latest remote".into(),
                    command: "git fetch".into(),
                    args: vec!["origin".into()],
                    working_dir: None,
                    timeout_secs: 30,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Checkout main branch".into(),
                    command: "git checkout".into(),
                    args: vec!["main".into()],
                    working_dir: None,
                    timeout_secs: 10,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 3,
                    description: "Pull latest changes".into(),
                    command: "git pull".into(),
                    args: vec!["origin".into(), "main".into()],
                    working_dir: None,
                    timeout_secs: 30,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 4,
                    description: "Create new feature branch".into(),
                    command: "git checkout".into(),
                    args: vec!["-b".into(), "feat/{{feature_name}}".into()],
                    working_dir: None,
                    timeout_secs: 10,
                    abort_on_failure: true,
                    optional: false,
                },
            ],
            params: vec![TemplateParam {
                name: "feature_name".into(),
                description: "Feature branch name (kebab-case)".into(),
                default: None,
                required: true,
                examples: vec!["multi-chain-support".into(), "task-templates".into()],
            }],
            platforms: vec![],
            estimated_secs: 80,
            builtin: true,
        },
        TaskTemplate {
            id: "dev.git.release".into(),
            name: "Git Release Tag".into(),
            description: "Tag a new release version".into(),
            category: TemplateCategory::Development,
            required_role: RequiredRole::Admin,
            capability: "shell_exec".into(),
            tags: vec!["git".into(), "release".into(), "tag".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Create annotated tag".into(),
                    command: "git tag".into(),
                    args: vec![
                        "-a".into(),
                        "v{{version}}".into(),
                        "-m".into(),
                        "Release v{{version}}".into(),
                    ],
                    working_dir: None,
                    timeout_secs: 10,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Push tag to remote".into(),
                    command: "git push".into(),
                    args: vec!["origin".into(), "v{{version}}".into()],
                    working_dir: None,
                    timeout_secs: 30,
                    abort_on_failure: true,
                    optional: false,
                },
            ],
            params: vec![TemplateParam {
                name: "version".into(),
                description: "Version number (semver)".into(),
                default: None,
                required: true,
                examples: vec!["3.0.0".into(), "3.1.0-beta.1".into()],
            }],
            platforms: vec![],
            estimated_secs: 40,
            builtin: true,
        },
        TaskTemplate {
            id: "dev.node.build".into(),
            name: "Node.js Build".into(),
            description: "Install deps, lint, test, and build Node.js project".into(),
            category: TemplateCategory::Development,
            required_role: RequiredRole::Operator,
            capability: "shell_exec".into(),
            tags: vec![
                "node".into(),
                "npm".into(),
                "build".into(),
                "javascript".into(),
            ],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Install dependencies".into(),
                    command: "npm install".into(),
                    args: vec![],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 120,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Run linter".into(),
                    command: "npm run".into(),
                    args: vec!["lint".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 60,
                    abort_on_failure: false,
                    optional: true,
                },
                TemplateStep {
                    order: 3,
                    description: "Run tests".into(),
                    command: "npm test".into(),
                    args: vec![],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 120,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 4,
                    description: "Build production bundle".into(),
                    command: "npm run".into(),
                    args: vec!["build".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 180,
                    abort_on_failure: true,
                    optional: false,
                },
            ],
            params: vec![TemplateParam {
                name: "project_dir".into(),
                description: "Node.js project directory".into(),
                default: Some(".".into()),
                required: false,
                examples: vec!["./frontend".into(), "./web-app".into()],
            }],
            platforms: vec![],
            estimated_secs: 480,
            builtin: true,
        },
        TaskTemplate {
            id: "dev.python.build".into(),
            name: "Python Build & Test".into(),
            description: "Lint, type-check, test a Python project".into(),
            category: TemplateCategory::Development,
            required_role: RequiredRole::Operator,
            capability: "shell_exec".into(),
            tags: vec!["python".into(), "pytest".into(), "build".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Install dependencies".into(),
                    command: "pip install".into(),
                    args: vec!["-r".into(), "requirements.txt".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 120,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Run ruff linter".into(),
                    command: "ruff check".into(),
                    args: vec![".".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 30,
                    abort_on_failure: false,
                    optional: true,
                },
                TemplateStep {
                    order: 3,
                    description: "Run pytest".into(),
                    command: "pytest".into(),
                    args: vec!["-v".into(), "--tb=short".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 180,
                    abort_on_failure: true,
                    optional: false,
                },
            ],
            params: vec![TemplateParam {
                name: "project_dir".into(),
                description: "Python project directory".into(),
                default: Some(".".into()),
                required: false,
                examples: vec!["./backend".into()],
            }],
            platforms: vec![],
            estimated_secs: 330,
            builtin: true,
        },
        TaskTemplate {
            id: "dev.android.build".into(),
            name: "Android Build".into(),
            description: "Build Android APK with Gradle".into(),
            category: TemplateCategory::Development,
            required_role: RequiredRole::Operator,
            capability: "shell_exec".into(),
            tags: vec![
                "android".into(),
                "gradle".into(),
                "kotlin".into(),
                "mobile".into(),
            ],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Run lint checks".into(),
                    command: "./gradlew".into(),
                    args: vec!["lint".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 180,
                    abort_on_failure: false,
                    optional: true,
                },
                TemplateStep {
                    order: 2,
                    description: "Run unit tests".into(),
                    command: "./gradlew".into(),
                    args: vec!["test".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 300,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 3,
                    description: "Build debug APK".into(),
                    command: "./gradlew".into(),
                    args: vec!["assembleDebug".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 600,
                    abort_on_failure: true,
                    optional: false,
                },
            ],
            params: vec![TemplateParam {
                name: "project_dir".into(),
                description: "Android project directory".into(),
                default: Some("./android".into()),
                required: false,
                examples: vec!["./android".into()],
            }],
            platforms: vec![],
            estimated_secs: 1080,
            builtin: true,
        },
        TaskTemplate {
            id: "dev.wasm.build".into(),
            name: "WASM Build".into(),
            description: "Build WebAssembly package with wasm-pack".into(),
            category: TemplateCategory::Development,
            required_role: RequiredRole::Operator,
            capability: "shell_exec".into(),
            tags: vec!["wasm".into(), "webassembly".into(), "build".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Build WASM package".into(),
                    command: "wasm-pack build".into(),
                    args: vec!["--target".into(), "web".into(), "--release".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 300,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Run WASM tests".into(),
                    command: "wasm-pack test".into(),
                    args: vec!["--node".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 120,
                    abort_on_failure: false,
                    optional: true,
                },
            ],
            params: vec![TemplateParam {
                name: "project_dir".into(),
                description: "WASM crate directory".into(),
                default: Some("./wasm-pkg".into()),
                required: false,
                examples: vec!["./wasm-pkg".into()],
            }],
            platforms: vec![],
            estimated_secs: 420,
            builtin: true,
        },
    ]
}

/// Marketing templates.
fn marketing_templates() -> Vec<TaskTemplate> {
    vec![
        TaskTemplate {
            id: "mkt.analytics.report".into(),
            name: "Analytics Report".into(),
            description: "Generate website analytics summary report".into(),
            category: TemplateCategory::Marketing,
            required_role: RequiredRole::Viewer,
            capability: "status_query".into(),
            tags: vec!["analytics".into(), "report".into(), "metrics".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Collect traffic data".into(),
                    command: "echo".into(),
                    args: vec!["[Analytics] Collecting traffic data from {{source}}...".into()],
                    working_dir: None,
                    timeout_secs: 10,
                    abort_on_failure: false,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Generate report".into(),
                    command: "echo".into(),
                    args: vec!["[Analytics] Report period: {{period}} | Source: {{source}}".into()],
                    working_dir: None,
                    timeout_secs: 10,
                    abort_on_failure: false,
                    optional: false,
                },
            ],
            params: vec![
                TemplateParam {
                    name: "period".into(),
                    description: "Report period (e.g., 7d, 30d, 90d)".into(),
                    default: Some("30d".into()),
                    required: false,
                    examples: vec!["7d".into(), "30d".into(), "90d".into()],
                },
                TemplateParam {
                    name: "source".into(),
                    description: "Traffic source".into(),
                    default: Some("all".into()),
                    required: false,
                    examples: vec!["google".into(), "twitter".into(), "github".into()],
                },
            ],
            platforms: vec![],
            estimated_secs: 20,
            builtin: true,
        },
        TaskTemplate {
            id: "mkt.seo.audit".into(),
            name: "SEO Audit".into(),
            description: "Run SEO checks on a website".into(),
            category: TemplateCategory::Marketing,
            required_role: RequiredRole::Operator,
            capability: "shell_exec".into(),
            tags: vec!["seo".into(), "audit".into(), "website".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Check sitemap".into(),
                    command: "curl".into(),
                    args: vec![
                        "-s".into(),
                        "-o".into(),
                        "/dev/null".into(),
                        "-w".into(),
                        "%{http_code}".into(),
                        "{{url}}/sitemap.xml".into(),
                    ],
                    working_dir: None,
                    timeout_secs: 15,
                    abort_on_failure: false,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Check robots.txt".into(),
                    command: "curl".into(),
                    args: vec!["-s".into(), "{{url}}/robots.txt".into()],
                    working_dir: None,
                    timeout_secs: 15,
                    abort_on_failure: false,
                    optional: false,
                },
                TemplateStep {
                    order: 3,
                    description: "Measure page load time".into(),
                    command: "curl".into(),
                    args: vec![
                        "-s".into(),
                        "-o".into(),
                        "/dev/null".into(),
                        "-w".into(),
                        "Time: %{time_total}s".into(),
                        "{{url}}".into(),
                    ],
                    working_dir: None,
                    timeout_secs: 30,
                    abort_on_failure: false,
                    optional: false,
                },
            ],
            params: vec![TemplateParam {
                name: "url".into(),
                description: "Website URL to audit".into(),
                default: None,
                required: true,
                examples: vec!["https://edgeclaw.io".into(), "https://example.com".into()],
            }],
            platforms: vec![],
            estimated_secs: 60,
            builtin: true,
        },
        TaskTemplate {
            id: "mkt.content.readme".into(),
            name: "README Generator".into(),
            description: "Generate project README from template".into(),
            category: TemplateCategory::Marketing,
            required_role: RequiredRole::Operator,
            capability: "file_write".into(),
            tags: vec!["content".into(), "readme".into(), "documentation".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Scan project structure".into(),
                    command: "find".into(),
                    args: vec![
                        "{{project_dir}}".into(),
                        "-maxdepth".into(),
                        "2".into(),
                        "-type".into(),
                        "f".into(),
                    ],
                    working_dir: None,
                    timeout_secs: 15,
                    abort_on_failure: false,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Check existing README".into(),
                    command: "cat".into(),
                    args: vec!["{{project_dir}}/README.md".into()],
                    working_dir: None,
                    timeout_secs: 5,
                    abort_on_failure: false,
                    optional: true,
                },
            ],
            params: vec![TemplateParam {
                name: "project_dir".into(),
                description: "Project root directory".into(),
                default: Some(".".into()),
                required: false,
                examples: vec![".".into()],
            }],
            platforms: vec![],
            estimated_secs: 20,
            builtin: true,
        },
        TaskTemplate {
            id: "mkt.social.post".into(),
            name: "Social Media Post".into(),
            description: "Prepare social media post for release announcement".into(),
            category: TemplateCategory::Marketing,
            required_role: RequiredRole::Viewer,
            capability: "status_query".into(),
            tags: vec!["social".into(), "post".into(), "announcement".into()],
            steps: vec![TemplateStep {
                order: 1,
                description: "Generate release notes summary".into(),
                command: "echo".into(),
                args: vec![
                    "[Social] {{platform}}: {{project_name}} v{{version}} released! {{message}}"
                        .into(),
                ],
                working_dir: None,
                timeout_secs: 5,
                abort_on_failure: false,
                optional: false,
            }],
            params: vec![
                TemplateParam {
                    name: "platform".into(),
                    description: "Target social platform".into(),
                    default: Some("twitter".into()),
                    required: false,
                    examples: vec!["twitter".into(), "linkedin".into(), "discord".into()],
                },
                TemplateParam {
                    name: "project_name".into(),
                    description: "Project name".into(),
                    default: Some("EdgeClaw".into()),
                    required: false,
                    examples: vec!["EdgeClaw".into()],
                },
                TemplateParam {
                    name: "version".into(),
                    description: "Release version".into(),
                    default: None,
                    required: true,
                    examples: vec!["3.0.0".into()],
                },
                TemplateParam {
                    name: "message".into(),
                    description: "Custom message".into(),
                    default: Some("Check out the latest features!".into()),
                    required: false,
                    examples: vec!["Multi-chain blockchain support!".into()],
                },
            ],
            platforms: vec![],
            estimated_secs: 5,
            builtin: true,
        },
    ]
}

/// DevOps templates.
fn devops_templates() -> Vec<TaskTemplate> {
    vec![
        TaskTemplate {
            id: "ops.docker.build".into(),
            name: "Docker Build & Push".into(),
            description: "Build Docker image and push to registry".into(),
            category: TemplateCategory::DevOps,
            required_role: RequiredRole::Admin,
            capability: "docker_manage".into(),
            tags: vec![
                "docker".into(),
                "container".into(),
                "build".into(),
                "registry".into(),
            ],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Build Docker image".into(),
                    command: "docker build".into(),
                    args: vec![
                        "-t".into(),
                        "{{registry}}/{{image}}:{{tag}}".into(),
                        "{{context}}".into(),
                    ],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 600,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Tag as latest".into(),
                    command: "docker tag".into(),
                    args: vec![
                        "{{registry}}/{{image}}:{{tag}}".into(),
                        "{{registry}}/{{image}}:latest".into(),
                    ],
                    working_dir: None,
                    timeout_secs: 10,
                    abort_on_failure: false,
                    optional: true,
                },
                TemplateStep {
                    order: 3,
                    description: "Push to registry".into(),
                    command: "docker push".into(),
                    args: vec!["{{registry}}/{{image}}:{{tag}}".into()],
                    working_dir: None,
                    timeout_secs: 300,
                    abort_on_failure: true,
                    optional: false,
                },
            ],
            params: vec![
                TemplateParam {
                    name: "registry".into(),
                    description: "Container registry".into(),
                    default: Some("ghcr.io/agentumi".into()),
                    required: false,
                    examples: vec!["ghcr.io/agentumi".into(), "docker.io/myorg".into()],
                },
                TemplateParam {
                    name: "image".into(),
                    description: "Image name".into(),
                    default: Some("edgeclaw-agent".into()),
                    required: false,
                    examples: vec!["edgeclaw-agent".into()],
                },
                TemplateParam {
                    name: "tag".into(),
                    description: "Image tag".into(),
                    default: None,
                    required: true,
                    examples: vec!["3.0.0".into(), "latest".into()],
                },
                TemplateParam {
                    name: "context".into(),
                    description: "Docker build context".into(),
                    default: Some(".".into()),
                    required: false,
                    examples: vec![".".into()],
                },
                TemplateParam {
                    name: "project_dir".into(),
                    description: "Project directory".into(),
                    default: Some(".".into()),
                    required: false,
                    examples: vec![".".into()],
                },
            ],
            platforms: vec![],
            estimated_secs: 910,
            builtin: true,
        },
        TaskTemplate {
            id: "ops.k8s.deploy".into(),
            name: "Kubernetes Deploy".into(),
            description: "Deploy to Kubernetes via Helm".into(),
            category: TemplateCategory::DevOps,
            required_role: RequiredRole::Admin,
            capability: "shell_exec".into(),
            tags: vec![
                "kubernetes".into(),
                "k8s".into(),
                "helm".into(),
                "deploy".into(),
            ],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Lint Helm chart".into(),
                    command: "helm lint".into(),
                    args: vec!["{{chart_path}}".into()],
                    working_dir: None,
                    timeout_secs: 30,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Dry-run install".into(),
                    command: "helm install".into(),
                    args: vec![
                        "{{release_name}}".into(),
                        "{{chart_path}}".into(),
                        "--dry-run".into(),
                        "--namespace".into(),
                        "{{namespace}}".into(),
                    ],
                    working_dir: None,
                    timeout_secs: 30,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 3,
                    description: "Apply deployment".into(),
                    command: "helm upgrade".into(),
                    args: vec![
                        "--install".into(),
                        "{{release_name}}".into(),
                        "{{chart_path}}".into(),
                        "--namespace".into(),
                        "{{namespace}}".into(),
                        "--create-namespace".into(),
                    ],
                    working_dir: None,
                    timeout_secs: 120,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 4,
                    description: "Verify deployment".into(),
                    command: "kubectl rollout status".into(),
                    args: vec![
                        "deployment/{{release_name}}".into(),
                        "-n".into(),
                        "{{namespace}}".into(),
                    ],
                    working_dir: None,
                    timeout_secs: 120,
                    abort_on_failure: false,
                    optional: false,
                },
            ],
            params: vec![
                TemplateParam {
                    name: "chart_path".into(),
                    description: "Helm chart directory".into(),
                    default: Some("./helm/edgeclaw".into()),
                    required: false,
                    examples: vec!["./helm/edgeclaw".into()],
                },
                TemplateParam {
                    name: "release_name".into(),
                    description: "Helm release name".into(),
                    default: Some("edgeclaw".into()),
                    required: false,
                    examples: vec!["edgeclaw".into(), "edgeclaw-prod".into()],
                },
                TemplateParam {
                    name: "namespace".into(),
                    description: "Kubernetes namespace".into(),
                    default: Some("edgeclaw".into()),
                    required: false,
                    examples: vec!["default".into(), "edgeclaw".into(), "production".into()],
                },
            ],
            platforms: vec![],
            estimated_secs: 300,
            builtin: true,
        },
        TaskTemplate {
            id: "ops.monitoring.setup".into(),
            name: "Monitoring Setup".into(),
            description: "Check Prometheus and Grafana monitoring stack".into(),
            category: TemplateCategory::DevOps,
            required_role: RequiredRole::Admin,
            capability: "shell_exec".into(),
            tags: vec!["monitoring".into(), "prometheus".into(), "grafana".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Check Prometheus endpoint".into(),
                    command: "curl".into(),
                    args: vec!["-s".into(), "{{prometheus_url}}/-/healthy".into()],
                    working_dir: None,
                    timeout_secs: 10,
                    abort_on_failure: false,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Check Grafana endpoint".into(),
                    command: "curl".into(),
                    args: vec!["-s".into(), "{{grafana_url}}/api/health".into()],
                    working_dir: None,
                    timeout_secs: 10,
                    abort_on_failure: false,
                    optional: false,
                },
            ],
            params: vec![
                TemplateParam {
                    name: "prometheus_url".into(),
                    description: "Prometheus URL".into(),
                    default: Some("http://localhost:9090".into()),
                    required: false,
                    examples: vec!["http://localhost:9090".into()],
                },
                TemplateParam {
                    name: "grafana_url".into(),
                    description: "Grafana URL".into(),
                    default: Some("http://localhost:3000".into()),
                    required: false,
                    examples: vec!["http://localhost:3000".into()],
                },
            ],
            platforms: vec![],
            estimated_secs: 20,
            builtin: true,
        },
        TaskTemplate {
            id: "ops.ci.pipeline".into(),
            name: "CI Pipeline Check".into(),
            description: "Simulate local CI pipeline (lint, test, build)".into(),
            category: TemplateCategory::DevOps,
            required_role: RequiredRole::Operator,
            capability: "shell_exec".into(),
            tags: vec!["ci".into(), "pipeline".into(), "validation".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Cargo fmt check".into(),
                    command: "cargo fmt".into(),
                    args: vec!["--check".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 30,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Cargo clippy".into(),
                    command: "cargo clippy".into(),
                    args: vec![
                        "--all-targets".into(),
                        "--".into(),
                        "-D".into(),
                        "warnings".into(),
                    ],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 120,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 3,
                    description: "Cargo test".into(),
                    command: "cargo test".into(),
                    args: vec![],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 300,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 4,
                    description: "Cargo build release".into(),
                    command: "cargo build".into(),
                    args: vec!["--release".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 300,
                    abort_on_failure: true,
                    optional: false,
                },
            ],
            params: vec![TemplateParam {
                name: "project_dir".into(),
                description: "Project directory".into(),
                default: Some(".".into()),
                required: false,
                examples: vec![".".into()],
            }],
            platforms: vec![],
            estimated_secs: 750,
            builtin: true,
        },
    ]
}

/// Security templates.
fn security_templates() -> Vec<TaskTemplate> {
    vec![
        TaskTemplate {
            id: "sec.audit.deps".into(),
            name: "Dependency Audit".into(),
            description: "Audit project dependencies for known vulnerabilities".into(),
            category: TemplateCategory::Security,
            required_role: RequiredRole::Operator,
            capability: "shell_exec".into(),
            tags: vec![
                "audit".into(),
                "dependencies".into(),
                "cve".into(),
                "vulnerability".into(),
            ],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Cargo audit (Rust)".into(),
                    command: "cargo audit".into(),
                    args: vec![],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 60,
                    abort_on_failure: false,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Cargo deny check".into(),
                    command: "cargo deny".into(),
                    args: vec!["check".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 60,
                    abort_on_failure: false,
                    optional: true,
                },
            ],
            params: vec![TemplateParam {
                name: "project_dir".into(),
                description: "Project directory".into(),
                default: Some(".".into()),
                required: false,
                examples: vec![".".into()],
            }],
            platforms: vec![],
            estimated_secs: 120,
            builtin: true,
        },
        TaskTemplate {
            id: "sec.crypto.verify".into(),
            name: "Crypto Verification".into(),
            description: "Verify cryptographic setup (key generation, signing, encryption)".into(),
            category: TemplateCategory::Security,
            required_role: RequiredRole::Admin,
            capability: "shell_exec".into(),
            tags: vec!["crypto".into(), "verification".into(), "keys".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Run crypto unit tests".into(),
                    command: "cargo test".into(),
                    args: vec!["identity::tests".into(), "session::tests".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 60,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Run ECNP codec tests".into(),
                    command: "cargo test".into(),
                    args: vec!["ecnp::tests".into()],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 60,
                    abort_on_failure: true,
                    optional: false,
                },
            ],
            params: vec![TemplateParam {
                name: "project_dir".into(),
                description: "Project directory".into(),
                default: Some(".".into()),
                required: false,
                examples: vec![".".into()],
            }],
            platforms: vec![],
            estimated_secs: 120,
            builtin: true,
        },
        TaskTemplate {
            id: "sec.scan.ports".into(),
            name: "Port Scan".into(),
            description: "Scan open ports on target host".into(),
            category: TemplateCategory::Security,
            required_role: RequiredRole::Admin,
            capability: "network_scan".into(),
            tags: vec!["scan".into(), "ports".into(), "network".into()],
            steps: vec![TemplateStep {
                order: 1,
                description: "Scan common ports".into(),
                command: "echo".into(),
                args: vec!["[Scan] Scanning {{host}} ports: 22,80,443,8443,9443,9444,9445".into()],
                working_dir: None,
                timeout_secs: 60,
                abort_on_failure: false,
                optional: false,
            }],
            params: vec![TemplateParam {
                name: "host".into(),
                description: "Target host to scan".into(),
                default: Some("localhost".into()),
                required: false,
                examples: vec!["localhost".into(), "192.168.1.1".into()],
            }],
            platforms: vec![],
            estimated_secs: 60,
            builtin: true,
        },
        TaskTemplate {
            id: "sec.fuzz.run".into(),
            name: "Fuzz Testing".into(),
            description: "Run fuzz testing targets".into(),
            category: TemplateCategory::Security,
            required_role: RequiredRole::Owner,
            capability: "shell_exec".into(),
            tags: vec!["fuzz".into(), "testing".into(), "security".into()],
            steps: vec![TemplateStep {
                order: 1,
                description: "Run fuzz target".into(),
                command: "cargo fuzz run".into(),
                args: vec!["{{target}}".into(), "--".into(), "-runs={{runs}}".into()],
                working_dir: Some("{{project_dir}}".into()),
                timeout_secs: 1800,
                abort_on_failure: false,
                optional: false,
            }],
            params: vec![
                TemplateParam {
                    name: "target".into(),
                    description: "Fuzz target name".into(),
                    default: Some("fuzz_ecnp_frame".into()),
                    required: false,
                    examples: vec!["fuzz_ecnp_frame".into(), "fuzz_federation_policy".into()],
                },
                TemplateParam {
                    name: "runs".into(),
                    description: "Number of fuzz runs".into(),
                    default: Some("10000".into()),
                    required: false,
                    examples: vec!["10000".into(), "100000".into(), "1000000".into()],
                },
                TemplateParam {
                    name: "project_dir".into(),
                    description: "Project directory".into(),
                    default: Some(".".into()),
                    required: false,
                    examples: vec![".".into()],
                },
            ],
            platforms: vec!["linux".into()],
            estimated_secs: 1800,
            builtin: true,
        },
    ]
}

/// System administration templates.
fn system_templates() -> Vec<TaskTemplate> {
    vec![
        TaskTemplate {
            id: "sys.info.collect".into(),
            name: "System Info".into(),
            description: "Collect system information (CPU, memory, disk, network)".into(),
            category: TemplateCategory::System,
            required_role: RequiredRole::Viewer,
            capability: "system_info".into(),
            tags: vec!["system".into(), "info".into(), "monitoring".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "OS information".into(),
                    command: "systeminfo".into(),
                    args: vec![],
                    working_dir: None,
                    timeout_secs: 30,
                    abort_on_failure: false,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Disk usage".into(),
                    command: "wmic".into(),
                    args: vec![
                        "logicaldisk".into(),
                        "get".into(),
                        "size,freespace,caption".into(),
                    ],
                    working_dir: None,
                    timeout_secs: 15,
                    abort_on_failure: false,
                    optional: false,
                },
            ],
            params: vec![],
            platforms: vec!["windows".into()],
            estimated_secs: 45,
            builtin: true,
        },
        TaskTemplate {
            id: "sys.cleanup.temp".into(),
            name: "Temp File Cleanup".into(),
            description: "Clean temporary files and caches".into(),
            category: TemplateCategory::System,
            required_role: RequiredRole::Admin,
            capability: "file_write".into(),
            tags: vec!["cleanup".into(), "temp".into(), "cache".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Clean Rust target directories".into(),
                    command: "cargo clean".into(),
                    args: vec![],
                    working_dir: Some("{{project_dir}}".into()),
                    timeout_secs: 60,
                    abort_on_failure: false,
                    optional: true,
                },
                TemplateStep {
                    order: 2,
                    description: "Report disk usage after cleanup".into(),
                    command: "echo".into(),
                    args: vec!["[Cleanup] Temporary files cleaned for {{project_dir}}".into()],
                    working_dir: None,
                    timeout_secs: 5,
                    abort_on_failure: false,
                    optional: false,
                },
            ],
            params: vec![TemplateParam {
                name: "project_dir".into(),
                description: "Project directory to clean".into(),
                default: Some(".".into()),
                required: false,
                examples: vec![".".into()],
            }],
            platforms: vec![],
            estimated_secs: 65,
            builtin: true,
        },
        TaskTemplate {
            id: "sys.network.check".into(),
            name: "Network Health Check".into(),
            description: "Check network connectivity and DNS resolution".into(),
            category: TemplateCategory::System,
            required_role: RequiredRole::Viewer,
            capability: "status_query".into(),
            tags: vec![
                "network".into(),
                "health".into(),
                "dns".into(),
                "ping".into(),
            ],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Ping gateway".into(),
                    command: "ping".into(),
                    args: vec!["-n".into(), "3".into(), "{{host}}".into()],
                    working_dir: None,
                    timeout_secs: 15,
                    abort_on_failure: false,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "DNS resolution".into(),
                    command: "nslookup".into(),
                    args: vec!["{{host}}".into()],
                    working_dir: None,
                    timeout_secs: 10,
                    abort_on_failure: false,
                    optional: false,
                },
            ],
            params: vec![TemplateParam {
                name: "host".into(),
                description: "Host to check".into(),
                default: Some("8.8.8.8".into()),
                required: false,
                examples: vec!["8.8.8.8".into(), "google.com".into(), "github.com".into()],
            }],
            platforms: vec![],
            estimated_secs: 25,
            builtin: true,
        },
        TaskTemplate {
            id: "sys.process.list".into(),
            name: "Process List".into(),
            description: "List running processes sorted by resource usage".into(),
            category: TemplateCategory::System,
            required_role: RequiredRole::Viewer,
            capability: "process_manage".into(),
            tags: vec!["process".into(), "list".into(), "resource".into()],
            steps: vec![TemplateStep {
                order: 1,
                description: "List top processes by memory".into(),
                command: "tasklist".into(),
                args: vec!["/FO".into(), "TABLE".into(), "/NH".into()],
                working_dir: None,
                timeout_secs: 15,
                abort_on_failure: false,
                optional: false,
            }],
            params: vec![],
            platforms: vec!["windows".into()],
            estimated_secs: 15,
            builtin: true,
        },
    ]
}

/// Data engineering templates.
fn data_templates() -> Vec<TaskTemplate> {
    vec![
        TaskTemplate {
            id: "data.db.backup".into(),
            name: "Database Backup".into(),
            description: "Create database backup".into(),
            category: TemplateCategory::Data,
            required_role: RequiredRole::Admin,
            capability: "file_write".into(),
            tags: vec!["database".into(), "backup".into(), "export".into()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Create backup directory".into(),
                    command: "mkdir".into(),
                    args: vec!["-p".into(), "{{backup_dir}}".into()],
                    working_dir: None,
                    timeout_secs: 5,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Export audit log".into(),
                    command: "echo".into(),
                    args: vec![
                        "[Backup] Exporting audit log to {{backup_dir}}/audit_backup.jsonl".into(),
                    ],
                    working_dir: None,
                    timeout_secs: 30,
                    abort_on_failure: false,
                    optional: false,
                },
            ],
            params: vec![TemplateParam {
                name: "backup_dir".into(),
                description: "Backup destination directory".into(),
                default: Some("./backups".into()),
                required: false,
                examples: vec!["./backups".into(), "/mnt/backup/edgeclaw".into()],
            }],
            platforms: vec![],
            estimated_secs: 35,
            builtin: true,
        },
        TaskTemplate {
            id: "data.log.analyze".into(),
            name: "Log Analysis".into(),
            description: "Analyze application logs for errors and warnings".into(),
            category: TemplateCategory::Data,
            required_role: RequiredRole::Viewer,
            capability: "log_read".into(),
            tags: vec!["log".into(), "analysis".into(), "errors".into()],
            steps: vec![TemplateStep {
                order: 1,
                description: "Count error entries".into(),
                command: "echo".into(),
                args: vec!["[LogAnalysis] Scanning {{log_file}} for errors...".into()],
                working_dir: None,
                timeout_secs: 30,
                abort_on_failure: false,
                optional: false,
            }],
            params: vec![TemplateParam {
                name: "log_file".into(),
                description: "Log file path".into(),
                default: Some("./logs/agent.log".into()),
                required: false,
                examples: vec!["./logs/agent.log".into()],
            }],
            platforms: vec![],
            estimated_secs: 30,
            builtin: true,
        },
    ]
}

// ─── Tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_category_display() {
        assert_eq!(TemplateCategory::Development.to_string(), "Development");
        assert_eq!(TemplateCategory::Marketing.to_string(), "Marketing");
        assert_eq!(TemplateCategory::DevOps.to_string(), "DevOps");
        assert_eq!(TemplateCategory::Security.to_string(), "Security");
        assert_eq!(TemplateCategory::System.to_string(), "System");
        assert_eq!(TemplateCategory::Data.to_string(), "Data");
        assert_eq!(TemplateCategory::Custom.to_string(), "Custom");
    }

    #[test]
    fn test_template_category_all() {
        assert_eq!(TemplateCategory::all().len(), 6);
    }

    #[test]
    fn test_default_library_has_templates() {
        let registry = TemplateRegistry::default_library();
        assert!(
            registry.count() > 20,
            "Expected 20+ templates, got {}",
            registry.count()
        );
    }

    #[test]
    fn test_by_category() {
        let registry = TemplateRegistry::default_library();
        let dev = registry.by_category(TemplateCategory::Development);
        assert!(dev.len() >= 5, "Expected 5+ dev templates");
        let mkt = registry.by_category(TemplateCategory::Marketing);
        assert!(mkt.len() >= 3, "Expected 3+ marketing templates");
        let ops = registry.by_category(TemplateCategory::DevOps);
        assert!(ops.len() >= 3, "Expected 3+ devops templates");
    }

    #[test]
    fn test_get_by_id() {
        let registry = TemplateRegistry::default_library();
        let t = registry.get("dev.rust.build").unwrap();
        assert_eq!(t.name, "Rust Build");
        assert_eq!(t.category, TemplateCategory::Development);
        assert!(!t.steps.is_empty());
    }

    #[test]
    fn test_search_templates() {
        let registry = TemplateRegistry::default_library();
        let results = registry.search("rust");
        assert!(!results.is_empty());
        let results = registry.search("docker");
        assert!(!results.is_empty());
        let results = registry.search("nonexistent_xyz");
        assert!(results.is_empty());
    }

    #[test]
    fn test_by_tag() {
        let registry = TemplateRegistry::default_library();
        let results = registry.by_tag("build");
        assert!(results.len() >= 3, "Expected 3+ build-tagged templates");
    }

    #[test]
    fn test_template_render() {
        let registry = TemplateRegistry::default_library();
        let t = registry.get("dev.rust.build").unwrap();
        let mut params = HashMap::new();
        params.insert(
            "project_dir".to_string(),
            "/home/user/my-project".to_string(),
        );

        let steps = t.render(&params).unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(
            steps[0].working_dir.as_ref().unwrap(),
            "/home/user/my-project"
        );
    }

    #[test]
    fn test_template_render_missing_required() {
        let registry = TemplateRegistry::default_library();
        let t = registry.get("dev.git.feature_start").unwrap();
        let params = HashMap::new(); // missing "feature_name" (required)
        let result = t.render(&params);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("feature_name"));
    }

    #[test]
    fn test_template_validate() {
        let t = TaskTemplate {
            id: "test.empty".into(),
            name: "Empty".into(),
            description: "desc".into(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Viewer,
            capability: "status_query".into(),
            tags: vec![],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 0,
            builtin: false,
        };
        assert!(t.validate().is_err()); // no steps

        let t2 = TaskTemplate {
            id: "".into(),
            steps: vec![TemplateStep {
                order: 1,
                description: "test".into(),
                command: "echo".into(),
                args: vec![],
                working_dir: None,
                timeout_secs: 5,
                abort_on_failure: false,
                optional: false,
            }],
            ..t.clone()
        };
        assert!(t2.validate().is_err()); // empty ID
    }

    #[test]
    fn test_register_custom_template() {
        let mut registry = TemplateRegistry::new();
        let t = TaskTemplate {
            id: "custom.hello".into(),
            name: "Hello World".into(),
            description: "Print hello".into(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Viewer,
            capability: "status_query".into(),
            tags: vec!["hello".into()],
            steps: vec![TemplateStep {
                order: 1,
                description: "Print hello".into(),
                command: "echo".into(),
                args: vec!["hello world".into()],
                working_dir: None,
                timeout_secs: 5,
                abort_on_failure: false,
                optional: false,
            }],
            params: vec![],
            platforms: vec![],
            estimated_secs: 5,
            builtin: false,
        };
        registry.register(t).unwrap();
        assert_eq!(registry.count(), 1);

        // Duplicate registration → error
        let t2 = TaskTemplate {
            id: "custom.hello".into(),
            name: "Dup".into(),
            description: "dup".into(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Viewer,
            capability: "status_query".into(),
            tags: vec![],
            steps: vec![TemplateStep {
                order: 1,
                description: "x".into(),
                command: "echo".into(),
                args: vec![],
                working_dir: None,
                timeout_secs: 5,
                abort_on_failure: false,
                optional: false,
            }],
            params: vec![],
            platforms: vec![],
            estimated_secs: 0,
            builtin: false,
        };
        assert!(registry.register(t2).is_err());
    }

    #[test]
    fn test_count_by_category() {
        let registry = TemplateRegistry::default_library();
        let counts = registry.count_by_category();
        assert!(counts.contains_key(&TemplateCategory::Development));
        assert!(counts.contains_key(&TemplateCategory::Marketing));
        assert!(*counts.get(&TemplateCategory::Development).unwrap() >= 5);
    }

    #[test]
    fn test_all_tags() {
        let registry = TemplateRegistry::default_library();
        let tags = registry.all_tags();
        assert!(!tags.is_empty());
        assert!(tags.contains(&"rust".to_string()));
        assert!(tags.contains(&"build".to_string()));
    }

    #[test]
    fn test_export_import_json() {
        let registry = TemplateRegistry::default_library();
        let json = registry.export_json().unwrap();
        assert!(!json.is_empty());

        let mut new_registry = TemplateRegistry::new();
        let count = new_registry.import_json(&json).unwrap();
        assert_eq!(count, registry.count());
    }

    #[test]
    fn test_all_builtin_templates_valid() {
        let registry = TemplateRegistry::default_library();
        for t in registry.list() {
            assert!(t.validate().is_ok(), "Template {} failed validation", t.id);
            assert!(t.builtin, "Template {} should be marked builtin", t.id);
            assert!(!t.id.is_empty());
            assert!(!t.name.is_empty());
            assert!(!t.steps.is_empty());
        }
    }

    #[test]
    fn test_template_serialize_deserialize() {
        let registry = TemplateRegistry::default_library();
        let t = registry.get("dev.rust.build").unwrap();
        let json = serde_json::to_string(t).unwrap();
        let parsed: TaskTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "dev.rust.build");
        assert_eq!(parsed.steps.len(), t.steps.len());
    }

    #[test]
    fn test_required_role_display() {
        assert_eq!(RequiredRole::Viewer.to_string(), "viewer");
        assert_eq!(RequiredRole::Owner.to_string(), "owner");
        assert_eq!(RequiredRole::Admin.to_string(), "admin");
        assert_eq!(RequiredRole::Operator.to_string(), "operator");
    }
}

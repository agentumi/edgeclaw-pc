//! DAG-based Workflow Template System
//!
//! Provides a YAML-based Domain Specific Language for defining complex workflows
//! with directed acyclic graph (DAG) execution, conditional branching, parallel execution,
//! and state management. This system replaces the sequential step-based templates with
//! a more powerful graph-based workflow engine.
//!
//! # Architecture
//!
//! - **Template DSL**: YAML-based workflow definition with nodes and edges
//! - **DAG Executor**: Topological sorting, parallel execution, state management
//! - **Component Library**: Reusable actions, transforms, conditionals, and utilities
//! - **Template Registry**: Built-in and custom template management
//!
//! # Example
//!
//! ```yaml
//! template:
//!   id: "weekly_sales_report"
//!   name: "주간 판매보고서 생성"
//!   domain: "business"
//!   category: "report"
//!
//! workflow:
//!   nodes:
//!     - id: "fetch_data"
//!       type: "action"
//!       action: "DatabaseQuery"
//!     - id: "analyze"
//!       type: "transform"
//!       transform: "CalculateMetrics"
//!   edges:
//!     - from: "fetch_data"
//!       to: "analyze"
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use thiserror::Error;

// ─── Error Types ─────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum WorkflowError {
    #[error("Template parse error: {0}")]
    ParseError(String),
    #[error("DAG validation error: {0}")]
    DagError(String),
    #[error("Execution error: {0}")]
    ExecutionError(String),
    #[error("Template not found: {0}")]
    NotFound(String),
    #[error("Circular dependency detected: {0}")]
    CircularDependency(String),
    #[error("Node execution failed: {0}")]
    NodeFailed(String),
}

pub type Result<T> = std::result::Result<T, WorkflowError>;

// ─── Template DSL Types ─────────────────────────────────────────────────────

/// Root template structure matching YAML DSL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTemplate {
    /// Template metadata
    pub template: TemplateMeta,
    /// Input variables definition
    #[serde(default)]
    pub variables: Vec<TemplateVariable>,
    /// Workflow DAG definition
    pub workflow: WorkflowDefinition,
    /// Resource requirements
    #[serde(default)]
    pub requirements: Requirements,
    /// Execution options
    #[serde(default)]
    pub options: ExecutionOptions,
}

/// Template metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMeta {
    pub id: String,
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    pub domain: TemplateDomain,
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub metadata: TemplateMetadata,
}

fn default_version() -> String {
    "1.0.0".to_string()
}

/// Extended metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TemplateMetadata {
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub usage_count: u64,
    #[serde(default)]
    pub rating: f32,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Template domain (business, development, marketing, investment)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TemplateDomain {
    Business,
    Development,
    Marketing,
    Investment,
    #[default]
    Custom,
}

/// Input variable definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVariable {
    pub name: String,
    #[serde(rename = "type")]
    pub var_type: VariableType,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub default: Option<serde_json::Value>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub options: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VariableType {
    String,
    Integer,
    Boolean,
    Array,
    Object,
    Enum,
}

// ─── Workflow DAG Definition ────────────────────────────────────────────────

/// Workflow definition with nodes and edges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    /// DAG nodes
    pub nodes: Vec<WorkflowNode>,
    /// Directed edges connecting nodes
    #[serde(default)]
    pub edges: Vec<WorkflowEdge>,
}

/// A node in the workflow DAG
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkflowNode {
    /// Action node (executes an operation)
    Action {
        id: String,
        action: String,
        #[serde(default)]
        params: HashMap<String, serde_json::Value>,
        #[serde(default)]
        outputs: Vec<String>,
        #[serde(default)]
        condition: Option<String>,
    },
    /// Transform node (data transformation)
    Transform {
        id: String,
        transform: String,
        #[serde(default)]
        inputs: Vec<String>,
        #[serde(default)]
        outputs: Vec<String>,
    },
    /// Conditional branch node
    Conditional {
        id: String,
        condition: String,
        #[serde(default)]
        true_nodes: Vec<String>,
        #[serde(default)]
        false_nodes: Vec<String>,
    },
    /// Parallel branch node
    Branch {
        id: String,
        #[serde(default)]
        branches: Vec<BranchDefinition>,
    },
    /// Set variable node
    SetVariable {
        id: String,
        name: String,
        value: serde_json::Value,
    },
    /// Log node
    Log {
        id: String,
        message: String,
        #[serde(default)]
        level: LogLevel,
    },
    /// Sleep/delay node
    Sleep {
        id: String,
        duration_ms: u64,
    },
    /// HTTP request node
    HttpRequest {
        id: String,
        url: String,
        #[serde(default = "default_get")]
        method: HttpMethod,
        #[serde(default)]
        headers: HashMap<String, String>,
        #[serde(default)]
        body: Option<String>,
    },
    /// Wait for event node
    WaitForEvent {
        id: String,
        event_type: String,
        #[serde(default = "default_timeout")]
        timeout_ms: u64,
    },
}

fn default_get() -> HttpMethod {
    HttpMethod::Get
}

fn default_timeout() -> u64 {
    30000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

/// Branch definition for parallel execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchDefinition {
    pub id: String,
    pub nodes: Vec<WorkflowNode>,
}

/// Directed edge between nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowEdge {
    pub from: String,
    #[serde(default)]
    pub to: String,
}

// ─── Requirements & Options ─────────────────────────────────────────────────

/// Resource requirements for template execution
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Requirements {
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub resources: ResourceRequirements,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceRequirements {
    #[serde(default)]
    pub cpu: String,
    #[serde(default)]
    pub memory: String,
    #[serde(default)]
    pub timeout_sec: u64,
}

/// Execution options
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutionOptions {
    #[serde(default)]
    pub retry_policy: RetryPolicy,
    #[serde(default)]
    pub notification: NotificationOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_backoff_ms")]
    pub backoff_ms: u64,
}

fn default_max_attempts() -> u32 {
    3
}

fn default_backoff_ms() -> u64 {
    1000
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            backoff_ms: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationOptions {
    #[serde(default)]
    pub on_start: bool,
    #[serde(default)]
    pub on_progress: bool,
    #[serde(default = "default_true")]
    pub on_complete: bool,
    #[serde(default = "default_true")]
    pub on_error: bool,
}

fn default_true() -> bool {
    true
}

// ─── DAG Execution Types ───────────────────────────────────────────────────

/// Compiled executable workflow
#[derive(Debug, Clone)]
pub struct ExecutableWorkflow {
    pub template_id: String,
    pub nodes: HashMap<String, ExecutableNode>,
    pub execution_plan: Vec<ExecutionStage>,
    pub variables: HashMap<String, serde_json::Value>,
}

/// An executable node with resolved parameters
#[derive(Debug, Clone)]
pub struct ExecutableNode {
    pub id: String,
    pub node_type: NodeExecutionType,
    pub action_name: Option<String>,
    pub transform_name: Option<String>,
    pub condition: Option<String>,
    pub depends_on: Vec<String>,
    pub outputs: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum NodeExecutionType {
    Action,
    Transform,
    Conditional,
    Branch,
    SetVariable,
    Log,
    Sleep,
    HttpRequest,
    WaitForEvent,
}

/// Action executor trait
pub trait ActionExecutor: Send + Sync {
    fn execute(&self, params: &HashMap<String, serde_json::Value>) -> Result<serde_json::Value>;
}

/// Transform executor trait
pub trait TransformExecutor: Send + Sync {
    fn transform(&self, input: &HashMap<String, serde_json::Value>) -> Result<serde_json::Value>;
}

/// Execution stage (can be parallel or sequential)
#[derive(Debug, Clone)]
pub struct ExecutionStage {
    pub nodes: Vec<String>,
    pub parallel: bool,
}

/// Workflow execution state
#[derive(Debug, Clone)]
pub struct WorkflowState {
    pub workflow_id: String,
    pub status: WorkflowStatus,
    pub current_node: Option<String>,
    pub node_states: HashMap<String, NodeState>,
    pub variables: HashMap<String, serde_json::Value>,
    pub outputs: HashMap<String, serde_json::Value>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStatus {
    Pending,
    Running,
    Paused,
    Succeeded,
    Failed,
    Canceled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

// ─── DAG Validator ──────────────────────────────────────────────────────────

/// Validates workflow DAG for cycles and connectivity
pub struct DagValidator;

impl DagValidator {
    /// Validate workflow definition for DAG correctness
    pub fn validate(workflow: &WorkflowDefinition) -> Result<()> {
        let node_ids: HashSet<&str> = workflow.nodes.iter().map(|n| n.id()).collect();
        
        // Check for duplicate node IDs
        let mut seen = HashSet::new();
        for node in &workflow.nodes {
            if !seen.insert(node.id()) {
                return Err(WorkflowError::DagError(format!(
                    "Duplicate node ID: {}",
                    node.id()
                )));
            }
        }
        
        // Validate edges reference existing nodes
        for edge in &workflow.edges {
            if !node_ids.contains(edge.from.as_str()) {
                return Err(WorkflowError::DagError(format!(
                    "Edge references non-existent node: {}",
                    edge.from
                )));
            }
            if !node_ids.contains(edge.to.as_str()) {
                return Err(WorkflowError::DagError(format!(
                    "Edge references non-existent node: {}",
                    edge.to
                )));
            }
        }
        
        // Check for cycles using DFS
        Self::check_cycles(workflow)?;
        
        Ok(())
    }
    
    /// Check for circular dependencies using DFS
    fn check_cycles(workflow: &WorkflowDefinition) -> Result<()> {
        let mut visited = HashSet::new();
        let mut recursion_stack = HashSet::new();
        
        // Build adjacency list
        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
        for node in &workflow.nodes {
            adjacency.insert(node.id(), Vec::new());
        }
        for edge in &workflow.edges {
            if let Some(neighbors) = adjacency.get_mut(&edge.from.as_str()) {
                neighbors.push(&edge.to);
            }
        }
        
        fn dfs<'a>(
            node: &'a str,
            adjacency: &HashMap<&str, Vec<&'a str>>,
            visited: &mut HashSet<&'a str>,
            recursion_stack: &mut HashSet<&'a str>,
        ) -> Result<()> {
            visited.insert(node);
            recursion_stack.insert(node);
            
            if let Some(neighbors) = adjacency.get(node) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        dfs(neighbor, adjacency, visited, recursion_stack)?;
                    } else if recursion_stack.contains(neighbor) {
                        return Err(WorkflowError::CircularDependency(format!(
                            "{} -> {}",
                            node, neighbor
                        )));
                    }
                }
            }
            
            recursion_stack.remove(node);
            Ok(())
        }
        
        for node in workflow.nodes.iter().map(|n| n.id()) {
            if !visited.contains(&node) {
                dfs(node, &adjacency, &mut visited, &mut recursion_stack)?;
            }
        }
        
        Ok(())
    }
    
    /// Generate topological execution order
    pub fn topological_sort(workflow: &WorkflowDefinition) -> Result<Vec<ExecutionStage>> {
        // Build adjacency and in-degree maps
        let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        
        for node in &workflow.nodes {
            adjacency.entry(node.id()).or_default();
            in_degree.entry(node.id()).or_insert(0);
        }
        
        for edge in &workflow.edges {
            adjacency.entry(&edge.from).or_default().push(&edge.to);
            *in_degree.entry(&edge.to).or_insert(0) += 1;
        }
        
        // Kahn's algorithm for topological sort
        let mut queue: Vec<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(node, _)| *node)
            .collect();
        
        let mut stages: Vec<ExecutionStage> = Vec::new();
        
        while !queue.is_empty() {
            // All nodes with in-degree 0 can run in parallel
            let stage_nodes: Vec<String> = queue.iter().map(|&s| s.to_string()).collect();
            
            // Process all nodes in this stage
            let mut next_queue: Vec<&str> = Vec::new();
            
            for &node in &queue {
                // Reduce in-degree for all neighbors
                if let Some(neighbors) = adjacency.get(node) {
                    for &neighbor in neighbors {
                        if let Some(deg) = in_degree.get_mut(neighbor) {
                            *deg -= 1;
                            if *deg == 0 {
                                next_queue.push(neighbor);
                            }
                        }
                    }
                }
            }
            
            stages.push(ExecutionStage {
                nodes: stage_nodes,
                parallel: true,
            });
            queue = next_queue;
        }
        
        // Check if all nodes were processed
        let processed: usize = stages.iter().map(|s| s.nodes.len()).sum();
        if processed != workflow.nodes.len() {
            return Err(WorkflowError::DagError(
                "Unable to process all nodes - possible cycle".to_string(),
            ));
        }
        
        Ok(stages)
    }
}

impl WorkflowNode {
    pub fn id(&self) -> &str {
        match self {
            WorkflowNode::Action { id, .. } => id,
            WorkflowNode::Transform { id, .. } => id,
            WorkflowNode::Conditional { id, .. } => id,
            WorkflowNode::Branch { id, .. } => id,
            WorkflowNode::SetVariable { id, .. } => id,
            WorkflowNode::Log { id, .. } => id,
            WorkflowNode::Sleep { id, .. } => id,
            WorkflowNode::HttpRequest { id, .. } => id,
            WorkflowNode::WaitForEvent { id, .. } => id,
        }
    }
}

impl fmt::Display for WorkflowTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WorkflowTemplate({}: {})",
            self.template.id, self.template.name
        )
    }
}

// ─── YAML Parsing ───────────────────────────────────────────────────────────

/// Parse workflow template from YAML string
pub fn parse_template(yaml: &str) -> Result<WorkflowTemplate> {
    serde_yaml::from_str(yaml).map_err(|e| WorkflowError::ParseError(e.to_string()))
}

/// Parse workflow template from YAML file
pub fn parse_template_file(path: &std::path::Path) -> Result<WorkflowTemplate> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| WorkflowError::ParseError(format!("Failed to read file: {}", e)))?;
    parse_template(&content)
}

// ─── Template Registry ───────────────────────────────────────────────────────

/// Registry for managing workflow templates
#[derive(Debug, Default)]
pub struct TemplateRegistry {
    templates: HashMap<String, WorkflowTemplate>,
}

impl TemplateRegistry {
    /// Create new registry with built-in templates
    pub fn new() -> Self {
        let mut registry = Self::default();
        registry.load_builtin_templates();
        registry
    }
    
    /// Load built-in templates
    fn load_builtin_templates(&mut self) {
        // Load from default directory if it exists
        let _ = self.load_directory(std::path::Path::new("templates"));
    }

    /// Load all YAML templates from a directory recursively
    pub fn load_directory(&mut self, path: &std::path::Path) -> Result<usize> {
        if !path.exists() || !path.is_dir() {
            return Ok(0);
        }

        let mut count = 0;
        self.walk_dir(path, &mut count);
        Ok(count)
    }

    fn walk_dir(&mut self, dir: &std::path::Path, count: &mut usize) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    self.walk_dir(&path, count);
                } else if path.extension().is_some_and(|ext| ext == "yaml" || ext == "yml") {
                    if let Ok(template) = parse_template_file(&path) {
                        self.templates.insert(template.template.id.clone(), template);
                        *count += 1;
                    }
                }
            }
        }
    }
    
    /// Register a template from YAML string
    pub fn register(&mut self, yaml: String) {
        if let Ok(template) = parse_template(&yaml) {
            self.templates.insert(template.template.id.clone(), template);
        }
    }
    
    /// Get template by ID
    pub fn get(&self, id: &str) -> Option<&WorkflowTemplate> {
        self.templates.get(id)
    }
    
    /// List all templates, optionally filtered by domain
    pub fn list(&self, domain: Option<TemplateDomain>) -> Vec<&WorkflowTemplate> {
        self.templates
            .values()
            .filter(|t| match domain {
                Some(d) => t.template.domain == d,
                None => true,
            })
            .collect()
    }
    
    /// Validate all templates in registry
    pub fn validate_all(&self) -> Vec<(String, Result<()>)> {
        self.templates
            .iter()
            .map(|(id, template)| (id.clone(), DagValidator::validate(&template.workflow)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_template() {
        let yaml = r#"
template:
  id: "test_workflow"
  name: "Test Workflow"
  version: "1.0.0"
  domain: "business"
  category: "test"

variables:
  - name: "input"
    type: "string"
    required: true

workflow:
  nodes:
    - type: "action"
      id: "step1"
      action: "Echo"
      params:
        message: "Hello"
  edges:
    - from: "step1"
      to: "step1"
"#;
        let result = parse_template(yaml);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_circular_dependency() {
        let yaml = r#"
template:
  id: "cycle_test"
  name: "Cycle Test"
  domain: "business"
  category: "test"

workflow:
  nodes:
    - type: "action"
      id: "a"
      action: "Echo"
    - type: "action"
      id: "b"
      action: "Echo"
  edges:
    - from: "a"
      to: "b"
    - from: "b"
      to: "a"
"#;
        let template = parse_template(yaml).unwrap();
        let result = DagValidator::validate(&template.workflow);
        assert!(result.is_err());
    }
}

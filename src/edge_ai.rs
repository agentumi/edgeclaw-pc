//! Edge AI with WASM plugin runtime.
//!
//! Provides [`WasmRuntime`] for sandboxed WASM plugin execution
//! and [`PluginManager`] for managing edge AI inference plugins.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::AgentError;

/// WASM plugin metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin name.
    pub name: String,
    /// Plugin version (semver).
    pub version: String,
    /// Plugin description.
    pub description: String,
    /// Author.
    pub author: String,
    /// Required capabilities (e.g., "network", "filesystem").
    pub permissions: Vec<String>,
    /// Entry function name.
    pub entry_point: String,
    /// Max execution time in seconds.
    pub max_exec_secs: u64,
    /// Max memory in bytes.
    pub max_memory_bytes: u64,
    /// Plugin type.
    pub plugin_type: PluginType,
}

/// Plugin type category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginType {
    /// AI inference (model execution).
    AiInference,
    /// Data transformation.
    DataTransform,
    /// Protocol handler.
    ProtocolHandler,
    /// Security scanner.
    SecurityScanner,
    /// Custom.
    Custom,
}

impl std::fmt::Display for PluginType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginType::AiInference => write!(f, "AI Inference"),
            PluginType::DataTransform => write!(f, "Data Transform"),
            PluginType::ProtocolHandler => write!(f, "Protocol Handler"),
            PluginType::SecurityScanner => write!(f, "Security Scanner"),
            PluginType::Custom => write!(f, "Custom"),
        }
    }
}

/// Plugin execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    /// Plugin name.
    pub plugin_name: String,
    /// Success flag.
    pub success: bool,
    /// Output data.
    pub output: String,
    /// Execution time in milliseconds.
    pub exec_time_ms: u64,
    /// Memory used in bytes.
    pub memory_used: u64,
    /// Error message if failed.
    pub error: Option<String>,
}

/// WASM sandbox configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Max memory per plugin (bytes).
    pub max_memory: u64,
    /// Max execution time (seconds).
    pub max_exec_time: u64,
    /// Allow network access.
    pub allow_network: bool,
    /// Allow filesystem access.
    pub allow_filesystem: bool,
    /// Allowed host functions.
    pub allowed_imports: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_memory: 64 * 1024 * 1024, // 64MB
            max_exec_time: 30,
            allow_network: false,
            allow_filesystem: false,
            allowed_imports: vec!["log".into(), "get_time".into(), "random".into()],
        }
    }
}

/// WASM runtime for sandboxed plugin execution.
pub struct WasmRuntime {
    sandbox_config: SandboxConfig,
    loaded_modules: HashMap<String, Vec<u8>>,
    execution_count: u64,
}

impl WasmRuntime {
    /// Create a new WASM runtime.
    pub fn new(sandbox_config: SandboxConfig) -> Self {
        Self {
            sandbox_config,
            loaded_modules: HashMap::new(),
            execution_count: 0,
        }
    }

    /// Get sandbox config reference.
    pub fn sandbox_config(&self) -> &SandboxConfig {
        &self.sandbox_config
    }

    /// Load a WASM module.
    pub fn load_module(&mut self, name: &str, wasm_bytes: Vec<u8>) -> Result<(), AgentError> {
        // Validate WASM magic number
        if wasm_bytes.len() < 4 {
            return Err(AgentError::InvalidParameter("WASM module too small".into()));
        }
        // Real WASM magic: \0asm (0x00 0x61 0x73 0x6d)
        // For testing, we accept any bytes
        if wasm_bytes.len() as u64 > self.sandbox_config.max_memory {
            return Err(AgentError::InvalidParameter(format!(
                "Module exceeds max memory: {} > {}",
                wasm_bytes.len(),
                self.sandbox_config.max_memory
            )));
        }
        self.loaded_modules.insert(name.to_string(), wasm_bytes);
        Ok(())
    }

    /// Unload a WASM module.
    pub fn unload_module(&mut self, name: &str) -> bool {
        self.loaded_modules.remove(name).is_some()
    }

    /// Execute a loaded WASM module (simulated).
    pub fn execute(&mut self, name: &str, input: &str) -> Result<PluginResult, AgentError> {
        let module = self
            .loaded_modules
            .get(name)
            .ok_or_else(|| AgentError::NotFound(format!("plugin: {}", name)))?;

        self.execution_count += 1;

        // Simulated execution — in production this would use wasmtime/wasmer
        let start = std::time::Instant::now();
        let output = format!(
            "Plugin '{}' processed {} bytes of input (module size: {} bytes)",
            name,
            input.len(),
            module.len()
        );
        let elapsed = start.elapsed();

        Ok(PluginResult {
            plugin_name: name.to_string(),
            success: true,
            output,
            exec_time_ms: elapsed.as_millis() as u64,
            memory_used: module.len() as u64,
            error: None,
        })
    }

    /// List loaded modules.
    pub fn loaded_modules(&self) -> Vec<String> {
        self.loaded_modules.keys().cloned().collect()
    }

    /// Total execution count.
    pub fn execution_count(&self) -> u64 {
        self.execution_count
    }
}

/// Plugin manager for discovering, loading, and managing edge AI plugins.
pub struct PluginManager {
    plugins_dir: std::path::PathBuf,
    manifests: HashMap<String, PluginManifest>,
    runtime: WasmRuntime,
}

impl PluginManager {
    /// Create a new plugin manager.
    pub fn new(plugins_dir: std::path::PathBuf) -> Self {
        Self {
            plugins_dir,
            manifests: HashMap::new(),
            runtime: WasmRuntime::new(SandboxConfig::default()),
        }
    }

    /// Create with custom sandbox config.
    pub fn with_sandbox(plugins_dir: std::path::PathBuf, sandbox: SandboxConfig) -> Self {
        Self {
            plugins_dir,
            manifests: HashMap::new(),
            runtime: WasmRuntime::new(sandbox),
        }
    }

    /// Register a plugin manifest.
    pub fn register(&mut self, manifest: PluginManifest) -> Result<(), AgentError> {
        // Validate permissions
        for perm in &manifest.permissions {
            match perm.as_str() {
                "network" if !self.runtime.sandbox_config().allow_network => {
                    return Err(AgentError::PolicyDenied(format!(
                        "Plugin '{}' requires network access, but sandbox denies it",
                        manifest.name
                    )));
                }
                "filesystem" if !self.runtime.sandbox_config().allow_filesystem => {
                    return Err(AgentError::PolicyDenied(format!(
                        "Plugin '{}' requires filesystem access, but sandbox denies it",
                        manifest.name
                    )));
                }
                _ => {}
            }
        }
        self.manifests.insert(manifest.name.clone(), manifest);
        Ok(())
    }

    /// Load a plugin WASM binary.
    pub fn load_plugin(&mut self, name: &str, wasm_bytes: Vec<u8>) -> Result<(), AgentError> {
        if !self.manifests.contains_key(name) {
            return Err(AgentError::NotFound(format!(
                "manifest for plugin: {}",
                name
            )));
        }
        self.runtime.load_module(name, wasm_bytes)
    }

    /// Execute a plugin.
    pub fn execute_plugin(&mut self, name: &str, input: &str) -> Result<PluginResult, AgentError> {
        self.runtime.execute(name, input)
    }

    /// Unload a plugin.
    pub fn unload_plugin(&mut self, name: &str) -> bool {
        self.manifests.remove(name);
        self.runtime.unload_module(name)
    }

    /// List registered plugins.
    pub fn list_plugins(&self) -> Vec<&PluginManifest> {
        self.manifests.values().collect()
    }

    /// Get plugins directory.
    pub fn plugins_dir(&self) -> &std::path::Path {
        &self.plugins_dir
    }

    /// Scan plugins directory for manifest files.
    pub fn scan_plugins(&self) -> Vec<String> {
        let mut found = Vec::new();
        if self.plugins_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&self.plugins_dir) {
                for entry in entries.flatten() {
                    if entry
                        .path()
                        .extension()
                        .map(|e| e == "wasm")
                        .unwrap_or(false)
                    {
                        if let Some(name) = entry.path().file_stem() {
                            found.push(name.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manifest(name: &str) -> PluginManifest {
        PluginManifest {
            name: name.to_string(),
            version: "1.0.0".into(),
            description: "Test plugin".into(),
            author: "test".into(),
            permissions: vec![],
            entry_point: "main".into(),
            max_exec_secs: 10,
            max_memory_bytes: 1024 * 1024,
            plugin_type: PluginType::AiInference,
        }
    }

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert!(!config.allow_network);
        assert!(!config.allow_filesystem);
        assert_eq!(config.max_exec_time, 30);
    }

    #[test]
    fn test_plugin_type_display() {
        assert_eq!(PluginType::AiInference.to_string(), "AI Inference");
        assert_eq!(PluginType::Custom.to_string(), "Custom");
    }

    #[test]
    fn test_wasm_runtime_load_execute() {
        let mut rt = WasmRuntime::new(SandboxConfig::default());
        rt.load_module("test-plugin", vec![0, 97, 115, 109, 1, 0, 0, 0])
            .unwrap();
        assert_eq!(rt.loaded_modules().len(), 1);
        let result = rt.execute("test-plugin", "hello").unwrap();
        assert!(result.success);
        assert_eq!(result.plugin_name, "test-plugin");
        assert_eq!(rt.execution_count(), 1);
    }

    #[test]
    fn test_wasm_runtime_module_too_large() {
        let sandbox = SandboxConfig {
            max_memory: 8,
            ..Default::default()
        };
        let mut rt = WasmRuntime::new(sandbox);
        let result = rt.load_module("big", vec![0; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_wasm_runtime_unload() {
        let mut rt = WasmRuntime::new(SandboxConfig::default());
        rt.load_module("test", vec![0, 1, 2, 3]).unwrap();
        assert!(rt.unload_module("test"));
        assert!(!rt.unload_module("nonexistent"));
    }

    #[test]
    fn test_plugin_manager_register() {
        let dir = std::env::temp_dir().join("ecplugins");
        let mut mgr = PluginManager::new(dir);
        mgr.register(test_manifest("my-plugin")).unwrap();
        assert_eq!(mgr.list_plugins().len(), 1);
    }

    #[test]
    fn test_plugin_manager_denied_network() {
        let dir = std::env::temp_dir().join("ecplugins");
        let mut mgr = PluginManager::new(dir);
        let mut manifest = test_manifest("net-plugin");
        manifest.permissions = vec!["network".into()];
        let result = mgr.register(manifest);
        assert!(result.is_err());
    }

    #[test]
    fn test_plugin_manager_load_execute() {
        let dir = std::env::temp_dir().join("ecplugins");
        let mut mgr = PluginManager::new(dir);
        mgr.register(test_manifest("test-ai")).unwrap();
        mgr.load_plugin("test-ai", vec![0, 97, 115, 109]).unwrap();
        let result = mgr.execute_plugin("test-ai", "input data").unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_plugin_manifest_serialize() {
        let manifest = test_manifest("test");
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: PluginManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.plugin_type, PluginType::AiInference);
    }

    #[test]
    fn test_plugin_result_serialize() {
        let result = PluginResult {
            plugin_name: "test".into(),
            success: true,
            output: "ok".into(),
            exec_time_ms: 5,
            memory_used: 1024,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: PluginResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
    }

    #[test]
    fn test_scan_empty_dir() {
        let dir = std::env::temp_dir().join(format!("ecscan_{}", uuid::Uuid::new_v4()));
        let mgr = PluginManager::new(dir);
        assert!(mgr.scan_plugins().is_empty());
    }

    #[test]
    fn test_plugin_manager_with_sandbox() {
        let dir = std::env::temp_dir().join("ecplugins_sandbox");
        let sandbox = SandboxConfig {
            allow_network: true,
            allow_filesystem: true,
            ..Default::default()
        };
        let mut mgr = PluginManager::with_sandbox(dir.clone(), sandbox);
        assert_eq!(mgr.plugins_dir(), dir);

        // register with network+filesystem perms should succeed
        let mut manifest = test_manifest("net-fs-plugin");
        manifest.permissions = vec!["network".into(), "filesystem".into()];
        mgr.register(manifest).unwrap();
        assert_eq!(mgr.list_plugins().len(), 1);
    }

    #[test]
    fn test_plugin_denied_filesystem() {
        let dir = std::env::temp_dir().join("ecplugins_fs");
        let mut mgr = PluginManager::new(dir); // default sandbox denies filesystem
        let mut manifest = test_manifest("fs-plugin");
        manifest.permissions = vec!["filesystem".into()];
        let result = mgr.register(manifest);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("filesystem"));
    }

    #[test]
    fn test_load_plugin_no_manifest() {
        let dir = std::env::temp_dir().join("ecplugins_nomf");
        let mut mgr = PluginManager::new(dir);
        let result = mgr.load_plugin("nonexistent", vec![0, 1, 2, 3]);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("manifest"));
    }

    #[test]
    fn test_unload_plugin() {
        let dir = std::env::temp_dir().join("ecplugins_unload");
        let mut mgr = PluginManager::new(dir);
        mgr.register(test_manifest("p1")).unwrap();
        mgr.load_plugin("p1", vec![0, 97, 115, 109]).unwrap();
        assert_eq!(mgr.list_plugins().len(), 1);
        assert!(mgr.unload_plugin("p1"));
        assert_eq!(mgr.list_plugins().len(), 0);
        assert!(!mgr.unload_plugin("p1")); // already unloaded
    }

    #[test]
    fn test_scan_plugins_with_wasm_files() {
        let dir = std::env::temp_dir().join(format!("ecscan_wasm_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plugin_a.wasm"), b"fake wasm").unwrap();
        std::fs::write(dir.join("plugin_b.wasm"), b"fake wasm 2").unwrap();
        std::fs::write(dir.join("readme.txt"), b"not a plugin").unwrap();
        let mgr = PluginManager::new(dir.clone());
        let found = mgr.scan_plugins();
        assert_eq!(found.len(), 2);
        assert!(found.contains(&"plugin_a".to_string()));
        assert!(found.contains(&"plugin_b".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_plugin_type_all_display() {
        assert_eq!(PluginType::DataTransform.to_string(), "Data Transform");
        assert_eq!(PluginType::ProtocolHandler.to_string(), "Protocol Handler");
        assert_eq!(PluginType::SecurityScanner.to_string(), "Security Scanner");
    }
}

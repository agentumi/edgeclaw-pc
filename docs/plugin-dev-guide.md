# Plugin Development Guide

> EdgeClaw V3.0 — Building Plugins for the Agent Platform

## Overview

EdgeClaw supports a plugin architecture that extends agent capabilities through
sandboxed WASM modules and native Rust plugins. Plugins can add custom
command handlers, data processors, and protocol extensions.

## Plugin Architecture

```
AgentEngine
├─ PluginManager
│  ├─ PluginRegistry (manifest, version, status)
│  ├─ WasmRuntime (wasmtime sandbox)
│  └─ PluginLoader (file + registry)
└─ Plugin ← trait
   ├─ NativePlugin    (Rust, in-process)
   └─ WasmPlugin      (WASM, sandboxed)
```

## Plugin Trait

All plugins implement the `Plugin` trait:

```rust
use async_trait::async_trait;

#[async_trait]
pub trait Plugin: Send + Sync {
    /// Unique plugin identifier
    fn id(&self) -> &str;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Semantic version string
    fn version(&self) -> &str;

    /// Capabilities this plugin provides
    fn capabilities(&self) -> Vec<Capability>;

    /// Initialize the plugin with engine context
    async fn init(&mut self, ctx: &PluginContext) -> Result<(), PluginError>;

    /// Handle an incoming command
    async fn handle(&self, cmd: &Command) -> Result<Response, PluginError>;

    /// Cleanup when plugin is unloaded
    async fn shutdown(&mut self) -> Result<(), PluginError>;
}
```

## Writing a Native Plugin

### Step 1: Create the Plugin Struct

```rust
use edgeclaw_agent::plugin::{Plugin, PluginContext, Capability, Command, Response};

pub struct DiskMonitorPlugin {
    threshold_pct: f64,
    initialized: bool,
}

impl DiskMonitorPlugin {
    pub fn new(threshold_pct: f64) -> Self {
        Self { threshold_pct, initialized: false }
    }
}
```

### Step 2: Implement the Trait

```rust
#[async_trait]
impl Plugin for DiskMonitorPlugin {
    fn id(&self) -> &str { "disk_monitor" }
    fn name(&self) -> &str { "Disk Usage Monitor" }
    fn version(&self) -> &str { "1.0.0" }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::SystemInfo, Capability::StatusQuery]
    }

    async fn init(&mut self, ctx: &PluginContext) -> Result<(), PluginError> {
        // Read config, set up monitoring intervals
        if let Some(thresh) = ctx.config.get("threshold") {
            self.threshold_pct = thresh.parse().unwrap_or(90.0);
        }
        self.initialized = true;
        Ok(())
    }

    async fn handle(&self, cmd: &Command) -> Result<Response, PluginError> {
        match cmd.action.as_str() {
            "check_disk" => {
                let usage = get_disk_usage()?;
                let alert = usage > self.threshold_pct;
                Ok(Response::json(serde_json::json!({
                    "usage_percent": usage,
                    "threshold": self.threshold_pct,
                    "alert": alert,
                })))
            }
            _ => Err(PluginError::UnknownAction(cmd.action.clone())),
        }
    }

    async fn shutdown(&mut self) -> Result<(), PluginError> {
        self.initialized = false;
        Ok(())
    }
}
```

### Step 3: Register the Plugin

```rust
let mut engine = AgentEngine::new(config).await?;
engine.register_plugin(Box::new(DiskMonitorPlugin::new(90.0)))?;
engine.start().await?;
```

## Writing a WASM Plugin

### Step 1: Create a WASM Crate

```toml
# Cargo.toml
[package]
name = "my-plugin"
version = "0.1.0"

[lib]
crate-type = ["cdylib"]

[dependencies]
wasm-bindgen = "0.2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

### Step 2: Export Plugin Functions

```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn plugin_id() -> String {
    "custom_analyzer".to_string()
}

#[wasm_bindgen]
pub fn plugin_version() -> String {
    "1.0.0".to_string()
}

#[wasm_bindgen]
pub fn plugin_capabilities() -> String {
    serde_json::to_string(&["data_analysis", "status_query"]).unwrap()
}

#[wasm_bindgen]
pub fn handle(action: &str, payload: &[u8]) -> Vec<u8> {
    match action {
        "analyze" => {
            let result = analyze_data(payload);
            serde_json::to_vec(&result).unwrap()
        }
        _ => b"unknown action".to_vec(),
    }
}
```

### Step 3: Build and Install

```bash
wasm-pack build --target web --out-dir dist
cp dist/my_plugin_bg.wasm ~/.edgeclaw/plugins/
```

## Plugin Manifest

Every plugin requires a `manifest.toml`:

```toml
[plugin]
id = "custom_analyzer"
name = "Custom Data Analyzer"
version = "1.0.0"
description = "Analyzes telemetry data for anomalies"
author = "EdgeClaw Community"
license = "MIT"

[plugin.runtime]
type = "wasm"                    # "wasm" or "native"
entry = "custom_analyzer_bg.wasm"
min_agent_version = "3.0.0"

[plugin.capabilities]
required = ["data_analysis"]
optional = ["status_query"]

[plugin.resources]
max_memory_mb = 32
max_cpu_ms = 500                 # per invocation
max_storage_mb = 10

[plugin.permissions]
network = false                  # no outbound network
filesystem = ["read"]            # read-only fs access
```

## PluginManager API

```rust
// Load plugin from file
engine.plugin_manager().load("~/.edgeclaw/plugins/analyzer.wasm").await?;

// Load from marketplace
engine.plugin_manager().install("custom_analyzer", "1.0.0").await?;

// List loaded plugins
let plugins = engine.plugin_manager().list();
for p in &plugins {
    println!("{}: {} v{} [{}]", p.id, p.name, p.version, p.status);
}

// Unload plugin
engine.plugin_manager().unload("custom_analyzer").await?;

// Send command to plugin
let resp = engine.plugin_manager()
    .dispatch("custom_analyzer", "analyze", payload)
    .await?;
```

## Sandboxing

WASM plugins run in a sandboxed environment:

| Resource | Default Limit | Configurable |
|----------|--------------|--------------|
| Memory | 32 MB | Yes |
| CPU time | 500 ms / call | Yes |
| Disk | 10 MB | Yes |
| Network | Disabled | Yes (manifest) |
| Filesystem | None | Read-only opt-in |

### Security Boundaries

1. **Memory isolation**: Each WASM module has its own linear memory
2. **No shared state**: Plugins communicate only through the Plugin API
3. **Capability-gated**: Plugin actions require matching RBAC capabilities
4. **Resource limits**: CPU, memory, and disk are capped per manifest

## Lifecycle

```
Install → Load → Init → Active (handle commands) → Shutdown → Unload
```

- **Install**: Copy `.wasm` + `manifest.toml` to plugins directory
- **Load**: PluginManager reads manifest, validates, compiles WASM
- **Init**: `init()` called with PluginContext (config, logger)
- **Active**: `handle()` called for matching commands
- **Shutdown**: `shutdown()` called for cleanup
- **Unload**: Resources freed, plugin deregistered

## CLI Commands

```bash
# List installed plugins
edgeclaw-agent plugin list

# Install a plugin
edgeclaw-agent plugin install ./my_plugin.wasm

# Enable/disable
edgeclaw-agent plugin enable custom_analyzer
edgeclaw-agent plugin disable custom_analyzer

# Show plugin info
edgeclaw-agent plugin info custom_analyzer

# Remove plugin
edgeclaw-agent plugin remove custom_analyzer
```

## Testing Plugins

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_disk_monitor_init() {
        let mut plugin = DiskMonitorPlugin::new(90.0);
        let ctx = PluginContext::test_default();
        assert!(plugin.init(&ctx).await.is_ok());
    }

    #[tokio::test]
    async fn test_disk_monitor_handle() {
        let mut plugin = DiskMonitorPlugin::new(90.0);
        let ctx = PluginContext::test_default();
        plugin.init(&ctx).await.unwrap();

        let cmd = Command::new("check_disk", b"");
        let resp = plugin.handle(&cmd).await.unwrap();
        assert!(resp.is_json());
    }
}
```

## Marketplace Manifest

For publishing to the EdgeClaw Plugin Marketplace:

```toml
[marketplace]
category = "monitoring"
tags = ["disk", "system", "alerts"]
homepage = "https://github.com/example/disk-monitor"
repository = "https://github.com/example/disk-monitor"
icon = "disk_icon.png"
screenshots = ["screenshot1.png"]

[marketplace.pricing]
model = "free"               # "free", "one-time", "subscription"
```

## Best Practices

1. **Keep plugins small** — target < 1MB WASM binary
2. **Fail gracefully** — return errors, never panic
3. **Minimal permissions** — request only what you need in manifest
4. **Version carefully** — follow semver for compatibility
5. **Test thoroughly** — unit tests + integration with mock engine
6. **Document exports** — clear doc comments on all public functions
7. **Zeroize secrets** — if handling keys, zeroize after use

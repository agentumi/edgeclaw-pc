<p align="center">
  <img src="https://img.shields.io/badge/EdgeClaw-Desktop%20Agent-blue?style=for-the-badge&logo=windows&logoColor=white" alt="EdgeClaw Desktop Agent" />
</p>

<h1 align="center">EdgeClaw Desktop Agent</h1>

<p align="center">
  <strong>Zero-Trust Edge AI Orchestration Agent for Desktop & Server</strong>
</p>

<p align="center">
  <a href="https://github.com/agentumi/edgeclaw_desktop/actions/workflows/ci.yml"><img src="https://github.com/agentumi/edgeclaw_desktop/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/version-1.0.0-blue" alt="Version" />
  <img src="https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0-green" alt="License" />
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange?logo=rust" alt="Rust" />
  <img src="https://img.shields.io/badge/tests-416%20passed-success" alt="Tests" />
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey" alt="Platform" />
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-cli-commands">CLI</a> •
  <a href="#-security-model">Security</a> •
  <a href="#%EF%B8%8F-configuration">Config</a> •
  <a href="#-testing">Testing</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

> **EdgeClaw Desktop Agent** runs as a background daemon on desktop/server systems,
> providing zero-trust device identity, encrypted communication, RBAC policy enforcement,
> and system monitoring — all orchestrated through the ECNP v1.1 binary protocol.

## ✨ Features

| Category | Feature | Details |
|----------|---------|---------|
| 🔐 **Identity** | Ed25519 + X25519 | Device fingerprinting, signing, & ECDH key exchange |
| 🛡️ **Encryption** | AES-256-GCM | ECDH → HKDF-SHA256 → session encryption with replay protection |
| 👤 **Access Control** | 5-Role RBAC | Owner / Admin / Operator / Viewer / Guest (17 capabilities) |
| 📦 **Protocol** | ECNP v1.1 | Binary framing with version, type, length, payload |
| 💻 **Monitoring** | System Info | CPU, memory, disk, process listing, capability detection |
| ⚡ **Execution** | Async Commands | Concurrent execution with limits, path restrictions, timeouts |
| 🔗 **Networking** | TCP Server | Async listener with connection pooling & broadcast shutdown |
| 🤝 **Peers** | Peer Manager | Connection tracking, role assignment, max-peer limits |
| ⚙️ **Config** | TOML | Platform-aware configuration with hot-reload |
| 🖥️ **Cross-Platform** | Win / Mac / Linux | Native builds on all major desktop platforms |
| 🤖 **AI Chat** | Pluggable AI | Ollama (local), OpenAI, Claude providers with fallback |
| 📋 **Audit** | Hash-Chained Log | SHA-256 chained audit trail with tamper detection |
| 🛡️ **Security** | Rate Limiting | Per-client rate limiting, injection detection, lockout |
| 🐳 **Docker** | Containerized | Multi-stage build with health checks |
| ⛓️ **Multi-Chain** | 6 Blockchains | SUI, Ethereum, Solana, NEAR, Cosmos, Aptos — modular providers |
| 📋 **Task Templates** | 75 Built-in | Dev, Marketing, DevOps, Security, System, Data workflow templates |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI (clap)                            │
│  start │ status │ identity │ capabilities │ info │ init      │
│  chain list/status │ template list/run/search               │
├─────────────────────────────────────────────────────────────┤
│                      AgentEngine                             │
│  ┌──────────────┬──────────────┬──────────────────────────┐  │
│  │  Identity     │  Session     │  Policy Engine           │  │
│  │  Manager      │  Manager     │  (RBAC, 5 roles,         │  │
│  │  (Ed25519/    │  (ECDH +     │   17 capabilities)       │  │
│  │   X25519)     │   AES-GCM)   │                          │  │
│  ├──────────────┼──────────────┼──────────────────────────┤  │
│  │  Multi-Chain  │  Task        │  Peer Manager            │  │
│  │  Client       │  Templates   │  (Connection pool,       │  │
│  │  (6 chains)   │  (75 built-  │   role tracking)         │  │
│  │              │   in flows)  │                          │  │
│  ├──────────────┼──────────────┼──────────────────────────┤  │
│  │  Command      │  System      │  Federation              │  │
│  │  Executor     │  Monitor     │  Manager                 │  │
│  │  (Async +     │  (CPU, Mem,  │  (Cross-org mesh)        │  │
│  │   Limits)     │   Disk)      │                          │  │
│  ├──────────────┴──────────────┴──────────────────────────┤  │
│  │        TCP / QUIC Server (tokio async)                     │  │
│  │           ECNP v1.1 Codec (binary framing)              │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | 1.75+ | [rustup.rs](https://rustup.rs/) |

### Build & Run

```bash
# 1. Clone
git clone https://github.com/agentumi/edgeclaw_desktop.git
cd edgeclaw_desktop

# 2. Build
cargo build --release

# 3. Initialize configuration
./target/release/edgeclaw-agent init

# 4. Start the agent daemon
./target/release/edgeclaw-agent start

# 5. Check status
./target/release/edgeclaw-agent status
```

## 🖥️ CLI Commands

| Command | Description | Example |
|---------|-------------|---------|
| `start` | Start the agent daemon on configured port | `edgeclaw-agent start` |
| `status` | Show running status and uptime | `edgeclaw-agent status` |
| `identity` | Display device identity (public key, device ID) | `edgeclaw-agent identity` |
| `capabilities` | List system capabilities detected on this host | `edgeclaw-agent capabilities` |
| `info` | Show full system information (CPU, memory, disk) | `edgeclaw-agent info` |
| `init` | Generate default configuration file | `edgeclaw-agent init` |
| `chain list` | List all configured blockchain providers | `edgeclaw-agent chain list` |
| `chain status` | Show blockchain connection status | `edgeclaw-agent chain status` |
| `chain set-primary` | Set the primary blockchain | `edgeclaw-agent chain set-primary sui` |
| `template list` | List all available task templates | `edgeclaw-agent template list` |
| `template search` | Search templates by keyword | `edgeclaw-agent template search rust` |
| `template run` | Execute a template with parameters | `edgeclaw-agent template run dev.rust.build` |

## 🔐 Security Model

### RBAC — 5 Roles, 17 Capabilities

| Role | Count | Key Capabilities |
|------|-------|-----------------|
| **Owner** | 17 | All capabilities including `shell_exec`, `firmware_update`, `policy_override` |
| **Admin** | 14 | All except `shell_exec`, `firmware_update`, `policy_override` |
| **Operator** | 8 | `file_read`, `file_write`, `process_manage`, `docker`, `network_scan` |
| **Viewer** | 3 | `status_query`, `log_read`, `system_info` |
| **Guest** | 1 | `status_query` only |

### Cryptography Stack

```
Device Identity ──── Ed25519 (signing + verification)
        │
Key Exchange ─────── X25519 ECDH (ephemeral)
        │
Key Derivation ───── HKDF-SHA256 (info: "ecnp-session-v2")
        │
Message Encrypt ──── AES-256-GCM (12-byte random nonce)
        │
Anti-Replay ──────── Message counter + nonce tracking
```

### Protocol: ECNP v1.1

```
┌─────────┬──────────┬────────────┬─────────────┐
│ Version │ Type     │ Length     │ Payload     │
│ (1B)    │ (1B)     │ (4B BE)   │ (N bytes)   │
└─────────┴──────────┴────────────┴─────────────┘
```

## ⚙️ Configuration

Configuration is stored in TOML format. Default path by platform:

| Platform | Path |
|----------|------|
| **Windows** | `%APPDATA%\edgeclaw\agent.toml` |
| **macOS** | `~/Library/Application Support/edgeclaw/agent.toml` |
| **Linux** | `~/.config/edgeclaw/agent.toml` |

### Default Configuration

```toml
[agent]
name = "edgeclaw-agent"
listen_port = 8443
max_peers = 32
heartbeat_interval_secs = 30

[transport]
protocol = "tcp"
max_frame_size = 65536
connection_timeout_secs = 10

[security]
require_encryption = true
session_timeout_secs = 3600
max_sessions = 64

[execution]
max_concurrent = 4
default_timeout_secs = 30
allowed_paths = ["/usr/local/bin", "/usr/bin"]

[resource]
cpu_limit_percent = 80.0
memory_limit_mb = 512
disk_limit_mb = 1024

[logging]
level = "info"
file = "edgeclaw-agent.log"
max_size_mb = 50

[multi_chain]
primary = "sui"

[[multi_chain.chains]]
chain_type = "sui"
rpc_url = "https://fullnode.devnet.sui.io:443"
contract_address = "0xabc..."
gas_budget = 10000000

[[multi_chain.chains]]
chain_type = "ethereum"
rpc_url = "https://mainnet.infura.io/v3/YOUR_KEY"
chain_id = "1"

[task_templates]
custom_dir = "~/.edgeclaw/templates"
auto_load = true
```

## 📁 Project Structure

```
edgeclaw_desktop/
├── src/
│   ├── main.rs          # CLI entry point (clap subcommands)
│   ├── lib.rs           # AgentEngine orchestrator
│   ├── config.rs        # TOML configuration management
│   ├── error.rs         # Error types (AgentError enum)
│   ├── identity.rs      # Ed25519/X25519 identity management
│   ├── session.rs       # ECDH + AES-256-GCM session encryption
│   ├── policy.rs        # RBAC policy engine (17 capabilities)
│   ├── protocol.rs      # Message types (ECM, EAP, Heartbeat)
│   ├── ecnp.rs          # ECNP v1.1 binary codec
│   ├── system.rs        # System info & capability detection
│   ├── executor.rs      # Async command execution with limits
│   ├── peer.rs          # Peer connection management
│   ├── server.rs        # TCP server with connection pool
│   ├── chain.rs         # Multi-chain blockchain abstraction (6 chains)
│   ├── task_templates.rs # Standardized workflow templates (75 built-in)
│   ├── blockchain.rs    # SUI blockchain SDK integration
│   ├── federation.rs    # Federated mesh network
│   ├── gateway.rs       # Cross-org gateway agent
│   ├── transport.rs     # TCP/QUIC transport layer
│   ├── tee.rs           # TEE abstraction (simulator)
│   ├── tee_sgx.rs       # Intel SGX backend (feature-gated)
│   ├── edge_ai.rs       # Edge AI runtime + plugin system
│   ├── wasm.rs          # WASM ECNP bridge
│   ├── k8s.rs           # Kubernetes CRD/operator
│   ├── secure_boot.rs   # Secure boot verification
│   ├── webui.rs         # Web dashboard
│   ├── websocket.rs     # WebSocket server
│   ├── metrics.rs       # Prometheus metrics
│   └── ...              # Additional modules
├── config/
│   └── default.toml     # Default agent configuration
├── contracts/           # Multi-chain smart contracts
│   ├── sui/             # SUI Move contracts
│   ├── evm/             # Ethereum/EVM Solidity contracts (Hardhat)
│   ├── solana/          # Solana Anchor programs
│   ├── near/            # NEAR Protocol contracts
│   ├── cosmos/          # Cosmos CosmWasm contracts
│   └── aptos/           # Aptos Move contracts
│
├── .github/workflows/ci.yml
├── AGENTS.md            # AI agent guidelines
├── CLAUDE.md            # Claude AI guidelines
├── CONTRIBUTING.md      # Contribution guide
├── SECURITY.md          # Security policy
├── CHANGELOG.md         # Release history
├── CODE_OF_CONDUCT.md   # Community standards
├── LICENSE-MIT          # MIT License
├── LICENSE-APACHE       # Apache 2.0 License
├── NOTICE               # Third-party attributions
└── Cargo.toml
```

## 🧪 Testing

### Test Summary

| Module | Tests | Command |
|--------|-------|---------|
| Config | — | `cargo test config::tests` |
| Identity | 4 | `cargo test identity::tests` |
| Session | 8 | `cargo test session::tests` |
| Policy | 10 | `cargo test policy::tests` |
| Executor | — | `cargo test executor::tests` |
| Peer | — | `cargo test peer::tests` |
| Server | — | `cargo test server::tests` |
| Chain (Multi-Chain) | 31 | `cargo test chain::tests` |
| Task Templates | 17 | `cargo test task_templates::tests` |
| Discovery | 13 | `cargo test discovery::tests` |
| Federation | — | `cargo test federation::tests` |
| Transport | — | `cargo test transport::tests` |
| TEE | — | `cargo test tee::tests` |
| Blockchain | — | `cargo test blockchain::tests` |
| **Total** | **416** | `cargo test` |

### Run Tests

```bash
# All 416 tests
cargo test

# Verbose output
cargo test -- --nocapture

# Single-threaded (for debugging)
cargo test -- --test-threads=1

# Specific module
cargo test policy::tests
```

### Lint & Format

```bash
# Clippy — zero warnings policy
cargo clippy --all-targets -- -D warnings

# Format check
cargo fmt --check

# Auto-format
cargo fmt
```

## 🤝 Contributing

We welcome contributions! Please read:

- [CONTRIBUTING.md](CONTRIBUTING.md) — Development workflow & PR process
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Community standards
- [SECURITY.md](SECURITY.md) — Vulnerability reporting

## 📜 License

Dual-licensed under **MIT** or **Apache-2.0** at your option.

- [LICENSE-MIT](LICENSE-MIT)
- [LICENSE-APACHE](LICENSE-APACHE)

Copyright (c) 2025-2026 EdgeClaw Contributors.

---

<p align="center">
  <sub>Built with 🦀 Rust + ⚡ tokio — Part of the <a href="https://github.com/agentumi">EdgeClaw</a> ecosystem</sub>
</p>

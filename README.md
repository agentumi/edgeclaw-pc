# EdgeClaw PC Agent (v2.0)

[![CI](https://github.com/agentumi/edgeclaw-pc/actions/workflows/ci.yml/badge.svg)](https://github.com/agentumi/edgeclaw-pc/actions)

A zero-trust edge AI orchestration agent for desktop/server environments. EdgeClaw PC Agent runs as a background daemon, manages device identity via Ed25519/X25519 cryptography, enforces RBAC-based policy controls, and communicates with peers over the ECNP (EdgeClaw Network Protocol) v1.1 binary protocol.

## Features

- **Device Identity** — Ed25519 signing keys + X25519 key exchange, platform-aware identity generation
- **Session Management** — ECDH → HKDF → AES-256-GCM encrypted sessions with replay protection
- **RBAC Policy Engine** — 17 capabilities across 5 roles (Owner, Admin, Operator, Viewer, Guest) with sandbox enforcement
- **ECNP v1.1 Protocol** — Binary framing with version, type, length, and payload encoding
- **System Monitoring** — CPU, memory, disk, process listing, and capability auto-detection
- **Async Command Execution** — Concurrent execution with configurable limits, path restrictions, and timeouts
- **Peer Management** — Connection pool with role tracking and max-peer limits
- **TCP Server** — Async listener with broadcast shutdown and connection pooling
- **Cross-Platform** — Windows, macOS, Linux support

## Architecture

```
┌──────────────────────────────────────────────┐
│              CLI (clap)                       │
├──────────────────────────────────────────────┤
│            AgentEngine                        │
│  ┌──────────┬──────────┬──────────┐          │
│  │ Identity │ Session  │  Policy  │          │
│  │ Manager  │ Manager  │  Engine  │          │
│  ├──────────┼──────────┼──────────┤          │
│  │ Executor │  System  │   Peer   │          │
│  │          │ Monitor  │ Manager  │          │
│  ├──────────┴──────────┴──────────┤          │
│  │        TCP Server              │          │
│  │        ECNP Codec              │          │
│  └────────────────────────────────┘          │
└──────────────────────────────────────────────┘
```

## Quick Start

### Build

```bash
cargo build --release
```

### Initialize Configuration

```bash
./target/release/edgeclaw-agent init
```

This creates a default configuration file at the platform-specific config directory.

### Start the Agent

```bash
./target/release/edgeclaw-agent start
```

### CLI Commands

| Command        | Description                                     |
| -------------- | ----------------------------------------------- |
| `start`        | Start the agent daemon on the configured port   |
| `status`       | Show running status and uptime                  |
| `identity`     | Display device identity (public key, device ID) |
| `capabilities` | List system capabilities detected on this host  |
| `info`         | Show full system information (CPU, memory, etc) |
| `init`         | Generate default configuration file             |

## Configuration

Configuration is loaded from TOML format. Default path:

- **Windows**: `%APPDATA%\edgeclaw\agent.toml`
- **macOS**: `~/Library/Application Support/edgeclaw/agent.toml`
- **Linux**: `~/.config/edgeclaw/agent.toml`

Example configuration (`config/default.toml`):

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
```

## Security Model

### Roles & Capabilities

| Role     | Key Capabilities                                           |
| -------- | ---------------------------------------------------------- |
| Owner    | All 17 capabilities including `shell_exec`, `firmware_update` |
| Admin    | 14 capabilities (no `shell_exec`, `firmware_update`, `policy_override`) |
| Operator | 8 capabilities (file read/write, process list, docker)     |
| Viewer   | 3 capabilities (status query, log read, system info)       |
| Guest    | 1 capability (status query only)                           |

### Cryptography

- **Identity**: Ed25519 signing + X25519 Diffie-Hellman
- **Session Keys**: ECDH → HKDF-SHA256 (info: `"ecnp-session-v2"`) → AES-256-GCM
- **Message Integrity**: 12-byte random nonce per message, replay protection via message counters

## Testing

```bash
# Run all 62 tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific module tests
cargo test policy::tests
cargo test executor::tests
```

## Project Structure

```
src/
├── main.rs       # CLI entry point (clap subcommands)
├── lib.rs        # AgentEngine orchestrator
├── config.rs     # TOML configuration management
├── error.rs      # Error types (AgentError enum)
├── identity.rs   # Ed25519/X25519 identity management
├── session.rs    # ECDH + AES-256-GCM session encryption
├── policy.rs     # RBAC policy engine (17 capabilities)
├── protocol.rs   # Message types (ECM, EAP, Heartbeat, etc.)
├── ecnp.rs       # ECNP v1.1 binary codec
├── system.rs     # System info & capability detection
├── executor.rs   # Async command execution with limits
├── peer.rs       # Peer connection management
└── server.rs     # TCP server with connection pool
config/
└── default.toml  # Default agent configuration
```

## License

Copyright (c) 2025 EdgeClaw. All rights reserved.

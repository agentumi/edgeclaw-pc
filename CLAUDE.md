# CLAUDE.md

> This file provides guidance to Claude (Anthropic AI) when working with EdgeClaw Desktop Agent.

## Quick Facts

| Aspect | Details |
|--------|---------|
| Language | Rust |
| Tests | 686 unit tests + 5 doc tests |
| Minimum | Rust 1.75 |
| Protocol | ECNP v1.1 binary framing |
| Security | Ed25519 + X25519 + AES-256-GCM |

## Project Structure

```
edgeclaw_desktop/
├── src/
│   ├── main.rs        # CLI entry point (clap)
│   ├── lib.rs         # AgentEngine orchestrator
│   ├── config.rs      # TOML config management
│   ├── error.rs       # Error types (AgentError)
│   ├── identity.rs    # Ed25519/X25519 identity (4 tests)
│   ├── session.rs     # ECDH + AES-256-GCM (8 tests)
│   ├── policy.rs      # RBAC engine (10 tests)
│   ├── protocol.rs    # Message types
│   ├── ecnp.rs        # ECNP v1.1 binary codec
│   ├── activity_log.rs     # Team activity log (30 tests)
│   ├── activity_collector.rs # EventBus → activity entries (18 tests)
│   ├── team_sync.rs        # P2P activity sync (20 tests)
│   ├── chain.rs       # Multi-chain blockchain (31 tests)
│   ├── task_templates.rs # Workflow templates (17 tests)
│   ├── blockchain.rs  # SUI blockchain SDK
│   ├── federation.rs  # Federated mesh protocol
│   ├── gateway.rs     # Cross-org gateway
│   ├── transport.rs   # TCP/QUIC transport
│   ├── tee.rs         # TEE abstraction (simulator)
│   ├── tee_sgx.rs     # Intel SGX backend
│   ├── edge_ai.rs     # Edge AI runtime + plugins
│   ├── wasm.rs        # WASM ECNP bridge
│   ├── k8s.rs         # Kubernetes CRD/operator
│   ├── secure_boot.rs # Secure boot verification
│   ├── system.rs      # System info & capabilities
│   ├── executor.rs    # Async command execution
│   ├── peer.rs        # Peer connection mgmt
│   └── server.rs      # TCP server
├── config/
│   └── default.toml   # Default configuration
├── contracts/         # Multi-chain smart contracts (6 chains)
│   ├── sui/           # SUI Move contracts
│   ├── evm/           # Ethereum Solidity (Hardhat + OpenZeppelin)
│   ├── solana/        # Solana Anchor programs
│   ├── near/          # NEAR Protocol (near-sdk)
│   ├── cosmos/        # Cosmos CosmWasm
│   └── aptos/         # Aptos Move contracts
└── Cargo.toml
```

## CLI Commands

```bash
# Run tests (625: 620 lib + 5 doc)
cargo test

# Build
cargo build --release

# Initialize config
./target/release/edgeclaw-agent init

# Start daemon
./target/release/edgeclaw-agent start

# Show status
./target/release/edgeclaw-agent status

# Display device identity
./target/release/edgeclaw-agent identity

# List capabilities
./target/release/edgeclaw-agent capabilities

# Show system info
./target/release/edgeclaw-agent info
```

## Architecture

```
CLI (clap)
    ↓
AgentEngine
├─ Identity Manager (Ed25519/X25519)
├─ Session Manager (AES-256-GCM)
├─ Policy Engine (RBAC, 17 capabilities)
├─ Activity Manager (hash-chained team log)
├─ Activity Collector (EventBus → entries)
├─ Multi-Chain Client (SUI/ETH/SOL/NEAR/Cosmos/Aptos)
├─ Template Registry (75 workflow templates)
├─ System Monitor (CPU, memory, disk)
├─ Command Executor (async with limits)
├─ Peer Manager (connection pooling)
├─ Federation Manager (cross-org mesh)
└─ TCP/QUIC Server (async listener)
    ↓
ECNP v1.1 Codec (binary framing)
```

## Security Model

| Layer | Tech | Purpose |
|-------|------|---------|
| Signing | Ed25519 | Device auth |
| Exchange | X25519 ECDH | Key agreement |
| KDF | HKDF-SHA256 | Key derivation |
| Encrypt | AES-256-GCM | Confidentiality + integrity |
| Replay | Nonce + timestamp | Anti-replay |

## Key Modules

- **IdentityManager** — Device fingerprinting & signing
- **SessionManager** — ECDH encrypted channels
- **PolicyEngine** — RBAC (5 roles, 17 capabilities)
- **ActivityLog** — Hash-chained team activity log with CRDT merge
- **ActivityCollector** — EventBus → ActivityEntry converter with noise filtering
- **TeamSync** — P2P team activity sync over ECNP (RBAC-filtered)
- **MultiChainClient** — 6-chain blockchain abstraction (SUI/ETH/SOL/NEAR/Cosmos/Aptos)
- **TemplateRegistry** — 75 built-in workflow templates (Dev/Marketing/DevOps/Security/System/Data)
- **SystemMonitor** — CPU, memory, disk, processes
- **Executor** — Async command execution with limits
- **PeerManager** — Connection tracking & role assignment
- **FederationManager** — Cross-organization mesh network
- **Server** — TCP/QUIC async listener with broadcast shutdown

## Testing

All modules have unit tests:

```bash
cargo test config::tests       # Configuration
cargo test identity::tests     # Ed25519/X25519
cargo test session::tests      # ECDH + AES-GCM
cargo test policy::tests       # RBAC
cargo test activity_log::tests # Team activity log (30 tests)
cargo test activity_collector::tests # Activity collector (18 tests)
cargo test team_sync::tests    # P2P activity sync (20 tests)
cargo test chain::tests        # Multi-chain blockchain (31 tests)
cargo test task_templates::tests # Task templates (17 tests)
cargo test discovery::tests    # Discovery + blockchain registry (13 tests)
cargo test blockchain::tests   # SUI blockchain SDK
cargo test federation::tests   # Federation protocol
cargo test transport::tests    # TCP/QUIC transport
cargo test executor::tests     # Command execution
cargo test peer::tests         # Peer management
cargo test server::tests       # TCP server
```

## Configuration (TOML)

```toml
[agent]
name = "edgeclaw-agent"
listen_port = 8443
max_peers = 32
heartbeat_interval_secs = 30

[security]
require_encryption = true
session_timeout_secs = 3600
max_sessions = 64

[execution]
max_concurrent = 4

[multi_chain]
primary = "sui"
# Add chain providers as [[multi_chain.chains]] entries

[task_templates]
custom_dir = "~/.edgeclaw/templates"
auto_load = true
```

## Security Invariants

✅ **NEVER violate**:
1. All connections authenticated (Ed25519)
2. All data encrypted (AES-256-GCM)
3. Nonce never reused
4. Key material zeroized
5. RBAC policy enforcement

## Coding Style

- Rust Edition 2021, MSRV 1.75
- No `unsafe` unless justified
- All public items have doc comments
- Conventional commits: `feat:`, `fix:`, `docs:`, `ci:`, `chore:`

---

Always run `cargo test && cargo clippy && cargo fmt` before pushing!

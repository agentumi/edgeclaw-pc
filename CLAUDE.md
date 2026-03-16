# EdgeClaw Desktop Agent Engine

Persistent memory and orchestration rules for the EdgeClaw Desktop system.

## Project Context
EdgeClaw is a zero-trust, high-performance desktop agent system built in Rust. It provides 17 capabilities ranging from system monitoring to blockchain interaction (SUI).

- **Tech Stack**: Rust (Edition 2021, MSRV 1.75+), Tokio, ECNP v1.1 Binary Protocol.
- **Security**: Ed25519 (Identity), X25519 (Perfect Forward Secrecy), AES-256-GCM (Session).
- **Architecture**: Multi-chain support, Federated mesh networking, Event-driven memory engine.

## Core Commands
- **Build**: `cargo build`
- **Release**: `cargo build --release`
- **Test**: `cargo test` (686 unit tests)
- **Lint**: `cargo clippy --all-targets -- -D warnings`
- **Format**: `cargo fmt`

## Directory Overview
- `src/`: Core logic (AgentEngine, Capabilities, Protocols)
- `contracts/`: SUI Move, EVM Solidity, Solana Anchor
- `templates/`: YAML-based workflow and business templates
- `config/`: Default TOML configurations
- `.agents/`: AI orchestration layer (Skills, Hooks, Workflows)

## Guiding Principles
1. **Zero Trust First**: Every internal/external call must be authenticated.
2. **Safety Over Speed**: Use `thiserror`, avoid `unsafe`, mandatory `clippy`.
3. **Context Sensitivity**: Use specialized skills in `.agents/skills/` for specific tasks.
4. **Audit Everything**: Ensure all privileged operations are logged to the hash-chained audit trail.

## Working with Antigravity
- **Mode Switching**: Use `/model <name>` to switch between Llama3 (General) and Qwen2.5-Coder (Tech).
- **Knowledge Retrieval**: Refer to Knowledge Items (KIs) before proposing architectural changes.
- **Verification**: Always run `cargo test` after modifying core logic.

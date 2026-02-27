# AGENTS.md

> Instructions for AI coding agents working on EdgeClaw Desktop Agent.

## Quick Reference

| Item | Details |
|------|---------|
| **Rust MSRV** | 1.75+ |
| **Tests** | 96 unit tests |
| **Protocol** | ECNP v1.1 binary |
| **Security** | Zero-trust: Ed25519 + X25519 + AES-256-GCM |
| **Async** | tokio runtime |

## Build & Test

```bash
cargo build --release
cargo test                      # 96 tests
cargo clippy --all-targets -- -D warnings
cargo fmt
```

## Code Conventions

### Rust
- `Edition 2021`, MSRV `1.75+`
- Use `thiserror` for errors
- All public APIs must have doc comments (`///`)
- All modules must include unit tests in `#[cfg(test)]` blocks
- Zero warnings: `cargo clippy --all-targets -- -D warnings`
- Format: `cargo fmt` before commit

## Architecture Principles

1. **Zero Trust** — Every connection authenticated + encrypted
2. **Async First** — Use tokio for concurrent operations
3. **No Unsafe** — Avoid `unsafe` Rust blocks
4. **Test Coverage** — All new code must have tests
5. **Binary Protocol** — Use ECNP, not JSON

## Security Requirements

- **Key Material**: MUST be zeroized after use
- **Session Keys**: ECDH → HKDF-SHA256 → AES-256-GCM
- **Nonce Reuse**: NEVER acceptable
- **Policy Checks**: All privileged operations MUST pass RBAC
- **Audit Logs**: MUST track all operations

## File Organization

```
src/
├── main.rs         # CLI entry (clap)
├── lib.rs          # AgentEngine (17 capabilities)
├── config.rs       # TOML config loading
├── error.rs        # AgentError enum
├── identity.rs     # Ed25519/X25519 (Ed claims 4 tests)
├── session.rs      # ECDH + AES-256-GCM (5 tests)
├── policy.rs       # RBAC 5 roles (10 tests)
├── protocol.rs     # Message types
├── ecnp.rs         # Binary codec
├── system.rs       # System monitoring
├── executor.rs     # Async command exec
├── peer.rs         # Connection pooling
└── server.rs       # TCP server

config/
└── default.toml    # Default configuration
```

## PR Checklist

- [ ] One logical change per PR
- [ ] Tests added for new functionality
- [ ] `cargo test` passes (96 tests)
- [ ] `cargo clippy --all-targets -- -D warnings` (zero warnings)
- [ ] `cargo fmt` run
- [ ] CHANGELOG.md updated
- [ ] CLA signed

## Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**: `feat:`, `fix:`, `docs:`, `style:`, `refactor:`, `perf:`, `test:`, `ci:`, `chore:`

## Testing Modules

```bash
cargo test config::tests       # Config loading (?)
cargo test identity::tests     # Ed25519/X25519 (4 tests)
cargo test session::tests      # ECDH + AES-GCM (5 tests)
cargo test policy::tests       # RBAC (10 tests)
cargo test executor::tests     # Command execution (?)
cargo test peer::tests         # Peer mgmt (?)
cargo test server::tests       # TCP server (?)
```

## Security Checklist

- [ ] All encryption uses `aes-gcm` crate
- [ ] All signatures use `ed25519-dalek`
- [ ] All ECDH uses `x25519-dalek`
- [ ] Nonces are cryptographically random (12 bytes)
- [ ] Key material zeroized after use
- [ ] No hardcoded secrets or test keys in production
- [ ] RBAC checks before privileged operations
- [ ] All operations logged to audit trail

## RBAC Capabilities (17 total)

**Owner** (17): All
**Admin** (14): All except shell_exec, firmware_update, policy_override
**Operator** (8): file_read/write, process_manage, docker, network_scan
**Viewer** (3): status_query, log_read, system_info
**Guest** (1): status_query

---

**Questions?** See [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md), or [CLAUDE.md](CLAUDE.md).

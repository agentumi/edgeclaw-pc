---
name: rust-core-engineering
description: Expert guidance for working on EdgeClaw core Rust logic, security, and protocols.
---

# Rust Core Engineering Skill

This skill is activated when modifying `src/` files or updating system-level protocols (ECNP).

## Coding Standards
- **Errors**: Always use `thiserror` for library errors (`error.rs`).
- **Async**: Use `tokio::sync::Mutex` for shared state across async tasks; use standard `Mutex` only for simple, synchronous data.
- **Documentation**: Triple-slash `///` doc comments are mandatory for public items.
- **Zero Warnings**: No clippy warnings allowed.

## Security (Zero Trust)
- **Keys**: Never store raw private keys in memory longer than necessary. Zeroize after use.
- **Nonces**: Use `rand::rngs::OsRng` for AES-GCM nonces (12 bytes).
- **Encryption**: Standard is AES-256-GCM from the `aes-gcm` crate.

## Testing Pattern
- Modules must have internal `#[cfg(test)]` blocks.
- Integration tests go in `tests/`.
- Mocking: Use `mockall` or simple trait injection for testing capabilities.

## Code Review Checklist
- [ ] Is it thread-safe?
- [ ] Are potential errors handled or bubbled up?
- [ ] Does it adhere to ECNP v1.1 spec?
- [ ] Is there an audit log entry for this operation?

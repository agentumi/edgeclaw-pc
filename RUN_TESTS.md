# Running Tests

EdgeClaw Desktop Agent has **62 tests** covering all core functionality.

---

## Quick Start

```bash
cargo test
```

## Run All Tests

```bash
# All 62 tests
cargo test

# Verbose output
cargo test -- --nocapture

# Single-threaded (for debugging)
cargo test -- --test-threads=1
```

## Run by Module

| Module | Tests | Command |
|--------|-------|---------|
| Config | - | `cargo test config::tests` |
| Identity (Ed25519/X25519) | 4 | `cargo test identity::tests` |
| Session (ECDH + AES-GCM) | 5 | `cargo test session::tests` |
| Policy (RBAC) | 10 | `cargo test policy::tests` |
| Executor (Async Commands) | - | `cargo test executor::tests` |
| Peer (Connection Pool) | - | `cargo test peer::tests` |
| Server (TCP) | - | `cargo test server::tests` |

## Lint & Format

```bash
# Clippy — zero warnings policy
cargo clippy --all-targets -- -D warnings

# Format check
cargo fmt --check

# Auto-format
cargo fmt
```

## Pre-Commit Checklist

Run all checks before committing:

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt
```

## Watch Mode

Auto-run tests on file changes:

```bash
# Install cargo-watch
cargo install cargo-watch

# Watch tests
cargo watch -x test

# Watch tests + clippy
cargo watch -x test -x clippy
```

## Troubleshooting

### Test Timeouts

```bash
cargo test -- --test-threads=1 --nocapture
```

### Build Cache Issues

```bash
cargo clean && cargo test
```

### Async Test Issues

For tests involving tokio runtime:

```bash
RUST_LOG=debug cargo test -- --nocapture
```

---

For more information, see [README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

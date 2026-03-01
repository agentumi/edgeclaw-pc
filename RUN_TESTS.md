# Running Tests

EdgeClaw Desktop Agent has **620 unit tests + 5 doc-tests** covering all core functionality.

**Code Coverage**: 85.85% (4830/5626 lines, excluding main.rs)
**Fuzz Testing**: 1,000,000 iterations across 8 targets, 0 crashes

---

## Quick Start

```bash
cargo test
```

## Run All Tests

```bash
# All 620 tests + 5 doc-tests
cargo test

# Verbose output
cargo test -- --nocapture

# Single-threaded (for debugging)
cargo test -- --test-threads=1
```

## Run by Module

| Module | Tests | Command |
|--------|-------|---------|
| Config | — | `cargo test config::tests` |
| Identity (Ed25519/X25519) | 4 | `cargo test identity::tests` |
| Session (ECDH + AES-GCM) | 8 | `cargo test session::tests` |
| Policy (RBAC) | 10 | `cargo test policy::tests` |
| Chain (Multi-Chain) | 31 | `cargo test chain::tests` |
| Task Templates | 17 | `cargo test task_templates::tests` |
| Discovery | 13 | `cargo test discovery::tests` |
| Blockchain (SUI SDK) | — | `cargo test blockchain::tests` |
| Federation | — | `cargo test federation::tests` |
| Transport (TCP/QUIC) | — | `cargo test transport::tests` |
| TEE (SGX/Simulator) | — | `cargo test tee::tests` |
| Edge AI | — | `cargo test edge_ai::tests` |
| Executor (Async Commands) | — | `cargo test executor::tests` |
| Peer (Connection Pool) | — | `cargo test peer::tests` |
| Server (TCP) | — | `cargo test server::tests` |

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

## Code Coverage

Requires [cargo-tarpaulin](https://github.com/xd009642/tarpaulin) (Linux/WSL2 only):

```bash
# Install
cargo install cargo-tarpaulin

# Measure coverage (excluding CLI entrypoint)
cargo tarpaulin --exclude-files 'src/main.rs' --out Stdout

# HTML report
cargo tarpaulin --exclude-files 'src/main.rs' --out Html
```

Current coverage: **85.85%** (4830/5626 lines)

## Fuzz Testing

Requires Rust nightly and [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz):

```bash
# Install
rustup toolchain install nightly
cargo install cargo-fuzz

# Run all 8 targets (125,000 iterations each = 1M total)
for t in fuzz_ecnp_parse fuzz_message_deserialize fuzz_aes_gcm fuzz_policy \
         fuzz_federation_policy fuzz_quic_frame fuzz_tee_attestation fuzz_wasm_protocol; do
    cargo +nightly fuzz run $t -- -runs=125000
done
```

---

For more information, see [README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

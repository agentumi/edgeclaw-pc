# Contributing to EdgeClaw Desktop Agent

Thank you for your interest in contributing! We welcome contributions from everyone.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Pull Request Process](#pull-request-process)
- [Commit Message Format](#commit-message-format)
- [Testing Requirements](#testing-requirements)
- [Security Considerations](#security-considerations)
- [License](#license)

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork:
   ```bash
   git clone https://github.com/<your-username>/edgeclaw_desktop.git
   cd edgeclaw_desktop
   ```
3. **Create a branch** from `dev`:
   ```bash
   git checkout -b feat/your-feature dev
   ```

## Development Environment

### Required Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | 1.75+ | Build & development ([rustup.rs](https://rustup.rs/)) |

### Setup

```bash
# Verify Rust installation
rustup show

# Install additional tools
cargo install cargo-watch   # Optional: auto-rebuild on changes
```

## Development Workflow

### Build & Test

```bash
# Build release binary
cargo build --release

# Run all 62 tests
cargo test

# Lint — zero warnings policy
cargo clippy --all-targets -- -D warnings

# Format check
cargo fmt --check
```

### Pre-Push Checklist

```bash
# Run everything before pushing
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt
```

### Watch Mode (Development)

```bash
cargo watch -x test -x clippy
```

## Coding Standards

### Rust

| Rule | Details |
|------|---------|
| Edition | 2021 |
| MSRV | 1.75+ |
| Async | Use `tokio` for all async operations |
| Errors | Use `thiserror` crate |
| Docs | All public APIs must have `///` doc comments |
| Tests | All modules must include `#[cfg(test)]` blocks |
| Warnings | Zero warnings policy (`-D warnings`) |
| Format | `cargo fmt` before every commit |
| Unsafe | Avoid `unsafe` unless absolutely justified |

## Pull Request Process

1. **One logical change per PR** — keep PRs focused and reviewable
2. **Tests required** — all new functionality must have tests
3. **Ensure CI passes**:
   - `cargo test` (62 tests)
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo fmt --check`
4. **Update documentation** — update CHANGELOG.md for user-facing changes
5. **Target `dev` branch** — PRs should target `dev`, not `main`
6. **Request review** — tag appropriate reviewers

## Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

| Type | Use For |
|------|---------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting, no code change |
| `refactor` | Code restructure, no behavior change |
| `perf` | Performance improvement |
| `test` | Adding/updating tests |
| `ci` | CI/CD pipeline changes |
| `chore` | Build system, dependencies |

### Examples

```
feat(server): add WebSocket upgrade support

Implement HTTP upgrade path for WebSocket connections
with automatic protocol detection and fallback to TCP.

Closes #15
```

```
fix(executor): prevent command injection via path traversal

Add path sanitization and sandbox enforcement to
async command executor. Restrict to allowed_paths only.
```

## Testing Requirements

- **All new code** must have associated tests
- Add tests in `#[cfg(test)]` module blocks
- **Target**: maintain 100% pass rate across all 62 tests
- Use `cargo test -- --nocapture` for debugging

## Security Considerations

When contributing security-related code:

- **Never** hardcode secrets or test keys
- **Always** zeroize key material after use
- **Never** reuse nonces
- **Always** validate RBAC before privileged operations
- **Always** enforce sandbox path restrictions in executor
- Report vulnerabilities to [security@edgeclaw.dev](mailto:security@edgeclaw.dev)

See [SECURITY.md](SECURITY.md) for the full security policy.

## License

By contributing, you agree that your contributions are dual-licensed under:

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community standards.

---

Thank you for helping build EdgeClaw!

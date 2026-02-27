# Changelog

All notable changes to EdgeClaw Desktop Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Prometheus metrics exporter
- WebSocket support for real-time events
- OTA (Over-The-Air) update support

---

## [1.0.1] - 2026-02-27

### Added
- `/health` and `/api/health` HTTP endpoints for Docker/load-balancer health checks
- `health` CLI subcommand for monitoring tools
- Crate-level documentation with `//!` doc comment and doc-test
- Persistent audit log (JSON lines to `audit.jsonl`, survives restarts)
- Rate limiter wired into Web UI HTTP server (per-IP, 60 req/min + 10 burst)
- HTTP 413 (Payload Too Large) and 429 (Too Many Requests) status codes
- `[ai]` and `[webui]` sections in default configuration file
- Graceful Ctrl+C shutdown handler with `tokio::signal`

### Changed
- CORS restricted from wildcard (`*`) to `http://127.0.0.1:9444` (localhost only)
- Dockerfile HEALTHCHECK updated to use `health` subcommand
- Audit log now loads previous entries from disk on startup

### Security
- Web UI rate limiting prevents DoS attacks on HTTP endpoints
- CORS origin restriction prevents cross-origin requests from untrusted sites

---

## [1.0.0] - 2026-02-27

### Added
- AI plugin architecture (Ollama, OpenAI, Claude providers)
- Interactive chat CLI with AI-powered command parsing
- Korean language support for chat commands
- Hash-chained audit logging with tamper detection
- Security module: rate limiting, input sanitization, connection tracking
- Shell injection detection and prevention
- Configurable AI policy (escalation, sensitive keyword filtering, consent)
- Quick action system for button-based UI
- Docker support with multi-stage build
- docker-compose.yml with health checks and resource limits
- MSRV 1.75 testing in CI
- Security audit step in CI pipeline
- 96 unit tests (up from 62)

### Changed
- Version normalized to 1.0.0
- CLI updated with chat, ai-status, audit-log, audit-verify subcommands
- Status command now shows AI provider info
- Configuration expanded with AI settings section
- All command executions now audit-logged

---

## [0.1.0] - 2026-02-26

### Added
- EdgeClaw PC Agent - zero-trust edge AI orchestration agent for desktop
- CLI with clap (start, status, identity, capabilities, info, init)
- Async TCP server with broadcast shutdown and connection pooling
- System monitoring (CPU, memory, disk, process listing)
- Async command executor with configurable limits and path restrictions
- TOML-based configuration management
- Peer connection management with role tracking
- 62 unit tests covering all functionality
- Full documentation and CI/CD pipeline

### Security
- Ed25519 signing keys + X25519 key exchange
- ECDH → HKDF-SHA256 → AES-256-GCM encrypted sessions
- Anti-replay protection with nonce tracking
- RBAC policy engine with 5 roles (17 capabilities)
- Configuration file path platform-aware
- Sandbox enforcement for restricted operations

---

[Unreleased]: https://github.com/agentumi/edgeclaw_desktop/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agentumi/edgeclaw_desktop/releases/tag/v0.1.0

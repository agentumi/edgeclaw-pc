# Changelog

All notable changes to EdgeClaw Desktop Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- OTA (Over-The-Air) update support
- Prometheus metrics exporter
- WebSocket support for real-time events

### Changed
- Improved performance for large command executions

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

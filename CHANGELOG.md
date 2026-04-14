# Changelog

All notable changes to EdgeClaw Desktop Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-04-14

### Added
- **MindVault Integration (V3 Phase 1)**:
  - `knowledge_graph.rs`: Layer 2 graph engine with petgraph (BFS/DFS, custom community detection).
  - `knowledge_ingest.rs`: Incremental SHA256-cached AST/Regex parser for Rust, MD, and TOML context injection.
  - `knowledge_wiki.rs`: Layer 3 community-based Markdown wiki generator.
  - `knowledge_query.rs`: 3-layer query orchestrator enforcing token budgets (~60,000 to ~900 tokens).

## [2.0.0] - 2026-03-08

### Added
- **Agent Memory System (V2 Phase 1)**:
  - `memory_engine.rs`: Multi-tiered memory (M0, M30, M90, M365) with retention policy.
  - `memory_distiller.rs`: Nightly distillation logic for lesson extraction.
  - `memory_search.rs`: Hybrid search (FTS + Mock Vector Similarity) and BootRitual context injection.
- **Identity & Economy (V2 Phase 2 & 5)**:
  - `identity_passport.rs`: Agent Passport NFT metadata and reputation scoring.
  - `reputation.rs`: PoP-based reputation calculation with Sybil defense (Diversity bonus).
  - SUI Move Contracts: `agent_passport.move`, `reputation.move`, `micro_escrow.move`.
- **ECNP v2.0 Protocol Extensions (Phase 5)**:
  - 17 new message types (0x30-0x55) for Memory Sync, Identity, and Task Delegation.
  - Loop prevention with `is_crossview` flag in `AgentChat`.
- **Mobile UI & Desktop Dashboards (Phase 4)**:
  - React/TS Desktop Mission Control, Agent Board (Kanban), and Memory Explorer.
  - Android (Kotlin/Compose) & iOS (SwiftUI) companion apps with UniFFI bridge.
- **Integration & Testing (Phase 6)**:
  - `tests/flywheel_e2e.rs`: Full-cycle integration test (Activity -> Memory -> Lesson -> Reputation -> Passport).

### Changed
- Total tests: 686 → 1,036+ (including new E2E and protocol tests).
- ECNP codec updated to version 2.0.

---

## [1.1.0] - 2026-03-01
- **Team Activity Log System** — Real-time agent activity tracking inspired by Tower:
  - `activity_log.rs` — Core hash-chained activity log with SHA-256 integrity:
    - `ActivityEntry` with Lamport clock, 7 `ActivityType` variants (FileEdit, CommandExec, AiChat, Decision, Error, PeerActivity, Custom)
    - `AgentSession` lifecycle with cost/token/turn tracking
    - `ContextInjection` for session-start context (files, git branch, environment)
    - CRDT merge (UUID dedup + Lamport ordering + hash recomputation)
    - JSONL append-only persistence with roundtrip verification
    - Full-text search, filter by tags/importance/project, statistics
    - 30 unit tests
  - `activity_collector.rs` — EventBus → ActivityEntry converter:
    - Automatic classification of `AgentEvent` variants into `ActivityType`
    - Configurable noise filtering (path glob, command substring, min importance)
    - Default filters for node_modules, build artifacts, trivial commands
    - 18 unit tests
  - `team_sync.rs` — P2P team activity synchronization over ECNP:
    - `TeamSyncMessage` enum with 7 variants (ActivityBroadcast, SessionSummary, LogQuery/Response, ContextRequest/Response, ActivityAck)
    - RBAC-filtered sync: Owner/Admin see all, Operator sees project-scoped, Viewer sees importance≥2, Guest blocked
    - ECNP message type codes 0x20–0x26
    - 20 unit tests
- 3 new `AgentEvent` variants: `FileModified`, `DecisionMade`, `ErrorOccurred`
- 7 new `MessageType` variants for activity sync protocol (0x20–0x26)
- **Multi-Chain Blockchain Abstraction** (`src/chain.rs`) — Modular provider system supporting 6 blockchains:
  - SUI (`SuiProvider`), Ethereum (`EthereumProvider`), Solana (`SolanaProvider`)
  - NEAR (`NearProvider`), Cosmos (`CosmosProvider`), Aptos (`AptosProvider`)
  - `ChainProvider` trait for unified device registration, policy NFTs, audit anchoring, token ops
  - `MultiChainClient` for managing multiple chains simultaneously with primary chain selection
  - `OfflineCache` for local fallback when blockchain is unreachable
  - CLI: `chain list`, `chain status`, `chain set-primary`
  - 31 new tests
- **Task Templates System** (`src/task_templates.rs`) — 75 built-in workflow templates:
  - Development (18): Rust build/test, Git feature/release, Node.js, Python, WASM, Go, Docker
  - Marketing (12): SEO audit, analytics, content calendar, social media, email, AB test
  - DevOps (15): Docker, K8s deploy/rollback, CI/CD, monitoring, SSL, backup
  - Security (10): vulnerability scan, dependency audit, SAST, secret scan, compliance
  - System (12): health check, backup, cleanup, network diagnostics, firewall
  - Data (8): DB backup/restore, ETL, migration, analysis, export
  - `TemplateRegistry` with search, filter by category/tag, JSON export/import
  - `render()` with `{{param}}` substitution in commands, args, and working_dir
  - CLI: `template list`, `template search`, `template run`
  - 17 new tests
- `[multi_chain]` and `[task_templates]` configuration sections in TOML
- **Multi-Chain Smart Contracts** (`contracts/`) — On-chain contracts for all 6 supported blockchains:
  - SUI Move: `device_registry.move`, `policy_nft.move`, `task_token.move`, `audit_anchor.move`
  - EVM Solidity: `DeviceRegistry.sol`, `PolicyNFT.sol` (ERC-721), `TaskToken.sol` (ERC-20), `AuditAnchor.sol` + Hardhat project
  - Solana Anchor: PDA-based device registry, SPL token minting, policy records, audit store
  - NEAR Protocol: Combined rust contract with NEP-141/NEP-171 compatible interfaces
  - Cosmos CosmWasm: Full entry_point contract with CW-20/CW-721 compatible patterns
  - Aptos Move: Coin standard token, Table-based storage, `#[view]`/`#[event]` patterns
  - Each chain implements: DeviceRegistry, PolicyNFT, TaskToken (ECLAW), AuditAnchor
  - Direct mapping to `ChainProvider` trait in `src/chain.rs`
- **Blockchain Registry Discovery** (`src/discovery.rs`) — SUI DeviceRegistry integration:
  - `discover_blockchain_registry()` — Query on-chain organization/device list
  - `lookup_blockchain_device()` — Look up specific device by public key
  - `DiscoveredOrganization` struct with org_id, name, device_count, gateway info
  - 5 new tests (registry_empty, registry_with_devices, registry_lookup, registry_skips_inactive, organization_serialize)
- **Blockchain Integration Guide** (`docs/blockchain-integration-guide.md`) — Comprehensive 6-chain deployment and SDK guide

### Changed
- Total tests: 625 → 686 (desktop lib), 691 with doc-tests (+61 new tests from activity log system)
- **Code coverage: 85.85%** (4830/5626 lines, excluding main.rs) — measured with cargo-tarpaulin on WSL2
  - 4 modules at 100%: config.rs, ecnp.rs, sync.rs, events.rs
  - 13 modules above 90%: chain (99.4%), task_templates (99.7%), protocol (100%), wasm (100%), edge_ai (98.8%), security (97.6%), license (96.9%), updater (95.5%), marketing (96.9%), identity (95.5%), secure_boot (94.8%), k8s (93.5%), registry (93.9%)
- **Fuzz testing: 1,000,000 iterations across 8 targets, 0 crashes** — cargo-fuzz with libFuzzer
  - fuzz_ecnp_parse, fuzz_message_deserialize, fuzz_aes_gcm, fuzz_policy
  - fuzz_federation_policy, fuzz_quic_frame, fuzz_tee_attestation, fuzz_wasm_protocol
- Architecture expanded with Multi-Chain Client, Task Templates, and Blockchain Discovery layers
- Release binary size: 6.29 MB (passes < 15MB spec)
- WASM binary size: 113 KB (passes < 1MB spec)

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

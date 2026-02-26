# Security Policy

## Reporting a Vulnerability

> **Do NOT report security vulnerabilities through public GitHub issues.**

We take the security of EdgeClaw Desktop Agent seriously. If you discover a
security vulnerability, please report it responsibly.

### How to Report

| Method | Contact |
|--------|--------|
| **Email** | [security@edgeclaw.dev](mailto:security@edgeclaw.dev) |
| **GitHub** | [Private Security Advisory](https://github.com/agentumi/edgeclaw_desktop/security/advisories/new) |

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgement | Within 48 hours |
| Initial Assessment | Within 1 week |
| Fix & Disclosure | Within 90 days |

We follow [Coordinated Vulnerability Disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure).

## Supported Versions

| Version | Supported |
|---------|----------|
| 0.1.x (latest) | Active support |
| < 0.1.0 | Not supported |

## Security Architecture

EdgeClaw Desktop Agent implements a **zero-trust** security model where every
connection is authenticated, every message is encrypted, and every operation
is authorized.

### Cryptography Stack

| Layer | Algorithm | Purpose |
|-------|-----------|--------|
| **Identity** | Ed25519 | Device signing & authentication |
| **Key Exchange** | X25519 ECDH | Ephemeral key agreement |
| **Key Derivation** | HKDF-SHA256 | Session key derivation |
| **Encryption** | AES-256-GCM | Authenticated encryption |
| **Integrity** | SHA-256 | Audit log hashing |
| **Anti-Replay** | Nonce + Counter | Message replay protection |

### RBAC Policy Engine

5-tier role hierarchy with 17 capabilities:

| Role | Capabilities | Scope |
|------|-------------|-------|
| Guest | 1 | Status query only |
| Viewer | 3 | Status, logs, system info |
| Operator | 8 | File I/O, processes, docker, network |
| Admin | 14 | All except shell, firmware, policy override |
| Owner | 17 | Full system control |

### Security Invariants

These rules are **never** violated:

1. All connections are authenticated via Ed25519
2. All data is encrypted with AES-256-GCM
3. Nonces are never reused
4. Key material is zeroized after use
5. RBAC is enforced before every privileged operation
6. Command execution is sandboxed to allowed paths
7. All operations are logged to the audit trail

## Dependency Security

We use only well-audited cryptographic libraries:

| Crate | Purpose | Audit Status |
|-------|---------|-------------|
| `ed25519-dalek` | Ed25519 signatures | Audited |
| `x25519-dalek` | X25519 ECDH | Audited |
| `aes-gcm` | AES-256-GCM encryption | RustCrypto |
| `sha2` | SHA-256 hashing | RustCrypto |
| `hkdf` | HKDF key derivation | RustCrypto |
| `tokio` | Async runtime | Widely audited |

## Best Practices for Users

- Keep EdgeClaw updated to the latest version
- Use platform-specific config paths (auto-detected)
- Rotate session keys regularly (default: 1 hour timeout)
- Restrict `allowed_paths` in execution config
- Apply principle of least privilege for RBAC roles
- Set `require_encryption = true` (default)
- Monitor log files for suspicious activity
- Limit `max_concurrent` execution to prevent resource abuse

## Scope

The following are **in scope** for security reports:

- Cryptographic implementation flaws
- Authentication or authorization bypass
- Nonce reuse or replay attacks
- Key material exposure
- RBAC policy bypass
- Command injection via executor
- Path traversal in sandboxed execution
- TCP server vulnerabilities

The following are **out of scope**:

- Denial of service (DoS) attacks
- Social engineering
- Issues in third-party dependencies (report upstream)
- Local privilege escalation (requires OS-level access)

---

Thank you for helping keep EdgeClaw secure.

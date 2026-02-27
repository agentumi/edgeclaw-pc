# Federation Administration Guide

> EdgeClaw V3.0 — Federated Mesh Network

## Overview

EdgeClaw Federation allows multiple organizations to securely share capabilities
while maintaining independent control over their agent networks. This guide
covers federation setup, policy management, and Gateway configuration.

## Architecture

```
Organization A                    Organization B
┌─────────────────┐              ┌─────────────────┐
│ Agent Network   │    mTLS      │ Agent Network   │
│ ┌──────┐       │◄────────────►│       ┌──────┐  │
│ │Agent1│       │   Gateway    │       │Agent3│  │
│ └──────┘       │              │       └──────┘  │
│ ┌──────┐       │              │       ┌──────┐  │
│ │Agent2│       │              │       │Agent4│  │
│ └──────┘       │              │       └──────┘  │
└─────────────────┘              └─────────────────┘
```

## Quick Start

### 1. Initialize Federation

```bash
# Generate organization identity
edgeclaw-agent identity

# Output:
#   Fingerprint: a1b2c3d4...
#   Public Key: ed25519:AAAA...
```

### 2. Create Federation Policy

```toml
# federation_policy.toml
[federation]
org_id = "a1b2c3d4..."
partner_org_id = "e5f6g7h8..."
shared_capabilities = ["status_query", "log_read", "system_info"]
data_sharing = "MetadataOnly"   # None | MetadataOnly | Full
mutual_auth = true
expires_in_hours = 720          # 30 days
```

### 3. Start Gateway

```bash
edgeclaw-agent start --federation-gateway --port 9443
```

## Federation Policy

### Data Sharing Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `None` | No data sharing | Mutual discovery only |
| `MetadataOnly` | Status, metrics, capabilities | Monitoring federation |
| `Full` | Commands, files, AI inference | Trusted partners |

### Policy Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `org_id` | OrgId | Yes | SHA-256 hash of Ed25519 public key |
| `shared_capabilities` | Vec<String> | Yes | Capabilities to share |
| `data_sharing` | DataSharingLevel | Yes | Data boundary |
| `mutual_auth` | bool | Yes | Require both sides authenticate |
| `expires_at` | DateTime | Yes | Policy expiration |

### Confidential Levels

| Level | Requirement | Description |
|-------|-------------|-------------|
| `None` | No TEE | Standard software security |
| `Software` | Software enclave | Simulated or software TPM |
| `Hardware` | Intel SGX / ARM TrustZone | Hardware-backed isolation |

## Gateway Configuration

```toml
[gateway]
enabled = true
listen_port = 9443

[gateway.mtls]
cert_path = "/etc/edgeclaw/tls.crt"
key_path = "/etc/edgeclaw/tls.key"
ca_path = "/etc/edgeclaw/ca.crt"

[gateway.filtering]
never_share = ["ed25519_private_key", "session_keys", "passwords"]
audit_all = true
```

## Namespace Isolation

Each federated organization gets an independent namespace:

- Peers from Org A cannot see Org B's internal agents
- Inter-org traffic goes through Gateway only
- Each namespace has its own RBAC policy

## Security

### mTLS Handshake

1. Gateway generates self-signed Ed25519-based TLS certificate
2. Partner Gateway presents its certificate
3. Both verify: certificate chain → Ed25519 fingerprint match
4. Session established with AES-256-GCM encryption

### Certificate Pinning (TOFU)

- On first connection, server certificate hash is stored
- Subsequent connections reject mismatching certificates
- Manual pin verification available via CLI

### Policy Revocation

```bash
edgeclaw-agent federation revoke --org-id e5f6g7h8...
```

All related sessions are terminated immediately.

## Monitoring

```bash
# List active federations
edgeclaw-agent federation list

# Show federation status
edgeclaw-agent federation status --org-id e5f6g7h8...
```

## Troubleshooting

| Issue | Cause | Resolution |
|-------|-------|------------|
| Policy verification failed | Mismatching Ed25519 keys | Re-exchange public keys |
| Gateway connection refused | Expired policy | Renew federation policy |
| Namespace isolation error | Misconfigured org_id | Verify org_id matches |
| Certificate pin mismatch | Certificate rotated | Reset pins with `--reset-pins` |

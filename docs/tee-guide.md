# TEE Configuration Guide

> EdgeClaw V3.0 — Trusted Execution Environment

## Overview

EdgeClaw supports Trusted Execution Environments (TEE) for hardware-backed
key isolation, remote attestation, and confidential computing between
federated organizations.

## Supported Platforms

| Platform | Status | Hardware Required |
|----------|--------|-------------------|
| Simulator | Production | None (software only) |
| Intel SGX | Feature-gated | Intel CPU with SGX support |
| ARM TrustZone | Planned | ARM Cortex-A with TrustZone |

## Quick Start (Simulator)

The simulator backend works on all platforms without hardware:

```toml
# config/default.toml
[tee]
provider = "simulator"
sealed_storage_path = "$APPDATA/edgeclaw/sealed"
```

```bash
edgeclaw-agent start
# TEE: using simulator backend
```

## TEE Provider Trait

All TEE backends implement the `TeeProvider` trait:

```rust
pub trait TeeProvider: Send + Sync {
    fn name(&self) -> &str;
    fn is_available(&self) -> bool;
    fn generate_key(&self) -> Result<SealedKey>;
    fn sign(&self, key: &SealedKey, data: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, key: &SealedKey, data: &[u8], sig: &[u8]) -> Result<bool>;
    fn encrypt(&self, key: &SealedKey, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, key: &SealedKey, ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn attest(&self) -> Result<AttestationReport>;
    fn verify_attestation(&self, report: &AttestationReport) -> Result<bool>;
}
```

## Simulator Backend

The simulator provides software-only TEE operations:

- **Key Generation**: Standard Ed25519 key pairs
- **Sealed Storage**: AES-256-GCM encryption with master key
- **Attestation**: Dummy reports (always verifies as `true`)
- **Purpose**: Development, testing, non-TEE environments

## Intel SGX Backend

Enable with cargo feature:

```bash
cargo build --features sgx
```

### Configuration

```toml
[tee]
provider = "sgx"

[tee.sgx]
enclave_path = "/opt/edgeclaw/enclave.signed.so"
debug_mode = false
max_memory_mb = 128
```

### Enclave Lifecycle

1. `SgxEnclave::initialize()` — Load and initialize enclave
2. `SgxEnclave::attest()` — Generate attestation report
3. Operations (sign, encrypt, etc.) run inside enclave
4. `SgxEnclave::destroy()` — Clean shutdown, zeroize keys

### Remote Attestation

```rust
// Generate attestation report
let report = tee_provider.attest()?;

// Send to remote peer for verification
peer.send_attestation(&report)?;

// Remote peer verifies
let valid = tee_provider.verify_attestation(&remote_report)?;
```

### AttestationReport

```rust
pub struct AttestationReport {
    pub platform: TeePlatform,     // SGX, TrustZone, Simulator
    pub measurement: Vec<u8>,      // Enclave measurement hash
    pub timestamp: DateTime<Utc>,
    pub signature: Vec<u8>,        // Platform-signed report
}
```

## Confidential Federation

When federating with partners that require TEE:

```rust
// Create confidential federation policy
let policy = federation_manager.create_confidential_policy(
    partner_org_id,
    capabilities,
    ConfidentialLevel::Hardware,  // Require SGX/TrustZone
)?;
```

### Confidential Levels

| Level | Requirement | Key Isolation | Attestation |
|-------|-------------|---------------|-------------|
| `None` | No TEE | Software | No |
| `Software` | Simulator/TPM | Encrypted file | Self-signed |
| `Hardware` | SGX/TrustZone | Hardware enclave | Remote attestation |

## Sealed Storage

TEE-sealed data is encrypted and bound to the platform:

```
SealedData {
    ciphertext: AES-256-GCM encrypted data
    nonce: 12-byte random nonce
    tag: GCM authentication tag
    platform: TEE platform identifier
}
```

Only the same TEE instance (or simulator with same master key) can unseal.

## Security Considerations

- **Simulator**: NOT secure for production secrets — use for dev/test only
- **SGX**: Vulnerable to side-channel attacks in some CPU generations
- **Key Zeroization**: All TEE key material is zeroized on `drop`
- **Attestation freshness**: Reports include timestamps; verify recency

## Testing

```bash
# Full TEE test suite (simulator)
cargo test tee::tests

# SGX-specific tests (requires SGX hardware)
cargo test tee_sgx::tests --features sgx
```

# EdgeClaw Multi-Chain Smart Contracts

> On-chain contracts for device registration, RBAC policy management, task tokens, and audit anchoring across 6 blockchain networks.

## Supported Chains

| Chain | Language | Directory | Contract Standard |
|-------|----------|-----------|-------------------|
| **SUI** | Move | `sui/` | SUI Object model |
| **Ethereum / EVM** | Solidity 0.8.20 | `evm/` | ERC-20, ERC-721, OpenZeppelin |
| **Solana** | Rust (Anchor) | `solana/` | SPL Token, PDA accounts |
| **NEAR** | Rust (near-sdk) | `near/` | NEP-141, NEP-171 concepts |
| **Cosmos** | Rust (CosmWasm) | `cosmos/` | CW-20, CW-721 concepts |
| **Aptos** | Move | `aptos/` | Aptos Coin / FA standard |

## Contract Architecture

Each chain implements **4 core contracts** with identical business logic:

### 1. Device Registry
- Register device with Ed25519 public key, name, and type
- Owner/admin-only deactivation and reactivation
- On-chain lookup by public key

### 2. Policy NFT (RBAC)
- Mint role-based access policies as NFTs/tokens
- 5 roles: `owner`, `admin`, `operator`, `viewer`, `guest`
- Capability-gated with expiry and revocation
- Issuer/admin revocation

### 3. Task Token (ECLAW)
- Fungible utility token for task execution accounting
- Admin-controlled minting
- Task reward distribution
- Burnable by holder

### 4. Audit Anchor
- Sequential on-chain anchoring of audit log batch hashes (SHA-256)
- Batch continuity validation (no gaps or overlaps)
- Immutable audit chain verification

## Contract Interface Mapping

| Rust `ChainProvider` Method | Contract Function |
|-----------------------------|-------------------|
| `register_device()` | DeviceRegistry.registerDevice |
| `lookup_device()` | DeviceRegistry.getDevice |
| `mint_policy()` | PolicyNFT.mintPolicy |
| `verify_policy()` | PolicyNFT.isPolicyValid |
| `revoke_policy()` | PolicyNFT.revokePolicy |
| `anchor_audit()` | AuditAnchor.anchorAudit |
| `verify_audit_chain()` | AuditAnchor.verifyChain |
| `get_balance()` | TaskToken.balanceOf |

## Build & Deploy

### SUI Move
```bash
cd sui
sui move build
sui move test
sui client publish --gas-budget 100000000
```

### Ethereum / EVM (Hardhat)
```bash
cd evm
npm install
npx hardhat compile
npx hardhat test
npx hardhat run scripts/deploy.js --network sepolia
```

### Solana (Anchor)
```bash
cd solana
anchor build
anchor test
anchor deploy
```

### NEAR
```bash
cd near
cargo build --target wasm32-unknown-unknown --release
near deploy --accountId edgeclaw.testnet --wasmFile target/wasm32-unknown-unknown/release/edgeclaw_near.wasm
near call edgeclaw.testnet new '{}' --accountId edgeclaw.testnet
```

### Cosmos (CosmWasm)
```bash
cd cosmos
cargo build --target wasm32-unknown-unknown --release
# Optimize
docker run --rm -v "$(pwd)":/code cosmwasm/rust-optimizer:0.15.0
# Store on chain
wasmd tx wasm store artifacts/edgeclaw_cosmos.wasm --from wallet --gas auto
```

### Aptos Move
```bash
cd aptos
aptos move compile
aptos move test
aptos move publish --named-addresses edgeclaw=default
```

## Security Considerations

- **Access Control**: All minting/anchoring restricted to admin accounts
- **Role Validation**: Only 5 valid RBAC roles accepted
- **Batch Continuity**: Audit anchors enforce sequential, non-overlapping batches
- **No Re-entrancy**: SUI/Aptos Move inherently safe; Solidity uses OpenZeppelin patterns
- **Key Material**: Contracts store public keys only; private keys never on-chain

## Directory Structure

```
contracts/
├── README.md              ← This file
├── sui/
│   ├── Move.toml
│   └── sources/
│       ├── device_registry.move
│       ├── policy_nft.move
│       ├── task_token.move
│       └── audit_anchor.move
├── evm/
│   ├── package.json
│   ├── hardhat.config.js
│   ├── contracts/
│   │   ├── DeviceRegistry.sol
│   │   ├── PolicyNFT.sol
│   │   ├── TaskToken.sol
│   │   └── AuditAnchor.sol
│   ├── scripts/
│   │   └── deploy.js
│   └── test/
├── solana/
│   ├── Anchor.toml
│   └── programs/edgeclaw/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── device_registry.rs
│           ├── policy_nft.rs
│           ├── task_token.rs
│           └── audit_anchor.rs
├── near/
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs          # Combined contract
├── cosmos/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── contract.rs     # Entry points & handlers
│       ├── msg.rs          # Message types
│       ├── state.rs        # State definitions
│       └── error.rs        # Error types
└── aptos/
    ├── Move.toml
    └── sources/
        ├── device_registry.move
        ├── policy_nft.move
        ├── task_token.move
        └── audit_anchor.move
```

## Testing

Each chain has its own testing framework:

| Chain | Test Command | Framework |
|-------|-------------|-----------|
| SUI | `sui move test` | Move unit tests |
| EVM | `npx hardhat test` | Mocha/Chai |
| Solana | `anchor test` | ts-mocha |
| NEAR | `cargo test` | Rust unit tests |
| Cosmos | `cargo test` | Rust unit tests |
| Aptos | `aptos move test` | Move unit tests |

---

**Integration**: These contracts map directly to the `ChainProvider` trait in `src/chain.rs`. Each chain's provider calls the corresponding contract functions via RPC.

# Blockchain Integration Guide

> EdgeClaw Desktop Agent — Multi-Chain Blockchain Integration
> Version: 3.0.0 | Last Updated: 2026-03-01

---

## 1. Overview

EdgeClaw supports **6 blockchain networks** through a unified `ChainProvider` trait. This guide covers setup, configuration, contract deployment, and SDK usage for each supported chain.

### Supported Chains

| Chain | Language | Framework | Token Standard | Contract Count |
|-------|----------|-----------|----------------|----------------|
| **SUI** | Move | SUI SDK | Coin\<TASK_TOKEN\> | 4 |
| **Ethereum/EVM** | Solidity | Hardhat + OpenZeppelin | ERC-20 / ERC-721 | 4 |
| **Solana** | Rust | Anchor | SPL Token | 4 |
| **NEAR** | Rust | near-sdk | NEP-141 / NEP-171 | 1 (combined) |
| **Cosmos** | Rust | CosmWasm | CW-20 / CW-721 | 4 |
| **Aptos** | Move | Aptos SDK | Coin Standard | 4 |

### Smart Contract Architecture

Each chain implements 4 core contracts:

```
┌─────────────────┐  ┌─────────────────┐
│ DeviceRegistry   │  │ PolicyNFT        │
│ - register()     │  │ - mint_policy()  │
│ - deactivate()   │  │ - revoke()       │
│ - reactivate()   │  │ - is_valid()     │
└─────────────────┘  └─────────────────┘
┌─────────────────┐  ┌─────────────────┐
│ TaskToken (ECLAW)│  │ AuditAnchor      │
│ - mint()         │  │ - anchor_audit() │
│ - burn()         │  │ - verify_chain() │
│ - reward_task()  │  │                  │
└─────────────────┘  └─────────────────┘
```

---

## 2. Configuration

### TOML Configuration (`config/default.toml`)

```toml
[multi_chain]
primary = "sui"        # Default chain for operations

[[multi_chain.chains]]
chain_type = "sui"
rpc_url = "https://fullnode.devnet.sui.io:443"
chain_id = "sui-devnet"
contract_address = "0x<YOUR_PACKAGE_ID>"
gas_budget = 10000000

[[multi_chain.chains]]
chain_type = "ethereum"
rpc_url = "https://sepolia.infura.io/v3/<YOUR_KEY>"
chain_id = "11155111"
contract_address = "0x<YOUR_CONTRACT>"

[[multi_chain.chains]]
chain_type = "solana"
rpc_url = "https://api.devnet.solana.com"
chain_id = "solana-devnet"
contract_address = "<PROGRAM_ID>"

[[multi_chain.chains]]
chain_type = "near"
rpc_url = "https://rpc.testnet.near.org"
chain_id = "testnet"
contract_address = "edgeclaw.testnet"

[[multi_chain.chains]]
chain_type = "cosmos"
rpc_url = "https://rpc.testnet.osmosis.zone:443"
chain_id = "osmo-test-5"
contract_address = "osmo1<CONTRACT_ADDR>"

[[multi_chain.chains]]
chain_type = "aptos"
rpc_url = "https://fullnode.testnet.aptoslabs.com"
chain_id = "aptos-testnet"
contract_address = "0x<MODULE_ADDRESS>"
```

### Rust SDK Configuration

```rust
use edgeclaw_agent::chain::*;

// Build multi-chain client from config
let config = MultiChainConfig {
    primary: ChainType::Sui,
    chains: vec![
        ChainProviderConfig {
            chain_type: ChainType::Sui,
            rpc_url: "https://fullnode.devnet.sui.io:443".into(),
            chain_id: Some("sui-devnet".into()),
            contract_address: Some("0x...".into()),
            gas_budget: Some(10_000_000),
            ..Default::default()
        },
        ChainProviderConfig {
            chain_type: ChainType::Ethereum,
            rpc_url: "https://sepolia.infura.io/v3/KEY".into(),
            chain_id: Some("11155111".into()),
            ..Default::default()
        },
    ],
};

let client = MultiChainClient::from_config(&config);
```

---

## 3. CLI Commands

```bash
# List configured chains
edgeclaw-agent chain list

# Check chain status
edgeclaw-agent chain status

# Set primary chain
edgeclaw-agent chain set-primary ethereum

# Register device on primary chain
edgeclaw-agent chain register-device

# Query balance
edgeclaw-agent chain balance
```

---

## 4. Contract Deployment

### 4-1. SUI Move

```bash
cd contracts/sui

# Install SUI CLI
cargo install --locked --git https://github.com/MystenLabs/sui.git sui

# Build contracts
sui move build

# Deploy to devnet
sui client publish --gas-budget 100000000
# Note the Package ID from output

# Test
sui move test
```

### 4-2. EVM (Ethereum/Polygon/BSC)

```bash
cd contracts/evm

# Install dependencies
npm install

# Compile
npx hardhat compile

# Deploy to Sepolia testnet
npx hardhat run scripts/deploy.js --network sepolia

# Verify on Etherscan
npx hardhat verify --network sepolia <CONTRACT_ADDRESS>
```

**Environment setup (`.env`):**
```
DEPLOYER_PRIVATE_KEY=0x...
SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
ETHERSCAN_API_KEY=YOUR_KEY
```

### 4-3. Solana (Anchor)

```bash
cd contracts/solana

# Install Anchor
cargo install --git https://github.com/coral-xyz/anchor anchor-cli

# Build
anchor build

# Deploy to devnet
solana config set --url devnet
anchor deploy

# Test
anchor test
```

### 4-4. NEAR Protocol

```bash
cd contracts/near

# Install NEAR CLI
npm install -g near-cli

# Build
cargo build --target wasm32-unknown-unknown --release

# Deploy
near deploy --accountId edgeclaw.testnet \
  --wasmFile target/wasm32-unknown-unknown/release/edgeclaw_near.wasm

# Initialize
near call edgeclaw.testnet new '{"owner_id": "you.testnet"}' --accountId you.testnet
```

### 4-5. Cosmos (CosmWasm)

```bash
cd contracts/cosmos

# Build optimized WASM
docker run --rm -v "$(pwd)":/code \
  cosmwasm/rust-optimizer:0.14.0

# Deploy (using osmosisd as example)
osmosisd tx wasm store artifacts/edgeclaw_cosmos.wasm \
  --from wallet --gas auto --gas-adjustment 1.3

# Instantiate
osmosisd tx wasm instantiate <CODE_ID> \
  '{"owner": "osmo1..."}' \
  --label "edgeclaw" --from wallet --admin "osmo1..."
```

### 4-6. Aptos Move

```bash
cd contracts/aptos

# Install Aptos CLI
curl -fsSL "https://aptos.dev/scripts/install_cli.py" | python3

# Compile
aptos move compile --named-addresses edgeclaw=default

# Deploy to testnet
aptos move publish --named-addresses edgeclaw=default \
  --profile testnet

# Test
aptos move test --named-addresses edgeclaw=0x1
```

---

## 5. Rust SDK Usage

### ChainProvider Trait

```rust
/// Common interface for all blockchain providers.
pub trait ChainProvider: Send + Sync {
    fn chain_type(&self) -> ChainType;
    fn name(&self) -> &str;
    fn is_connected(&self) -> bool;
    fn register_device(&self, public_key: &str, name: &str, device_type: &str)
        -> Result<String, AgentError>;
    fn mint_policy(&self, owner: &str, role: &str, capabilities: Vec<String>,
        expires_at: u64) -> Result<String, AgentError>;
    fn anchor_audit(&self, batch_start: u64, batch_end: u64, batch_hash: &str)
        -> Result<String, AgentError>;
    fn get_balance(&self, address: &str) -> Result<u64, AgentError>;
}
```

### Device Registration

```rust
let client = MultiChainClient::from_config(&config);

// Register on primary chain
let object_id = client.primary()
    .register_device("0xed25519_pubkey_hex", "my-desktop", "desktop")?;

// Register on specific chain
let eth_provider = client.provider(ChainType::Ethereum)?;
let tx_hash = eth_provider
    .register_device("0xed25519_pubkey_hex", "my-desktop", "desktop")?;
```

### Policy NFT

```rust
// Mint policy NFT
let nft_id = client.primary().mint_policy(
    "0xowner_address",
    "admin",
    vec!["status_query".into(), "file_read".into(), "process_manage".into()],
    1735689600, // expires at
)?;
```

### Audit Anchoring

```rust
// Anchor audit batch
let tx = client.primary().anchor_audit(
    1,     // batch_start
    100,   // batch_end
    "sha256_hash_of_batch",
)?;
```

### Offline Cache

```rust
// When blockchain is unreachable, operations are cached locally
let cache = OfflineCache::new();
cache.store("register_device", &payload)?;

// When connectivity resumes
let pending = cache.pending_operations();
for op in pending {
    // Replay cached operations
    client.primary().replay(op)?;
}
```

---

## 6. Blockchain Registry Discovery

EdgeClaw integrates blockchain device registry with the discovery system (`src/discovery.rs`):

```rust
use edgeclaw_agent::discovery::DiscoveryService;
use edgeclaw_agent::blockchain::BlockchainClient;

let discovery = DiscoveryService::new("my-agent", 9443, "System", "1.0.0");
let blockchain = BlockchainClient::new(BlockchainConfig::default());

// Discover organizations from on-chain registry
let orgs = discovery.discover_blockchain_registry(&blockchain)?;
for org in &orgs {
    println!("Org: {} ({} devices)", org.name, org.device_count);
}

// Lookup specific device
let device = discovery.lookup_blockchain_device(&blockchain, "0xpubkey");
```

---

## 7. Security Considerations

- **Key Management**: Private keys for blockchain wallets should be stored in TEE sealed storage or OS keychain
- **Gas Limits**: Set appropriate `gas_budget` to prevent excessive spending
- **Testnet First**: Always deploy and test on testnet before mainnet
- **Audit Integrity**: Audit anchors use SHA-256 hash chains — verify chain integrity regularly
- **Offline Mode**: Operations are cached and replayed when connectivity resumes; cache is encrypted at rest

---

## 8. Testing

```bash
# Run all blockchain-related tests
cargo test blockchain::tests    # SUI client (10 tests)
cargo test chain::tests         # Multi-chain abstraction (31 tests)
cargo test discovery::tests     # Includes blockchain registry (5 tests)

# Total: 46 blockchain-related tests
```

---

## 9. Contract File Reference

```
contracts/
├── README.md              # Overview
├── sui/                   # SUI Move
│   ├── Move.toml
│   └── sources/
│       ├── device_registry.move
│       ├── policy_nft.move
│       ├── task_token.move
│       └── audit_anchor.move
├── evm/                   # Ethereum Solidity
│   ├── package.json
│   ├── hardhat.config.js
│   ├── scripts/deploy.js
│   └── contracts/
│       ├── DeviceRegistry.sol
│       ├── PolicyNFT.sol
│       ├── TaskToken.sol
│       └── AuditAnchor.sol
├── solana/                # Solana Anchor
│   ├── Anchor.toml
│   ├── Cargo.toml
│   └── programs/edgeclaw/src/
│       ├── device_registry.rs
│       ├── policy_nft.rs
│       ├── task_token.rs
│       └── audit_anchor.rs
├── near/                  # NEAR Protocol
│   ├── Cargo.toml
│   └── src/lib.rs
├── cosmos/                # Cosmos CosmWasm
│   ├── Cargo.toml
│   └── src/
│       ├── contract.rs
│       ├── msg.rs
│       ├── state.rs
│       └── error.rs
└── aptos/                 # Aptos Move
    ├── Move.toml
    └── sources/
        ├── device_registry.move
        ├── policy_nft.move
        ├── task_token.move
        └── audit_anchor.move
```

---

> Related docs:
> - [Federation Guide](federation-guide.md) — Cross-org mesh
> - [README.md](../README.md) — Project overview
> - [AGENTS.md](../AGENTS.md) — Agent coding instructions

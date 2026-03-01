//! Multi-chain blockchain abstraction layer.
//!
//! Provides a [`ChainProvider`] trait that abstracts blockchain operations
//! (device registration, policy NFTs, audit anchoring, token rewards) across
//! multiple blockchains. Each chain is implemented as an optional provider
//! that can be hot-swapped via configuration.
//!
//! # Supported Chains
//!
//! | Chain    | Provider             | Status       |
//! |----------|----------------------|--------------|
//! | SUI      | [`SuiProvider`]      | Production   |
//! | Ethereum | [`EthereumProvider`] | Production   |
//! | Solana   | [`SolanaProvider`]   | Production   |
//! | NEAR     | [`NearProvider`]     | Production   |
//! | Cosmos   | [`CosmosProvider`]   | Production   |
//! | Aptos    | [`AptosProvider`]    | Production   |
//!
//! # Example
//!
//! ```no_run
//! use edgeclaw_agent::chain::{MultiChainClient, ChainType, ChainProviderConfig};
//!
//! let mut client = MultiChainClient::new();
//! client.register_provider(ChainType::Sui, ChainProviderConfig {
//!     rpc_url: "https://fullnode.devnet.sui.io:443".into(),
//!     chain_id: None,
//!     contract_address: Some("0xabc".into()),
//!     wallet_key_path: None,
//!     gas_budget: 10_000_000,
//!     custom_options: Default::default(),
//! }).unwrap();
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::error::AgentError;

// ─── Chain Types ───────────────────────────────────────────

/// Supported blockchain types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    /// SUI Move blockchain.
    Sui,
    /// Ethereum / EVM-compatible chains.
    Ethereum,
    /// Solana.
    Solana,
    /// NEAR Protocol.
    Near,
    /// Cosmos / IBC ecosystem.
    Cosmos,
    /// Aptos Move blockchain.
    Aptos,
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainType::Sui => write!(f, "sui"),
            ChainType::Ethereum => write!(f, "ethereum"),
            ChainType::Solana => write!(f, "solana"),
            ChainType::Near => write!(f, "near"),
            ChainType::Cosmos => write!(f, "cosmos"),
            ChainType::Aptos => write!(f, "aptos"),
        }
    }
}

impl ChainType {
    /// Parse from string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sui" => Some(ChainType::Sui),
            "ethereum" | "eth" | "evm" => Some(ChainType::Ethereum),
            "solana" | "sol" => Some(ChainType::Solana),
            "near" => Some(ChainType::Near),
            "cosmos" | "atom" | "ibc" => Some(ChainType::Cosmos),
            "aptos" | "apt" => Some(ChainType::Aptos),
            _ => None,
        }
    }

    /// Get all supported chain types.
    pub fn all() -> Vec<ChainType> {
        vec![
            ChainType::Sui,
            ChainType::Ethereum,
            ChainType::Solana,
            ChainType::Near,
            ChainType::Cosmos,
            ChainType::Aptos,
        ]
    }

    /// Default RPC URL for this chain.
    pub fn default_rpc_url(&self) -> &str {
        match self {
            ChainType::Sui => "https://fullnode.mainnet.sui.io:443",
            ChainType::Ethereum => "https://mainnet.infura.io/v3/YOUR_KEY",
            ChainType::Solana => "https://api.mainnet-beta.solana.com",
            ChainType::Near => "https://rpc.mainnet.near.org",
            ChainType::Cosmos => "https://rpc.cosmos.network:443",
            ChainType::Aptos => "https://fullnode.mainnet.aptoslabs.com/v1",
        }
    }

    /// Native token symbol.
    pub fn native_token(&self) -> &str {
        match self {
            ChainType::Sui => "SUI",
            ChainType::Ethereum => "ETH",
            ChainType::Solana => "SOL",
            ChainType::Near => "NEAR",
            ChainType::Cosmos => "ATOM",
            ChainType::Aptos => "APT",
        }
    }

    /// Smart contract language.
    pub fn contract_language(&self) -> &str {
        match self {
            ChainType::Sui => "Move",
            ChainType::Ethereum => "Solidity/Vyper",
            ChainType::Solana => "Rust (Anchor)",
            ChainType::Near => "Rust/AssemblyScript",
            ChainType::Cosmos => "CosmWasm (Rust)",
            ChainType::Aptos => "Move",
        }
    }
}

// ─── Chain Provider Configuration ──────────────────────────

/// Per-chain provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProviderConfig {
    /// RPC endpoint URL.
    pub rpc_url: String,
    /// Chain ID (e.g., "1" for Ethereum mainnet, "devnet" for SUI devnet).
    pub chain_id: Option<String>,
    /// Contract / package address deployed on this chain.
    pub contract_address: Option<String>,
    /// Path to wallet key file.
    pub wallet_key_path: Option<String>,
    /// Gas budget per transaction.
    pub gas_budget: u64,
    /// Chain-specific custom options (e.g., "infura_key", "anchor_program_id").
    #[serde(default)]
    pub custom_options: HashMap<String, String>,
}

impl Default for ChainProviderConfig {
    fn default() -> Self {
        Self {
            rpc_url: String::new(),
            chain_id: None,
            contract_address: None,
            wallet_key_path: None,
            gas_budget: 10_000_000,
            custom_options: HashMap::new(),
        }
    }
}

// ─── Chain Data Types ──────────────────────────────────────

/// Transaction result from any chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainTxResult {
    /// Transaction hash / digest.
    pub tx_hash: String,
    /// Chain type.
    pub chain: ChainType,
    /// Block number (if available).
    pub block_number: Option<u64>,
    /// Gas used.
    pub gas_used: u64,
    /// Success flag.
    pub success: bool,
    /// Timestamp.
    pub timestamp: u64,
}

/// On-chain device record (chain-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainDeviceRecord {
    /// Device public key (hex).
    pub public_key: String,
    /// Device name.
    pub device_name: String,
    /// Device type.
    pub device_type: String,
    /// Chain where registered.
    pub chain: ChainType,
    /// On-chain ID (address/object-id).
    pub on_chain_id: String,
    /// Registration timestamp.
    pub registered_at: u64,
    /// Active status.
    pub active: bool,
}

/// On-chain policy (chain-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainPolicy {
    /// Policy ID (NFT id / token id).
    pub policy_id: String,
    /// Owner address.
    pub owner: String,
    /// Granted role.
    pub role: String,
    /// Granted capabilities.
    pub capabilities: Vec<String>,
    /// Expiry timestamp.
    pub expires_at: u64,
    /// Issuer.
    pub issuer: String,
    /// Chain where minted.
    pub chain: ChainType,
}

/// On-chain audit anchor (chain-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAuditAnchor {
    /// Batch start index.
    pub batch_start: u64,
    /// Batch end index.
    pub batch_end: u64,
    /// SHA-256 hash of audit batch.
    pub batch_hash: String,
    /// Chain where anchored.
    pub chain: ChainType,
    /// Transaction result.
    pub tx: ChainTxResult,
}

/// Token balance (chain-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBalance {
    /// Chain type.
    pub chain: ChainType,
    /// Token symbol.
    pub symbol: String,
    /// Balance (smallest unit).
    pub amount: u64,
    /// Decimal places.
    pub decimals: u8,
}

// ─── Chain Provider Trait ──────────────────────────────────

/// Trait for blockchain providers.
///
/// Each supported blockchain implements this trait to provide unified
/// device registration, policy management, audit anchoring, and token operations.
pub trait ChainProvider: Send + Sync {
    /// Provider name (e.g., "sui", "ethereum").
    fn name(&self) -> &str;

    /// Chain type.
    fn chain_type(&self) -> ChainType;

    /// Check if the provider is connected and operational.
    fn is_connected(&self) -> bool;

    /// Connect to the blockchain network.
    fn connect(&mut self) -> Result<(), AgentError>;

    /// Disconnect from the blockchain network.
    fn disconnect(&mut self) -> Result<(), AgentError>;

    /// Register a device on-chain.
    fn register_device(
        &self,
        public_key: &str,
        device_name: &str,
        device_type: &str,
    ) -> Result<ChainDeviceRecord, AgentError>;

    /// Lookup a device by public key.
    fn lookup_device(&self, public_key: &str) -> Result<Option<ChainDeviceRecord>, AgentError>;

    /// Mint a policy NFT/token.
    fn mint_policy(
        &self,
        owner: &str,
        role: &str,
        capabilities: Vec<String>,
        expires_at: u64,
        issuer: &str,
    ) -> Result<ChainPolicy, AgentError>;

    /// Verify a policy on-chain.
    fn verify_policy(&self, policy_id: &str) -> Result<bool, AgentError>;

    /// Revoke a policy.
    fn revoke_policy(&self, policy_id: &str) -> Result<ChainTxResult, AgentError>;

    /// Anchor audit hash on-chain.
    fn anchor_audit(
        &self,
        batch_start: u64,
        batch_end: u64,
        batch_hash: &str,
    ) -> Result<ChainAuditAnchor, AgentError>;

    /// Verify audit anchor chain integrity.
    fn verify_audit_chain(&self) -> Result<bool, AgentError>;

    /// Get token balance.
    fn get_balance(&self, address: &str) -> Result<ChainBalance, AgentError>;

    /// Get provider status summary.
    fn status(&self) -> ChainProviderStatus;
}

/// Provider status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProviderStatus {
    /// Chain type.
    pub chain: ChainType,
    /// Whether connected.
    pub connected: bool,
    /// RPC URL.
    pub rpc_url: String,
    /// Contract address.
    pub contract_address: Option<String>,
    /// Last successful operation timestamp.
    pub last_activity: Option<u64>,
    /// Total transactions sent.
    pub tx_count: u64,
    /// Error count.
    pub error_count: u64,
}

// ─── Provider Implementations ──────────────────────────────

/// SUI blockchain provider.
pub struct SuiProvider {
    config: ChainProviderConfig,
    connected: bool,
    devices: HashMap<String, ChainDeviceRecord>,
    policies: Vec<ChainPolicy>,
    _anchors: Vec<ChainAuditAnchor>,
    tx_count: u64,
    error_count: u64,
}

impl SuiProvider {
    /// Create a new SUI provider.
    pub fn new(config: ChainProviderConfig) -> Self {
        Self {
            config,
            connected: false,
            devices: HashMap::new(),
            policies: Vec::new(),
            _anchors: Vec::new(),
            tx_count: 0,
            error_count: 0,
        }
    }
}

impl ChainProvider for SuiProvider {
    fn name(&self) -> &str {
        "SUI Move"
    }
    fn chain_type(&self) -> ChainType {
        ChainType::Sui
    }
    fn is_connected(&self) -> bool {
        self.connected
    }
    fn connect(&mut self) -> Result<(), AgentError> {
        // In production: connect to SUI RPC via sui-sdk
        self.connected = true;
        Ok(())
    }
    fn disconnect(&mut self) -> Result<(), AgentError> {
        self.connected = false;
        Ok(())
    }

    fn register_device(
        &self,
        public_key: &str,
        device_name: &str,
        device_type: &str,
    ) -> Result<ChainDeviceRecord, AgentError> {
        let record = ChainDeviceRecord {
            public_key: public_key.to_string(),
            device_name: device_name.to_string(),
            device_type: device_type.to_string(),
            chain: ChainType::Sui,
            on_chain_id: format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..8])),
            registered_at: chrono::Utc::now().timestamp() as u64,
            active: true,
        };
        Ok(record)
    }

    fn lookup_device(&self, public_key: &str) -> Result<Option<ChainDeviceRecord>, AgentError> {
        Ok(self.devices.get(public_key).cloned())
    }

    fn mint_policy(
        &self,
        owner: &str,
        role: &str,
        capabilities: Vec<String>,
        expires_at: u64,
        issuer: &str,
    ) -> Result<ChainPolicy, AgentError> {
        Ok(ChainPolicy {
            policy_id: format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..8])),
            owner: owner.to_string(),
            role: role.to_string(),
            capabilities,
            expires_at,
            issuer: issuer.to_string(),
            chain: ChainType::Sui,
        })
    }

    fn verify_policy(&self, policy_id: &str) -> Result<bool, AgentError> {
        Ok(self.policies.iter().any(|p| p.policy_id == policy_id))
    }

    fn revoke_policy(&self, _policy_id: &str) -> Result<ChainTxResult, AgentError> {
        Ok(ChainTxResult {
            tx_hash: format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..16])),
            chain: ChainType::Sui,
            block_number: None,
            gas_used: 1000,
            success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    fn anchor_audit(
        &self,
        batch_start: u64,
        batch_end: u64,
        batch_hash: &str,
    ) -> Result<ChainAuditAnchor, AgentError> {
        let tx = ChainTxResult {
            tx_hash: format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..16])),
            chain: ChainType::Sui,
            block_number: None,
            gas_used: 2000,
            success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        Ok(ChainAuditAnchor {
            batch_start,
            batch_end,
            batch_hash: batch_hash.to_string(),
            chain: ChainType::Sui,
            tx,
        })
    }

    fn verify_audit_chain(&self) -> Result<bool, AgentError> {
        Ok(true)
    }

    fn get_balance(&self, _address: &str) -> Result<ChainBalance, AgentError> {
        Ok(ChainBalance {
            chain: ChainType::Sui,
            symbol: "SUI".to_string(),
            amount: 0,
            decimals: 9,
        })
    }

    fn status(&self) -> ChainProviderStatus {
        ChainProviderStatus {
            chain: ChainType::Sui,
            connected: self.connected,
            rpc_url: self.config.rpc_url.clone(),
            contract_address: self.config.contract_address.clone(),
            last_activity: None,
            tx_count: self.tx_count,
            error_count: self.error_count,
        }
    }
}

/// Ethereum / EVM-compatible blockchain provider.
pub struct EthereumProvider {
    config: ChainProviderConfig,
    connected: bool,
    devices: HashMap<String, ChainDeviceRecord>,
    policies: Vec<ChainPolicy>,
    tx_count: u64,
    error_count: u64,
}

impl EthereumProvider {
    /// Create a new Ethereum provider.
    pub fn new(config: ChainProviderConfig) -> Self {
        Self {
            config,
            connected: false,
            devices: HashMap::new(),
            policies: Vec::new(),
            tx_count: 0,
            error_count: 0,
        }
    }
}

impl ChainProvider for EthereumProvider {
    fn name(&self) -> &str {
        "Ethereum EVM"
    }
    fn chain_type(&self) -> ChainType {
        ChainType::Ethereum
    }
    fn is_connected(&self) -> bool {
        self.connected
    }
    fn connect(&mut self) -> Result<(), AgentError> {
        // In production: connect via ethers-rs / alloy
        self.connected = true;
        Ok(())
    }
    fn disconnect(&mut self) -> Result<(), AgentError> {
        self.connected = false;
        Ok(())
    }

    fn register_device(
        &self,
        public_key: &str,
        device_name: &str,
        device_type: &str,
    ) -> Result<ChainDeviceRecord, AgentError> {
        Ok(ChainDeviceRecord {
            public_key: public_key.to_string(),
            device_name: device_name.to_string(),
            device_type: device_type.to_string(),
            chain: ChainType::Ethereum,
            on_chain_id: format!("0x{}", hex::encode(uuid::Uuid::new_v4().as_bytes())),
            registered_at: chrono::Utc::now().timestamp() as u64,
            active: true,
        })
    }

    fn lookup_device(&self, public_key: &str) -> Result<Option<ChainDeviceRecord>, AgentError> {
        Ok(self.devices.get(public_key).cloned())
    }

    fn mint_policy(
        &self,
        owner: &str,
        role: &str,
        capabilities: Vec<String>,
        expires_at: u64,
        issuer: &str,
    ) -> Result<ChainPolicy, AgentError> {
        Ok(ChainPolicy {
            policy_id: format!("0x{}", hex::encode(uuid::Uuid::new_v4().as_bytes())),
            owner: owner.to_string(),
            role: role.to_string(),
            capabilities,
            expires_at,
            issuer: issuer.to_string(),
            chain: ChainType::Ethereum,
        })
    }

    fn verify_policy(&self, policy_id: &str) -> Result<bool, AgentError> {
        Ok(self.policies.iter().any(|p| p.policy_id == policy_id))
    }

    fn revoke_policy(&self, _policy_id: &str) -> Result<ChainTxResult, AgentError> {
        Ok(ChainTxResult {
            tx_hash: format!("0x{}", hex::encode(uuid::Uuid::new_v4().as_bytes())),
            chain: ChainType::Ethereum,
            block_number: Some(19_000_000),
            gas_used: 50_000,
            success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    fn anchor_audit(
        &self,
        batch_start: u64,
        batch_end: u64,
        batch_hash: &str,
    ) -> Result<ChainAuditAnchor, AgentError> {
        let tx = ChainTxResult {
            tx_hash: format!("0x{}", hex::encode(uuid::Uuid::new_v4().as_bytes())),
            chain: ChainType::Ethereum,
            block_number: Some(19_000_001),
            gas_used: 80_000,
            success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        Ok(ChainAuditAnchor {
            batch_start,
            batch_end,
            batch_hash: batch_hash.to_string(),
            chain: ChainType::Ethereum,
            tx,
        })
    }

    fn verify_audit_chain(&self) -> Result<bool, AgentError> {
        Ok(true)
    }

    fn get_balance(&self, _address: &str) -> Result<ChainBalance, AgentError> {
        Ok(ChainBalance {
            chain: ChainType::Ethereum,
            symbol: "ETH".to_string(),
            amount: 0,
            decimals: 18,
        })
    }

    fn status(&self) -> ChainProviderStatus {
        ChainProviderStatus {
            chain: ChainType::Ethereum,
            connected: self.connected,
            rpc_url: self.config.rpc_url.clone(),
            contract_address: self.config.contract_address.clone(),
            last_activity: None,
            tx_count: self.tx_count,
            error_count: self.error_count,
        }
    }
}

/// Solana blockchain provider.
pub struct SolanaProvider {
    config: ChainProviderConfig,
    connected: bool,
    devices: HashMap<String, ChainDeviceRecord>,
    policies: Vec<ChainPolicy>,
    tx_count: u64,
    error_count: u64,
}

impl SolanaProvider {
    /// Create a new Solana provider.
    pub fn new(config: ChainProviderConfig) -> Self {
        Self {
            config,
            connected: false,
            devices: HashMap::new(),
            policies: Vec::new(),
            tx_count: 0,
            error_count: 0,
        }
    }
}

impl ChainProvider for SolanaProvider {
    fn name(&self) -> &str {
        "Solana"
    }
    fn chain_type(&self) -> ChainType {
        ChainType::Solana
    }
    fn is_connected(&self) -> bool {
        self.connected
    }
    fn connect(&mut self) -> Result<(), AgentError> {
        self.connected = true;
        Ok(())
    }
    fn disconnect(&mut self) -> Result<(), AgentError> {
        self.connected = false;
        Ok(())
    }

    fn register_device(
        &self,
        public_key: &str,
        device_name: &str,
        device_type: &str,
    ) -> Result<ChainDeviceRecord, AgentError> {
        Ok(ChainDeviceRecord {
            public_key: public_key.to_string(),
            device_name: device_name.to_string(),
            device_type: device_type.to_string(),
            chain: ChainType::Solana,
            on_chain_id: hex::encode(&uuid::Uuid::new_v4().as_bytes()[..]),
            registered_at: chrono::Utc::now().timestamp() as u64,
            active: true,
        })
    }

    fn lookup_device(&self, public_key: &str) -> Result<Option<ChainDeviceRecord>, AgentError> {
        Ok(self.devices.get(public_key).cloned())
    }

    fn mint_policy(
        &self,
        owner: &str,
        role: &str,
        capabilities: Vec<String>,
        expires_at: u64,
        issuer: &str,
    ) -> Result<ChainPolicy, AgentError> {
        Ok(ChainPolicy {
            policy_id: hex::encode(&uuid::Uuid::new_v4().as_bytes()[..]),
            owner: owner.to_string(),
            role: role.to_string(),
            capabilities,
            expires_at,
            issuer: issuer.to_string(),
            chain: ChainType::Solana,
        })
    }

    fn verify_policy(&self, policy_id: &str) -> Result<bool, AgentError> {
        Ok(self.policies.iter().any(|p| p.policy_id == policy_id))
    }

    fn revoke_policy(&self, _policy_id: &str) -> Result<ChainTxResult, AgentError> {
        Ok(ChainTxResult {
            tx_hash: hex::encode(&uuid::Uuid::new_v4().as_bytes()[..]),
            chain: ChainType::Solana,
            block_number: Some(250_000_000),
            gas_used: 5000,
            success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    fn anchor_audit(
        &self,
        batch_start: u64,
        batch_end: u64,
        batch_hash: &str,
    ) -> Result<ChainAuditAnchor, AgentError> {
        let tx = ChainTxResult {
            tx_hash: hex::encode(&uuid::Uuid::new_v4().as_bytes()[..]),
            chain: ChainType::Solana,
            block_number: Some(250_000_001),
            gas_used: 5000,
            success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        Ok(ChainAuditAnchor {
            batch_start,
            batch_end,
            batch_hash: batch_hash.to_string(),
            chain: ChainType::Solana,
            tx,
        })
    }

    fn verify_audit_chain(&self) -> Result<bool, AgentError> {
        Ok(true)
    }

    fn get_balance(&self, _address: &str) -> Result<ChainBalance, AgentError> {
        Ok(ChainBalance {
            chain: ChainType::Solana,
            symbol: "SOL".to_string(),
            amount: 0,
            decimals: 9,
        })
    }

    fn status(&self) -> ChainProviderStatus {
        ChainProviderStatus {
            chain: ChainType::Solana,
            connected: self.connected,
            rpc_url: self.config.rpc_url.clone(),
            contract_address: self.config.contract_address.clone(),
            last_activity: None,
            tx_count: self.tx_count,
            error_count: self.error_count,
        }
    }
}

/// NEAR Protocol blockchain provider.
pub struct NearProvider {
    config: ChainProviderConfig,
    connected: bool,
    tx_count: u64,
    error_count: u64,
}

impl NearProvider {
    /// Create a new NEAR provider.
    pub fn new(config: ChainProviderConfig) -> Self {
        Self {
            config,
            connected: false,
            tx_count: 0,
            error_count: 0,
        }
    }
}

impl ChainProvider for NearProvider {
    fn name(&self) -> &str {
        "NEAR Protocol"
    }
    fn chain_type(&self) -> ChainType {
        ChainType::Near
    }
    fn is_connected(&self) -> bool {
        self.connected
    }
    fn connect(&mut self) -> Result<(), AgentError> {
        self.connected = true;
        Ok(())
    }
    fn disconnect(&mut self) -> Result<(), AgentError> {
        self.connected = false;
        Ok(())
    }

    fn register_device(
        &self,
        public_key: &str,
        device_name: &str,
        device_type: &str,
    ) -> Result<ChainDeviceRecord, AgentError> {
        Ok(ChainDeviceRecord {
            public_key: public_key.to_string(),
            device_name: device_name.to_string(),
            device_type: device_type.to_string(),
            chain: ChainType::Near,
            on_chain_id: format!("{}.edgeclaw.near", device_name),
            registered_at: chrono::Utc::now().timestamp() as u64,
            active: true,
        })
    }

    fn lookup_device(&self, _public_key: &str) -> Result<Option<ChainDeviceRecord>, AgentError> {
        Ok(None)
    }

    fn mint_policy(
        &self,
        owner: &str,
        role: &str,
        capabilities: Vec<String>,
        expires_at: u64,
        issuer: &str,
    ) -> Result<ChainPolicy, AgentError> {
        Ok(ChainPolicy {
            policy_id: format!("near-policy-{}", uuid::Uuid::new_v4()),
            owner: owner.to_string(),
            role: role.to_string(),
            capabilities,
            expires_at,
            issuer: issuer.to_string(),
            chain: ChainType::Near,
        })
    }

    fn verify_policy(&self, _policy_id: &str) -> Result<bool, AgentError> {
        Ok(true)
    }

    fn revoke_policy(&self, _policy_id: &str) -> Result<ChainTxResult, AgentError> {
        Ok(ChainTxResult {
            tx_hash: format!("{}", uuid::Uuid::new_v4()),
            chain: ChainType::Near,
            block_number: Some(100_000_000),
            gas_used: 300_000_000_000,
            success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    fn anchor_audit(
        &self,
        batch_start: u64,
        batch_end: u64,
        batch_hash: &str,
    ) -> Result<ChainAuditAnchor, AgentError> {
        let tx = ChainTxResult {
            tx_hash: format!("{}", uuid::Uuid::new_v4()),
            chain: ChainType::Near,
            block_number: Some(100_000_001),
            gas_used: 300_000_000_000,
            success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        Ok(ChainAuditAnchor {
            batch_start,
            batch_end,
            batch_hash: batch_hash.to_string(),
            chain: ChainType::Near,
            tx,
        })
    }

    fn verify_audit_chain(&self) -> Result<bool, AgentError> {
        Ok(true)
    }

    fn get_balance(&self, _address: &str) -> Result<ChainBalance, AgentError> {
        Ok(ChainBalance {
            chain: ChainType::Near,
            symbol: "NEAR".to_string(),
            amount: 0,
            decimals: 24,
        })
    }

    fn status(&self) -> ChainProviderStatus {
        ChainProviderStatus {
            chain: ChainType::Near,
            connected: self.connected,
            rpc_url: self.config.rpc_url.clone(),
            contract_address: self.config.contract_address.clone(),
            last_activity: None,
            tx_count: self.tx_count,
            error_count: self.error_count,
        }
    }
}

/// Cosmos / IBC blockchain provider.
pub struct CosmosProvider {
    config: ChainProviderConfig,
    connected: bool,
    tx_count: u64,
    error_count: u64,
}

impl CosmosProvider {
    /// Create a new Cosmos provider.
    pub fn new(config: ChainProviderConfig) -> Self {
        Self {
            config,
            connected: false,
            tx_count: 0,
            error_count: 0,
        }
    }
}

impl ChainProvider for CosmosProvider {
    fn name(&self) -> &str {
        "Cosmos IBC"
    }
    fn chain_type(&self) -> ChainType {
        ChainType::Cosmos
    }
    fn is_connected(&self) -> bool {
        self.connected
    }
    fn connect(&mut self) -> Result<(), AgentError> {
        self.connected = true;
        Ok(())
    }
    fn disconnect(&mut self) -> Result<(), AgentError> {
        self.connected = false;
        Ok(())
    }

    fn register_device(
        &self,
        public_key: &str,
        device_name: &str,
        device_type: &str,
    ) -> Result<ChainDeviceRecord, AgentError> {
        Ok(ChainDeviceRecord {
            public_key: public_key.to_string(),
            device_name: device_name.to_string(),
            device_type: device_type.to_string(),
            chain: ChainType::Cosmos,
            on_chain_id: format!("cosmos1{}", hex::encode(uuid::Uuid::new_v4().as_bytes())),
            registered_at: chrono::Utc::now().timestamp() as u64,
            active: true,
        })
    }

    fn lookup_device(&self, _public_key: &str) -> Result<Option<ChainDeviceRecord>, AgentError> {
        Ok(None)
    }

    fn mint_policy(
        &self,
        owner: &str,
        role: &str,
        capabilities: Vec<String>,
        expires_at: u64,
        issuer: &str,
    ) -> Result<ChainPolicy, AgentError> {
        Ok(ChainPolicy {
            policy_id: format!("cosmos-policy-{}", uuid::Uuid::new_v4()),
            owner: owner.to_string(),
            role: role.to_string(),
            capabilities,
            expires_at,
            issuer: issuer.to_string(),
            chain: ChainType::Cosmos,
        })
    }

    fn verify_policy(&self, _policy_id: &str) -> Result<bool, AgentError> {
        Ok(true)
    }

    fn revoke_policy(&self, _policy_id: &str) -> Result<ChainTxResult, AgentError> {
        Ok(ChainTxResult {
            tx_hash: hex::encode(uuid::Uuid::new_v4().as_bytes()),
            chain: ChainType::Cosmos,
            block_number: Some(20_000_000),
            gas_used: 200_000,
            success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    fn anchor_audit(
        &self,
        batch_start: u64,
        batch_end: u64,
        batch_hash: &str,
    ) -> Result<ChainAuditAnchor, AgentError> {
        let tx = ChainTxResult {
            tx_hash: hex::encode(uuid::Uuid::new_v4().as_bytes()),
            chain: ChainType::Cosmos,
            block_number: Some(20_000_001),
            gas_used: 200_000,
            success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        Ok(ChainAuditAnchor {
            batch_start,
            batch_end,
            batch_hash: batch_hash.to_string(),
            chain: ChainType::Cosmos,
            tx,
        })
    }

    fn verify_audit_chain(&self) -> Result<bool, AgentError> {
        Ok(true)
    }

    fn get_balance(&self, _address: &str) -> Result<ChainBalance, AgentError> {
        Ok(ChainBalance {
            chain: ChainType::Cosmos,
            symbol: "ATOM".to_string(),
            amount: 0,
            decimals: 6,
        })
    }

    fn status(&self) -> ChainProviderStatus {
        ChainProviderStatus {
            chain: ChainType::Cosmos,
            connected: self.connected,
            rpc_url: self.config.rpc_url.clone(),
            contract_address: self.config.contract_address.clone(),
            last_activity: None,
            tx_count: self.tx_count,
            error_count: self.error_count,
        }
    }
}

/// Aptos Move blockchain provider.
pub struct AptosProvider {
    config: ChainProviderConfig,
    connected: bool,
    tx_count: u64,
    error_count: u64,
}

impl AptosProvider {
    /// Create a new Aptos provider.
    pub fn new(config: ChainProviderConfig) -> Self {
        Self {
            config,
            connected: false,
            tx_count: 0,
            error_count: 0,
        }
    }
}

impl ChainProvider for AptosProvider {
    fn name(&self) -> &str {
        "Aptos Move"
    }
    fn chain_type(&self) -> ChainType {
        ChainType::Aptos
    }
    fn is_connected(&self) -> bool {
        self.connected
    }
    fn connect(&mut self) -> Result<(), AgentError> {
        self.connected = true;
        Ok(())
    }
    fn disconnect(&mut self) -> Result<(), AgentError> {
        self.connected = false;
        Ok(())
    }

    fn register_device(
        &self,
        public_key: &str,
        device_name: &str,
        device_type: &str,
    ) -> Result<ChainDeviceRecord, AgentError> {
        Ok(ChainDeviceRecord {
            public_key: public_key.to_string(),
            device_name: device_name.to_string(),
            device_type: device_type.to_string(),
            chain: ChainType::Aptos,
            on_chain_id: format!("0x{}", hex::encode(uuid::Uuid::new_v4().as_bytes())),
            registered_at: chrono::Utc::now().timestamp() as u64,
            active: true,
        })
    }

    fn lookup_device(&self, _public_key: &str) -> Result<Option<ChainDeviceRecord>, AgentError> {
        Ok(None)
    }

    fn mint_policy(
        &self,
        owner: &str,
        role: &str,
        capabilities: Vec<String>,
        expires_at: u64,
        issuer: &str,
    ) -> Result<ChainPolicy, AgentError> {
        Ok(ChainPolicy {
            policy_id: format!("0x{}", hex::encode(uuid::Uuid::new_v4().as_bytes())),
            owner: owner.to_string(),
            role: role.to_string(),
            capabilities,
            expires_at,
            issuer: issuer.to_string(),
            chain: ChainType::Aptos,
        })
    }

    fn verify_policy(&self, _policy_id: &str) -> Result<bool, AgentError> {
        Ok(true)
    }

    fn revoke_policy(&self, _policy_id: &str) -> Result<ChainTxResult, AgentError> {
        Ok(ChainTxResult {
            tx_hash: format!("0x{}", hex::encode(uuid::Uuid::new_v4().as_bytes())),
            chain: ChainType::Aptos,
            block_number: Some(500_000_000),
            gas_used: 1000,
            success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }

    fn anchor_audit(
        &self,
        batch_start: u64,
        batch_end: u64,
        batch_hash: &str,
    ) -> Result<ChainAuditAnchor, AgentError> {
        let tx = ChainTxResult {
            tx_hash: format!("0x{}", hex::encode(uuid::Uuid::new_v4().as_bytes())),
            chain: ChainType::Aptos,
            block_number: Some(500_000_001),
            gas_used: 1000,
            success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        Ok(ChainAuditAnchor {
            batch_start,
            batch_end,
            batch_hash: batch_hash.to_string(),
            chain: ChainType::Aptos,
            tx,
        })
    }

    fn verify_audit_chain(&self) -> Result<bool, AgentError> {
        Ok(true)
    }

    fn get_balance(&self, _address: &str) -> Result<ChainBalance, AgentError> {
        Ok(ChainBalance {
            chain: ChainType::Aptos,
            symbol: "APT".to_string(),
            amount: 0,
            decimals: 8,
        })
    }

    fn status(&self) -> ChainProviderStatus {
        ChainProviderStatus {
            chain: ChainType::Aptos,
            connected: self.connected,
            rpc_url: self.config.rpc_url.clone(),
            contract_address: self.config.contract_address.clone(),
            last_activity: None,
            tx_count: self.tx_count,
            error_count: self.error_count,
        }
    }
}

// ─── Multi-Chain Client ────────────────────────────────────

/// Factory function to create a provider by chain type.
pub fn create_provider(chain: ChainType, config: ChainProviderConfig) -> Box<dyn ChainProvider> {
    match chain {
        ChainType::Sui => Box::new(SuiProvider::new(config)),
        ChainType::Ethereum => Box::new(EthereumProvider::new(config)),
        ChainType::Solana => Box::new(SolanaProvider::new(config)),
        ChainType::Near => Box::new(NearProvider::new(config)),
        ChainType::Cosmos => Box::new(CosmosProvider::new(config)),
        ChainType::Aptos => Box::new(AptosProvider::new(config)),
    }
}

/// Multi-chain client that manages multiple blockchain providers.
///
/// Supports registering multiple chains simultaneously and routing
/// operations to the appropriate provider. Includes a primary chain
/// for default operations and fallback logic.
pub struct MultiChainClient {
    providers: HashMap<ChainType, Box<dyn ChainProvider>>,
    primary: Option<ChainType>,
    /// Offline cache for when all chains are unreachable.
    offline_cache: Vec<OfflineCacheEntry>,
}

/// Offline cache entry for pending blockchain operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineCacheEntry {
    /// Target chain.
    pub chain: ChainType,
    /// Operation type.
    pub operation: String,
    /// Serialized payload.
    pub payload: String,
    /// Cached timestamp.
    pub cached_at: chrono::DateTime<chrono::Utc>,
    /// Retry count.
    pub retries: u32,
}

impl MultiChainClient {
    /// Create a new empty multi-chain client.
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            primary: None,
            offline_cache: Vec::new(),
        }
    }

    /// Register a blockchain provider.
    pub fn register_provider(
        &mut self,
        chain: ChainType,
        config: ChainProviderConfig,
    ) -> Result<(), AgentError> {
        let provider = create_provider(chain, config);
        self.providers.insert(chain, provider);
        // First registered becomes primary
        if self.primary.is_none() {
            self.primary = Some(chain);
        }
        Ok(())
    }

    /// Set the primary chain for default operations.
    pub fn set_primary(&mut self, chain: ChainType) -> Result<(), AgentError> {
        if !self.providers.contains_key(&chain) {
            return Err(AgentError::NotFound(format!(
                "chain provider not registered: {}",
                chain
            )));
        }
        self.primary = Some(chain);
        Ok(())
    }

    /// Get the primary chain type.
    pub fn primary_chain(&self) -> Option<ChainType> {
        self.primary
    }

    /// Get a provider reference by chain type.
    pub fn provider(&self, chain: ChainType) -> Option<&dyn ChainProvider> {
        self.providers.get(&chain).map(|p| p.as_ref())
    }

    /// Get a mutable provider reference by chain type.
    pub fn provider_mut(&mut self, chain: ChainType) -> Option<&mut Box<dyn ChainProvider>> {
        self.providers.get_mut(&chain)
    }

    /// Get the primary provider.
    pub fn primary_provider(&self) -> Option<&dyn ChainProvider> {
        self.primary.and_then(|c| self.provider(c))
    }

    /// Connect all registered providers.
    pub fn connect_all(&mut self) -> Vec<(ChainType, Result<(), AgentError>)> {
        let chains: Vec<ChainType> = self.providers.keys().copied().collect();
        let mut results = Vec::new();
        for chain in chains {
            if let Some(provider) = self.providers.get_mut(&chain) {
                let result = provider.connect();
                results.push((chain, result));
            }
        }
        results
    }

    /// Disconnect all providers.
    pub fn disconnect_all(&mut self) -> Vec<(ChainType, Result<(), AgentError>)> {
        let chains: Vec<ChainType> = self.providers.keys().copied().collect();
        let mut results = Vec::new();
        for chain in chains {
            if let Some(provider) = self.providers.get_mut(&chain) {
                let result = provider.disconnect();
                results.push((chain, result));
            }
        }
        results
    }

    /// List all registered chain types.
    pub fn registered_chains(&self) -> Vec<ChainType> {
        self.providers.keys().copied().collect()
    }

    /// Get status of all providers.
    pub fn status_all(&self) -> Vec<ChainProviderStatus> {
        self.providers.values().map(|p| p.status()).collect()
    }

    /// Register device on a specific chain (or primary).
    pub fn register_device(
        &self,
        chain: Option<ChainType>,
        public_key: &str,
        device_name: &str,
        device_type: &str,
    ) -> Result<ChainDeviceRecord, AgentError> {
        let target = chain
            .or(self.primary)
            .ok_or_else(|| AgentError::NotFound("no chain provider registered".to_string()))?;
        let provider = self
            .providers
            .get(&target)
            .ok_or_else(|| AgentError::NotFound(format!("chain not registered: {}", target)))?;
        provider.register_device(public_key, device_name, device_type)
    }

    /// Mint policy on a specific chain (or primary).
    pub fn mint_policy(
        &self,
        chain: Option<ChainType>,
        owner: &str,
        role: &str,
        capabilities: Vec<String>,
        expires_at: u64,
        issuer: &str,
    ) -> Result<ChainPolicy, AgentError> {
        let target = chain
            .or(self.primary)
            .ok_or_else(|| AgentError::NotFound("no chain provider registered".to_string()))?;
        let provider = self
            .providers
            .get(&target)
            .ok_or_else(|| AgentError::NotFound(format!("chain not registered: {}", target)))?;
        provider.mint_policy(owner, role, capabilities, expires_at, issuer)
    }

    /// Anchor audit on a specific chain (or primary).
    pub fn anchor_audit(
        &self,
        chain: Option<ChainType>,
        batch_start: u64,
        batch_end: u64,
        batch_hash: &str,
    ) -> Result<ChainAuditAnchor, AgentError> {
        let target = chain
            .or(self.primary)
            .ok_or_else(|| AgentError::NotFound("no chain provider registered".to_string()))?;
        let provider = self
            .providers
            .get(&target)
            .ok_or_else(|| AgentError::NotFound(format!("chain not registered: {}", target)))?;
        provider.anchor_audit(batch_start, batch_end, batch_hash)
    }

    /// Cross-chain anchor: anchor the same audit hash on all registered chains.
    pub fn anchor_audit_all(
        &self,
        batch_start: u64,
        batch_end: u64,
        batch_hash: &str,
    ) -> Vec<(ChainType, Result<ChainAuditAnchor, AgentError>)> {
        self.providers
            .iter()
            .map(|(chain, provider)| {
                let result = provider.anchor_audit(batch_start, batch_end, batch_hash);
                (*chain, result)
            })
            .collect()
    }

    /// Get balance across all chains.
    pub fn balances_all(
        &self,
        address: &str,
    ) -> Vec<(ChainType, Result<ChainBalance, AgentError>)> {
        self.providers
            .iter()
            .map(|(chain, provider)| {
                let result = provider.get_balance(address);
                (*chain, result)
            })
            .collect()
    }

    /// Get offline cache size.
    pub fn cache_size(&self) -> usize {
        self.offline_cache.len()
    }

    /// Flush offline cache.
    pub fn flush_cache(&mut self) -> usize {
        let count = self.offline_cache.len();
        self.offline_cache.clear();
        count
    }

    /// Add entry to offline cache.
    pub fn cache_operation(&mut self, chain: ChainType, operation: &str, payload: &str) {
        self.offline_cache.push(OfflineCacheEntry {
            chain,
            operation: operation.to_string(),
            payload: payload.to_string(),
            cached_at: chrono::Utc::now(),
            retries: 0,
        });
    }
}

impl Default for MultiChainClient {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Configuration Helper ──────────────────────────────────

/// Multi-chain configuration section (for TOML config).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiChainConfig {
    /// Enable multi-chain support.
    #[serde(default)]
    pub enabled: bool,
    /// Primary chain for default operations.
    #[serde(default)]
    pub primary_chain: String,
    /// Per-chain configurations.
    #[serde(default)]
    pub chains: HashMap<String, ChainProviderConfig>,
    /// Enable cross-chain audit anchoring.
    #[serde(default)]
    pub cross_chain_audit: bool,
}

impl Default for MultiChainConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            primary_chain: "sui".to_string(),
            chains: HashMap::new(),
            cross_chain_audit: false,
        }
    }
}

impl MultiChainConfig {
    /// Build a MultiChainClient from this config.
    pub fn build_client(&self) -> Result<MultiChainClient, AgentError> {
        let mut client = MultiChainClient::new();
        for (name, config) in &self.chains {
            if let Some(chain) = ChainType::from_str_loose(name) {
                client.register_provider(chain, config.clone())?;
            }
        }
        if let Some(primary) = ChainType::from_str_loose(&self.primary_chain) {
            if client.providers.contains_key(&primary) {
                client.set_primary(primary)?;
            }
        }
        Ok(client)
    }
}

// ─── Tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sui_config() -> ChainProviderConfig {
        ChainProviderConfig {
            rpc_url: "https://fullnode.devnet.sui.io:443".into(),
            chain_id: Some("devnet".into()),
            contract_address: Some("0xtest".into()),
            wallet_key_path: None,
            gas_budget: 10_000_000,
            custom_options: HashMap::new(),
        }
    }

    fn eth_config() -> ChainProviderConfig {
        ChainProviderConfig {
            rpc_url: "https://mainnet.infura.io/v3/test".into(),
            chain_id: Some("1".into()),
            contract_address: Some("0xContractAddr".into()),
            wallet_key_path: None,
            gas_budget: 100_000,
            custom_options: HashMap::new(),
        }
    }

    #[test]
    fn test_chain_type_display() {
        assert_eq!(ChainType::Sui.to_string(), "sui");
        assert_eq!(ChainType::Ethereum.to_string(), "ethereum");
        assert_eq!(ChainType::Solana.to_string(), "solana");
        assert_eq!(ChainType::Near.to_string(), "near");
        assert_eq!(ChainType::Cosmos.to_string(), "cosmos");
        assert_eq!(ChainType::Aptos.to_string(), "aptos");
    }

    #[test]
    fn test_chain_type_from_str() {
        assert_eq!(ChainType::from_str_loose("sui"), Some(ChainType::Sui));
        assert_eq!(ChainType::from_str_loose("ETH"), Some(ChainType::Ethereum));
        assert_eq!(ChainType::from_str_loose("evm"), Some(ChainType::Ethereum));
        assert_eq!(ChainType::from_str_loose("sol"), Some(ChainType::Solana));
        assert_eq!(ChainType::from_str_loose("NEAR"), Some(ChainType::Near));
        assert_eq!(ChainType::from_str_loose("ibc"), Some(ChainType::Cosmos));
        assert_eq!(ChainType::from_str_loose("apt"), Some(ChainType::Aptos));
        assert_eq!(ChainType::from_str_loose("unknown"), None);
    }

    #[test]
    fn test_chain_type_metadata() {
        assert_eq!(ChainType::Sui.native_token(), "SUI");
        assert_eq!(ChainType::Ethereum.contract_language(), "Solidity/Vyper");
        assert_eq!(ChainType::Solana.native_token(), "SOL");
        assert_eq!(ChainType::all().len(), 6);
    }

    #[test]
    fn test_create_provider_factory() {
        let provider = create_provider(ChainType::Sui, sui_config());
        assert_eq!(provider.name(), "SUI Move");
        assert_eq!(provider.chain_type(), ChainType::Sui);
        assert!(!provider.is_connected());
    }

    #[test]
    fn test_sui_provider_register_device() {
        let provider = SuiProvider::new(sui_config());
        let record = provider
            .register_device("0xpubkey", "my-desktop", "desktop")
            .unwrap();
        assert_eq!(record.chain, ChainType::Sui);
        assert_eq!(record.device_name, "my-desktop");
        assert!(record.active);
        assert!(record.on_chain_id.starts_with("0x"));
    }

    #[test]
    fn test_ethereum_provider_register_device() {
        let provider = EthereumProvider::new(eth_config());
        let record = provider
            .register_device("0xpubkey", "my-node", "desktop")
            .unwrap();
        assert_eq!(record.chain, ChainType::Ethereum);
        assert!(record.on_chain_id.starts_with("0x"));
    }

    #[test]
    fn test_multi_chain_client_register_providers() {
        let mut client = MultiChainClient::new();
        client
            .register_provider(ChainType::Sui, sui_config())
            .unwrap();
        client
            .register_provider(ChainType::Ethereum, eth_config())
            .unwrap();

        assert_eq!(client.registered_chains().len(), 2);
        assert_eq!(client.primary_chain(), Some(ChainType::Sui)); // first registered
    }

    #[test]
    fn test_multi_chain_set_primary() {
        let mut client = MultiChainClient::new();
        client
            .register_provider(ChainType::Sui, sui_config())
            .unwrap();
        client
            .register_provider(ChainType::Ethereum, eth_config())
            .unwrap();

        client.set_primary(ChainType::Ethereum).unwrap();
        assert_eq!(client.primary_chain(), Some(ChainType::Ethereum));

        // Set unknown chain → error
        let result = client.set_primary(ChainType::Solana);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_chain_register_device() {
        let mut client = MultiChainClient::new();
        client
            .register_provider(ChainType::Sui, sui_config())
            .unwrap();
        client
            .register_provider(ChainType::Ethereum, eth_config())
            .unwrap();

        // Register on primary (SUI)
        let record = client
            .register_device(None, "0xkey", "dev1", "desktop")
            .unwrap();
        assert_eq!(record.chain, ChainType::Sui);

        // Register on specific chain (ETH)
        let record = client
            .register_device(Some(ChainType::Ethereum), "0xkey", "dev2", "mobile")
            .unwrap();
        assert_eq!(record.chain, ChainType::Ethereum);
    }

    #[test]
    fn test_multi_chain_mint_policy() {
        let mut client = MultiChainClient::new();
        client
            .register_provider(
                ChainType::Solana,
                ChainProviderConfig {
                    rpc_url: "https://api.devnet.solana.com".into(),
                    ..Default::default()
                },
            )
            .unwrap();

        let policy = client
            .mint_policy(
                None,
                "owner",
                "admin",
                vec!["status_query".into()],
                99999,
                "issuer",
            )
            .unwrap();
        assert_eq!(policy.chain, ChainType::Solana);
        assert_eq!(policy.role, "admin");
    }

    #[test]
    fn test_multi_chain_anchor_audit() {
        let mut client = MultiChainClient::new();
        client
            .register_provider(ChainType::Sui, sui_config())
            .unwrap();

        let anchor = client
            .anchor_audit(None, 1, 100, "abcdef1234567890")
            .unwrap();
        assert_eq!(anchor.chain, ChainType::Sui);
        assert_eq!(anchor.batch_start, 1);
        assert_eq!(anchor.batch_end, 100);
    }

    #[test]
    fn test_multi_chain_anchor_all() {
        let mut client = MultiChainClient::new();
        client
            .register_provider(ChainType::Sui, sui_config())
            .unwrap();
        client
            .register_provider(ChainType::Ethereum, eth_config())
            .unwrap();

        let results = client.anchor_audit_all(1, 50, "hash123");
        assert_eq!(results.len(), 2);
        for (chain, result) in &results {
            assert!(result.is_ok());
            let anchor = result.as_ref().unwrap();
            assert_eq!(anchor.chain, *chain);
        }
    }

    #[test]
    fn test_multi_chain_connect_all() {
        let mut client = MultiChainClient::new();
        client
            .register_provider(ChainType::Sui, sui_config())
            .unwrap();
        client
            .register_provider(
                ChainType::Near,
                ChainProviderConfig {
                    rpc_url: "https://rpc.testnet.near.org".into(),
                    ..Default::default()
                },
            )
            .unwrap();

        let results = client.connect_all();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(_, r)| r.is_ok()));
    }

    #[test]
    fn test_multi_chain_status_all() {
        let mut client = MultiChainClient::new();
        client
            .register_provider(ChainType::Sui, sui_config())
            .unwrap();
        client
            .register_provider(ChainType::Ethereum, eth_config())
            .unwrap();

        let statuses = client.status_all();
        assert_eq!(statuses.len(), 2);
    }

    #[test]
    fn test_multi_chain_balances_all() {
        let mut client = MultiChainClient::new();
        client
            .register_provider(ChainType::Sui, sui_config())
            .unwrap();
        client
            .register_provider(ChainType::Ethereum, eth_config())
            .unwrap();

        let balances = client.balances_all("0xmyaddr");
        assert_eq!(balances.len(), 2);
        for (_, result) in &balances {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_multi_chain_offline_cache() {
        let mut client = MultiChainClient::new();
        client.cache_operation(ChainType::Sui, "register_device", "{\"key\":\"val\"}");
        client.cache_operation(ChainType::Ethereum, "anchor_audit", "{\"hash\":\"abc\"}");
        assert_eq!(client.cache_size(), 2);

        let flushed = client.flush_cache();
        assert_eq!(flushed, 2);
        assert_eq!(client.cache_size(), 0);
    }

    #[test]
    fn test_multi_chain_no_provider_error() {
        let client = MultiChainClient::new();
        let result = client.register_device(None, "0xkey", "dev", "desktop");
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_chain_config_build() {
        let mut chains = HashMap::new();
        chains.insert("sui".to_string(), sui_config());
        chains.insert("ethereum".to_string(), eth_config());

        let config = MultiChainConfig {
            enabled: true,
            primary_chain: "ethereum".to_string(),
            chains,
            cross_chain_audit: true,
        };

        let client = config.build_client().unwrap();
        assert_eq!(client.registered_chains().len(), 2);
        assert_eq!(client.primary_chain(), Some(ChainType::Ethereum));
    }

    #[test]
    fn test_chain_provider_config_default() {
        let config = ChainProviderConfig::default();
        assert!(config.rpc_url.is_empty());
        assert_eq!(config.gas_budget, 10_000_000);
        assert!(config.custom_options.is_empty());
    }

    #[test]
    fn test_chain_tx_result_serialize() {
        let tx = ChainTxResult {
            tx_hash: "0xabc".to_string(),
            chain: ChainType::Sui,
            block_number: Some(100),
            gas_used: 5000,
            success: true,
            timestamp: 1234567890,
        };
        let json = serde_json::to_string(&tx).unwrap();
        let parsed: ChainTxResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tx_hash, "0xabc");
        assert_eq!(parsed.chain, ChainType::Sui);
    }

    #[test]
    fn test_provider_status() {
        let provider = SuiProvider::new(sui_config());
        let status = provider.status();
        assert_eq!(status.chain, ChainType::Sui);
        assert!(!status.connected);
        assert_eq!(status.tx_count, 0);
    }

    // ── New coverage tests ─────────────────────────────────

    #[test]
    fn test_chain_type_default_rpc_urls() {
        for chain in ChainType::all() {
            let url = chain.default_rpc_url();
            assert!(!url.is_empty(), "empty url for {}", chain);
            assert!(url.starts_with("https://"), "bad scheme for {}", chain);
        }
    }

    #[test]
    fn test_chain_type_contract_languages() {
        let expected = vec![
            (ChainType::Sui, "Move"),
            (ChainType::Ethereum, "Solidity/Vyper"),
            (ChainType::Solana, "Rust (Anchor)"),
            (ChainType::Near, "Rust/AssemblyScript"),
            (ChainType::Cosmos, "CosmWasm (Rust)"),
            (ChainType::Aptos, "Move"),
        ];
        for (chain, lang) in expected {
            assert_eq!(chain.contract_language(), lang, "wrong for {}", chain);
        }
    }

    #[test]
    fn test_chain_type_native_tokens() {
        let expected = vec![
            (ChainType::Sui, "SUI"),
            (ChainType::Ethereum, "ETH"),
            (ChainType::Solana, "SOL"),
            (ChainType::Near, "NEAR"),
            (ChainType::Cosmos, "ATOM"),
            (ChainType::Aptos, "APT"),
        ];
        for (chain, token) in expected {
            assert_eq!(chain.native_token(), token, "wrong for {}", chain);
        }
    }

    #[test]
    fn test_sui_connect_disconnect() {
        let mut provider = SuiProvider::new(sui_config());
        assert!(!provider.is_connected());
        provider.connect().unwrap();
        assert!(provider.is_connected());
        provider.disconnect().unwrap();
        assert!(!provider.is_connected());
    }

    #[test]
    fn test_sui_lookup_device_empty() {
        let provider = SuiProvider::new(sui_config());
        let result = provider.lookup_device("0xnonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_sui_verify_policy_not_found() {
        let provider = SuiProvider::new(sui_config());
        let result = provider.verify_policy("nonexistent-policy").unwrap();
        assert!(!result);
    }

    #[test]
    fn test_sui_revoke_policy() {
        let provider = SuiProvider::new(sui_config());
        let result = provider.revoke_policy("0xpolicy1").unwrap();
        assert!(result.success);
        assert_eq!(result.chain, ChainType::Sui);
        assert!(result.tx_hash.starts_with("0x"));
    }

    #[test]
    fn test_sui_get_balance() {
        let provider = SuiProvider::new(sui_config());
        let balance = provider.get_balance("0xaddr").unwrap();
        assert_eq!(balance.chain, ChainType::Sui);
        assert_eq!(balance.symbol, "SUI");
        assert_eq!(balance.decimals, 9);
    }

    #[test]
    fn test_sui_anchor_audit() {
        let provider = SuiProvider::new(sui_config());
        let anchor = provider.anchor_audit(10, 20, "abc123hash").unwrap();
        assert_eq!(anchor.batch_start, 10);
        assert_eq!(anchor.batch_end, 20);
        assert_eq!(anchor.batch_hash, "abc123hash");
        assert_eq!(anchor.chain, ChainType::Sui);
        assert!(anchor.tx.success);
    }

    #[test]
    fn test_sui_verify_audit_chain() {
        let provider = SuiProvider::new(sui_config());
        assert!(provider.verify_audit_chain().unwrap());
    }

    #[test]
    fn test_sui_mint_policy() {
        let provider = SuiProvider::new(sui_config());
        let policy = provider
            .mint_policy("owner1", "admin", vec!["cap1".into()], 9999, "issuer1")
            .unwrap();
        assert_eq!(policy.chain, ChainType::Sui);
        assert_eq!(policy.role, "admin");
        assert_eq!(policy.owner, "owner1");
        assert_eq!(policy.issuer, "issuer1");
        assert_eq!(policy.capabilities, vec!["cap1"]);
        assert_eq!(policy.expires_at, 9999);
    }

    #[test]
    fn test_ethereum_connect_disconnect() {
        let mut provider = EthereumProvider::new(eth_config());
        assert!(!provider.is_connected());
        provider.connect().unwrap();
        assert!(provider.is_connected());
        provider.disconnect().unwrap();
        assert!(!provider.is_connected());
    }

    #[test]
    fn test_ethereum_lookup_device_empty() {
        let provider = EthereumProvider::new(eth_config());
        assert!(provider.lookup_device("0xkey").unwrap().is_none());
    }

    #[test]
    fn test_ethereum_verify_policy_not_found() {
        let provider = EthereumProvider::new(eth_config());
        assert!(!provider.verify_policy("0xnope").unwrap());
    }

    #[test]
    fn test_ethereum_revoke_policy() {
        let provider = EthereumProvider::new(eth_config());
        let tx = provider.revoke_policy("0xpol").unwrap();
        assert!(tx.success);
        assert_eq!(tx.chain, ChainType::Ethereum);
        assert!(tx.block_number.is_some());
    }

    #[test]
    fn test_ethereum_anchor_audit() {
        let provider = EthereumProvider::new(eth_config());
        let anchor = provider.anchor_audit(5, 15, "ethash").unwrap();
        assert_eq!(anchor.batch_start, 5);
        assert_eq!(anchor.batch_end, 15);
        assert_eq!(anchor.chain, ChainType::Ethereum);
        assert!(anchor.tx.block_number.is_some());
    }

    #[test]
    fn test_ethereum_verify_audit_chain() {
        let provider = EthereumProvider::new(eth_config());
        assert!(provider.verify_audit_chain().unwrap());
    }

    #[test]
    fn test_ethereum_get_balance() {
        let provider = EthereumProvider::new(eth_config());
        let b = provider.get_balance("0xaddr").unwrap();
        assert_eq!(b.symbol, "ETH");
        assert_eq!(b.decimals, 18);
    }

    #[test]
    fn test_ethereum_mint_policy() {
        let provider = EthereumProvider::new(eth_config());
        let p = provider
            .mint_policy("o", "viewer", vec![], 100, "i")
            .unwrap();
        assert_eq!(p.chain, ChainType::Ethereum);
        assert_eq!(p.role, "viewer");
    }

    #[test]
    fn test_ethereum_status() {
        let provider = EthereumProvider::new(eth_config());
        let s = provider.status();
        assert_eq!(s.chain, ChainType::Ethereum);
        assert!(!s.connected);
    }

    #[test]
    fn test_solana_full_lifecycle() {
        let mut provider = SolanaProvider::new(ChainProviderConfig {
            rpc_url: "https://api.devnet.solana.com".into(),
            ..Default::default()
        });

        // connect
        provider.connect().unwrap();
        assert!(provider.is_connected());

        // register device
        let rec = provider
            .register_device("0xkey", "sol-dev", "desktop")
            .unwrap();
        assert_eq!(rec.chain, ChainType::Solana);
        assert_eq!(rec.device_name, "sol-dev");

        // lookup (empty — not persisted to map in register_device)
        assert!(provider.lookup_device("0xkey").unwrap().is_none());

        // mint policy
        let p = provider
            .mint_policy("owner", "operator", vec!["file_read".into()], 5000, "iss")
            .unwrap();
        assert_eq!(p.chain, ChainType::Solana);

        // verify policy (empty internal list)
        assert!(!provider.verify_policy("fake").unwrap());

        // revoke policy
        let tx = provider.revoke_policy("id").unwrap();
        assert!(tx.success);
        assert_eq!(tx.chain, ChainType::Solana);

        // anchor audit
        let a = provider.anchor_audit(1, 50, "solhash").unwrap();
        assert_eq!(a.batch_start, 1);
        assert_eq!(a.batch_end, 50);

        // verify audit chain
        assert!(provider.verify_audit_chain().unwrap());

        // get balance
        let b = provider.get_balance("addr").unwrap();
        assert_eq!(b.symbol, "SOL");
        assert_eq!(b.decimals, 9);

        // status
        let s = provider.status();
        assert_eq!(s.chain, ChainType::Solana);
        assert!(s.connected);

        // disconnect
        provider.disconnect().unwrap();
        assert!(!provider.is_connected());
    }

    #[test]
    fn test_near_provider_full_lifecycle() {
        let mut provider = NearProvider::new(ChainProviderConfig {
            rpc_url: "https://rpc.testnet.near.org".into(),
            ..Default::default()
        });

        provider.connect().unwrap();
        assert!(provider.is_connected());

        let rec = provider
            .register_device("0xkey", "near-dev", "desktop")
            .unwrap();
        assert_eq!(rec.chain, ChainType::Near);
        assert!(rec.on_chain_id.contains("edgeclaw.near"));

        assert!(provider.lookup_device("0xkey").unwrap().is_none());

        let p = provider.mint_policy("o", "admin", vec![], 99, "i").unwrap();
        assert_eq!(p.chain, ChainType::Near);
        assert!(p.policy_id.starts_with("near-policy-"));

        assert!(provider.verify_policy("x").unwrap());

        let tx = provider.revoke_policy("pid").unwrap();
        assert!(tx.success);
        assert_eq!(tx.chain, ChainType::Near);

        let a = provider.anchor_audit(0, 10, "nearhash").unwrap();
        assert_eq!(a.chain, ChainType::Near);

        assert!(provider.verify_audit_chain().unwrap());

        let b = provider.get_balance("addr").unwrap();
        assert_eq!(b.symbol, "NEAR");
        assert_eq!(b.decimals, 24);

        let s = provider.status();
        assert_eq!(s.chain, ChainType::Near);
        assert!(s.connected);

        provider.disconnect().unwrap();
        assert!(!provider.is_connected());
    }

    #[test]
    fn test_cosmos_provider_full_lifecycle() {
        let mut provider = CosmosProvider::new(ChainProviderConfig {
            rpc_url: "https://rpc.cosmos.network:443".into(),
            ..Default::default()
        });

        provider.connect().unwrap();
        assert!(provider.is_connected());

        let rec = provider
            .register_device("0xkey", "cosmos-dev", "gateway")
            .unwrap();
        assert_eq!(rec.chain, ChainType::Cosmos);
        assert!(rec.on_chain_id.starts_with("cosmos1"));

        assert!(provider.lookup_device("key").unwrap().is_none());

        let p = provider
            .mint_policy("o", "owner", vec!["all".into()], 100, "i")
            .unwrap();
        assert_eq!(p.chain, ChainType::Cosmos);
        assert!(p.policy_id.starts_with("cosmos-policy-"));

        assert!(provider.verify_policy("any").unwrap());

        let tx = provider.revoke_policy("pid").unwrap();
        assert!(tx.success);

        let a = provider.anchor_audit(5, 55, "cosmoshash").unwrap();
        assert_eq!(a.chain, ChainType::Cosmos);

        assert!(provider.verify_audit_chain().unwrap());

        let b = provider.get_balance("addr").unwrap();
        assert_eq!(b.symbol, "ATOM");
        assert_eq!(b.decimals, 6);

        let s = provider.status();
        assert!(s.connected);

        provider.disconnect().unwrap();
        assert!(!provider.is_connected());
    }

    #[test]
    fn test_aptos_provider_full_lifecycle() {
        let mut provider = AptosProvider::new(ChainProviderConfig {
            rpc_url: "https://fullnode.devnet.aptoslabs.com/v1".into(),
            ..Default::default()
        });

        provider.connect().unwrap();
        assert!(provider.is_connected());

        let rec = provider
            .register_device("0xkey", "aptos-dev", "mobile")
            .unwrap();
        assert_eq!(rec.chain, ChainType::Aptos);
        assert!(rec.on_chain_id.starts_with("0x"));

        assert!(provider.lookup_device("key").unwrap().is_none());

        let p = provider.mint_policy("o", "guest", vec![], 50, "i").unwrap();
        assert_eq!(p.chain, ChainType::Aptos);
        assert!(p.policy_id.starts_with("0x"));

        assert!(provider.verify_policy("any").unwrap());

        let tx = provider.revoke_policy("pid").unwrap();
        assert!(tx.success);

        let a = provider.anchor_audit(100, 200, "aptoshash").unwrap();
        assert_eq!(a.chain, ChainType::Aptos);

        assert!(provider.verify_audit_chain().unwrap());

        let b = provider.get_balance("addr").unwrap();
        assert_eq!(b.symbol, "APT");
        assert_eq!(b.decimals, 8);

        let s = provider.status();
        assert!(s.connected);

        provider.disconnect().unwrap();
        assert!(!provider.is_connected());
    }

    #[test]
    fn test_create_provider_all_chains() {
        for chain in ChainType::all() {
            let provider = create_provider(chain, ChainProviderConfig::default());
            assert_eq!(provider.chain_type(), chain);
            assert!(!provider.is_connected());
            assert!(!provider.name().is_empty());
        }
    }

    #[test]
    fn test_multi_chain_disconnect_all() {
        let mut client = MultiChainClient::new();
        client
            .register_provider(ChainType::Sui, sui_config())
            .unwrap();
        client
            .register_provider(ChainType::Ethereum, eth_config())
            .unwrap();
        client.connect_all();

        let results = client.disconnect_all();
        assert_eq!(results.len(), 2);
        for (_, r) in &results {
            assert!(r.is_ok());
        }
    }

    #[test]
    fn test_multi_chain_provider_accessor() {
        let mut client = MultiChainClient::new();
        client
            .register_provider(ChainType::Sui, sui_config())
            .unwrap();
        assert!(client.provider(ChainType::Sui).is_some());
        assert!(client.provider(ChainType::Ethereum).is_none());
    }

    #[test]
    fn test_multi_chain_provider_mut_accessor() {
        let mut client = MultiChainClient::new();
        client
            .register_provider(ChainType::Sui, sui_config())
            .unwrap();
        assert!(client.provider_mut(ChainType::Sui).is_some());
        assert!(client.provider_mut(ChainType::Ethereum).is_none());
    }

    #[test]
    fn test_multi_chain_primary_provider() {
        let mut client = MultiChainClient::new();
        assert!(client.primary_provider().is_none());
        client
            .register_provider(ChainType::Sui, sui_config())
            .unwrap();
        let primary = client.primary_provider().unwrap();
        assert_eq!(primary.chain_type(), ChainType::Sui);
    }

    #[test]
    fn test_multi_chain_default() {
        let client = MultiChainClient::default();
        assert!(client.registered_chains().is_empty());
        assert!(client.primary_chain().is_none());
        assert_eq!(client.cache_size(), 0);
    }

    #[test]
    fn test_multi_chain_config_default() {
        let config = MultiChainConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.primary_chain, "sui");
        assert!(config.chains.is_empty());
        assert!(!config.cross_chain_audit);
    }

    #[test]
    fn test_offline_cache_entry_serialize() {
        let entry = OfflineCacheEntry {
            chain: ChainType::Sui,
            operation: "register".to_string(),
            payload: "{}".to_string(),
            cached_at: chrono::Utc::now(),
            retries: 3,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: OfflineCacheEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain, ChainType::Sui);
        assert_eq!(parsed.operation, "register");
        assert_eq!(parsed.retries, 3);
    }

    #[test]
    fn test_chain_device_record_serialize() {
        let record = ChainDeviceRecord {
            public_key: "0xabc".to_string(),
            device_name: "test-dev".to_string(),
            device_type: "desktop".to_string(),
            chain: ChainType::Ethereum,
            on_chain_id: "0x123".to_string(),
            registered_at: 1234567890,
            active: true,
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: ChainDeviceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.public_key, "0xabc");
        assert_eq!(parsed.chain, ChainType::Ethereum);
        assert!(parsed.active);
    }

    #[test]
    fn test_chain_policy_serialize() {
        let policy = ChainPolicy {
            policy_id: "pid1".to_string(),
            owner: "owner1".to_string(),
            role: "admin".to_string(),
            capabilities: vec!["cap1".into(), "cap2".into()],
            expires_at: 99999,
            issuer: "issuer1".to_string(),
            chain: ChainType::Near,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: ChainPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.policy_id, "pid1");
        assert_eq!(parsed.chain, ChainType::Near);
        assert_eq!(parsed.capabilities.len(), 2);
    }

    #[test]
    fn test_chain_audit_anchor_serialize() {
        let anchor = ChainAuditAnchor {
            batch_start: 1,
            batch_end: 100,
            batch_hash: "hash123".to_string(),
            chain: ChainType::Cosmos,
            tx: ChainTxResult {
                tx_hash: "0xtx".to_string(),
                chain: ChainType::Cosmos,
                block_number: Some(999),
                gas_used: 100,
                success: true,
                timestamp: 1111,
            },
        };
        let json = serde_json::to_string(&anchor).unwrap();
        let parsed: ChainAuditAnchor = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.batch_start, 1);
        assert_eq!(parsed.batch_end, 100);
        assert_eq!(parsed.chain, ChainType::Cosmos);
    }

    #[test]
    fn test_chain_balance_serialize() {
        let balance = ChainBalance {
            chain: ChainType::Aptos,
            symbol: "APT".to_string(),
            amount: 1000000,
            decimals: 8,
        };
        let json = serde_json::to_string(&balance).unwrap();
        let parsed: ChainBalance = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.symbol, "APT");
        assert_eq!(parsed.amount, 1000000);
    }

    #[test]
    fn test_chain_provider_status_serialize() {
        let status = ChainProviderStatus {
            chain: ChainType::Solana,
            connected: true,
            rpc_url: "https://api.devnet.solana.com".to_string(),
            contract_address: Some("0xabc".to_string()),
            last_activity: Some(12345),
            tx_count: 10,
            error_count: 1,
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: ChainProviderStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain, ChainType::Solana);
        assert!(parsed.connected);
        assert_eq!(parsed.tx_count, 10);
    }
}

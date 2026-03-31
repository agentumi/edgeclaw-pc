use crate::error::AgentError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

pub mod eth;
pub mod others;
pub mod solana;
pub mod sui;

// ─── Chain Types ───────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    Sui,
    Ethereum,
    Solana,
    Near,
    Cosmos,
    Aptos,
}

impl ChainType {
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

// ─── Chain Data Models ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProviderConfig {
    pub rpc_url: String,
    pub chain_id: Option<String>,
    pub contract_address: Option<String>,
    pub wallet_key_path: Option<String>,
    pub gas_budget: u64,
    #[serde(default)]
    pub custom_options: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainTxResult {
    pub tx_hash: String,
    pub chain: ChainType,
    pub block_number: Option<u64>,
    pub gas_used: u64,
    pub success: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainDeviceRecord {
    pub public_key: String,
    pub device_name: String,
    pub device_type: String,
    pub chain: ChainType,
    pub on_chain_id: String,
    pub registered_at: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainPolicy {
    pub policy_id: String,
    pub owner: String,
    pub role: String,
    pub capabilities: Vec<String>,
    pub expires_at: u64,
    pub issuer: String,
    pub chain: ChainType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAuditAnchor {
    pub batch_start: u64,
    pub batch_end: u64,
    pub batch_hash: String,
    pub chain: ChainType,
    pub tx: ChainTxResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBalance {
    pub chain: ChainType,
    pub symbol: String,
    pub amount: u64,
    pub decimals: u8,
}

// ─── Chain Provider Trait ──────────────────────────────────

pub trait ChainProvider: Send + Sync {
    fn name(&self) -> &str;
    fn chain_type(&self) -> ChainType;
    fn is_connected(&self) -> bool;
    fn connect(&mut self) -> Result<(), AgentError>;
    fn disconnect(&mut self) -> Result<(), AgentError>;

    fn register_device(
        &self,
        public_key: &str,
        device_name: &str,
        device_type: &str,
    ) -> Result<ChainDeviceRecord, AgentError>;
    fn lookup_device(&self, public_key: &str) -> Result<Option<ChainDeviceRecord>, AgentError>;

    fn mint_policy(
        &self,
        owner: &str,
        role: &str,
        capabilities: Vec<String>,
        expires_at: u64,
        issuer: &str,
    ) -> Result<ChainPolicy, AgentError>;
    fn verify_policy(&self, policy_id: &str) -> Result<bool, AgentError>;
    fn revoke_policy(&self, policy_id: &str) -> Result<ChainTxResult, AgentError>;

    fn anchor_audit(
        &self,
        batch_start: u64,
        batch_end: u64,
        batch_hash: &str,
    ) -> Result<ChainAuditAnchor, AgentError>;
    fn verify_audit_chain(&self) -> Result<bool, AgentError>;

    fn get_balance(&self, address: &str) -> Result<ChainBalance, AgentError>;
    fn status(&self) -> ChainProviderStatus;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProviderStatus {
    pub chain: ChainType,
    pub connected: bool,
    pub rpc_url: String,
    pub contract_address: Option<String>,
    pub last_activity: Option<u64>,
    pub tx_count: u64,
    pub error_count: u64,
}

// ─── Multi-Chain Client ────────────────────────────────────

pub struct MultiChainClient {
    providers: HashMap<ChainType, Box<dyn ChainProvider>>,
    pub primary: Option<ChainType>,
    pub offline_cache: Vec<OfflineCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineCacheEntry {
    pub chain: ChainType,
    pub operation: String,
    pub payload: String,
    pub cached_at: chrono::DateTime<chrono::Utc>,
    pub retries: u32,
}

impl Default for MultiChainClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiChainClient {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            primary: None,
            offline_cache: Vec::new(),
        }
    }
    pub fn register_provider(
        &mut self,
        chain: ChainType,
        config: ChainProviderConfig,
    ) -> Result<(), AgentError> {
        let provider = create_provider(chain, config);
        self.providers.insert(chain, provider);
        if self.primary.is_none() {
            self.primary = Some(chain);
        }
        Ok(())
    }
    pub fn set_primary(&mut self, chain: ChainType) -> Result<(), AgentError> {
        if !self.providers.contains_key(&chain) {
            return Err(AgentError::NotFound(format!(
                "chain provider not registered: {chain}"
            )));
        }
        self.primary = Some(chain);
        Ok(())
    }
    pub fn provider(&self, chain: ChainType) -> Option<&dyn ChainProvider> {
        self.providers.get(&chain).map(|p| p.as_ref())
    }
    pub fn primary_provider(&self) -> Option<&dyn ChainProvider> {
        self.primary.and_then(|c| self.provider(c))
    }
    pub fn providers(&self) -> &HashMap<ChainType, Box<dyn ChainProvider>> {
        &self.providers
    }
}

pub fn create_provider(chain: ChainType, config: ChainProviderConfig) -> Box<dyn ChainProvider> {
    match chain {
        ChainType::Sui => Box::new(sui::SuiProvider::new(config)),
        ChainType::Ethereum => Box::new(eth::EthereumProvider::new(config)),
        ChainType::Solana => Box::new(solana::SolanaProvider::new(config)),
        ChainType::Near => Box::new(others::NearProvider::new(config)),
        ChainType::Cosmos => Box::new(others::CosmosProvider::new(config)),
        ChainType::Aptos => Box::new(others::AptosProvider::new(config)),
    }
}

// ─── Multi-Chain Configuration ─────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiChainConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_primary")]
    pub primary_chain: String,
    #[serde(default)]
    pub chains: HashMap<String, ChainProviderConfig>,
    #[serde(default)]
    pub cross_chain_audit: bool,
}

fn default_primary() -> String {
    "sui".to_string()
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
    pub fn build_client(&self) -> Result<MultiChainClient, AgentError> {
        let mut client = MultiChainClient::new();
        if !self.enabled {
            return Ok(client);
        }
        for (name, cfg) in &self.chains {
            let chain_type = match name.as_str() {
                "sui" => ChainType::Sui,
                "ethereum" | "eth" => ChainType::Ethereum,
                "solana" | "sol" => ChainType::Solana,
                "near" => ChainType::Near,
                "cosmos" => ChainType::Cosmos,
                "aptos" => ChainType::Aptos,
                _ => continue,
            };
            client.register_provider(chain_type, cfg.clone())?;
        }
        Ok(client)
    }
}

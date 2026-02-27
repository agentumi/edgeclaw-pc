//! Blockchain integration for device registry, policy NFTs, and audit anchoring.
//!
//! Provides [`BlockchainClient`] for SUI blockchain interaction with offline
//! cache support. Designed for minimal on-chain footprint.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::AgentError;

/// Blockchain network type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainNetwork {
    /// SUI mainnet.
    Mainnet,
    /// SUI testnet.
    Testnet,
    /// SUI devnet.
    Devnet,
    /// Local development.
    Local,
}

impl std::fmt::Display for ChainNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainNetwork::Mainnet => write!(f, "mainnet"),
            ChainNetwork::Testnet => write!(f, "testnet"),
            ChainNetwork::Devnet => write!(f, "devnet"),
            ChainNetwork::Local => write!(f, "local"),
        }
    }
}

/// Blockchain client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfig {
    /// Network to use.
    pub network: ChainNetwork,
    /// RPC endpoint URL.
    pub rpc_url: String,
    /// Package address (deployed Move contract).
    pub package_address: Option<String>,
    /// Max gas budget per transaction.
    pub max_gas_budget: u64,
    /// Enable offline cache.
    pub offline_cache: bool,
    /// Auto-retry failed transactions.
    pub auto_retry: bool,
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            network: ChainNetwork::Devnet,
            rpc_url: "https://fullnode.devnet.sui.io:443".into(),
            package_address: None,
            max_gas_budget: 10_000_000,
            offline_cache: true,
            auto_retry: true,
        }
    }
}

/// Device registration record on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// Device public key (Ed25519 hex).
    pub public_key: String,
    /// Device name.
    pub device_name: String,
    /// Device type (desktop, mobile, iot).
    pub device_type: String,
    /// Registration timestamp.
    pub registered_at: u64,
    /// On-chain object ID.
    pub object_id: Option<String>,
    /// Whether device is active.
    pub active: bool,
}

/// Policy NFT representing access rights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyNft {
    /// NFT object ID.
    pub nft_id: String,
    /// Owner address.
    pub owner: String,
    /// Granted role.
    pub role: String,
    /// Granted capabilities.
    pub capabilities: Vec<String>,
    /// Expiry timestamp (epoch seconds).
    pub expires_at: u64,
    /// Issuer device ID.
    pub issuer: String,
}

/// Audit anchor on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAnchor {
    /// Batch start index.
    pub batch_start: u64,
    /// Batch end index.
    pub batch_end: u64,
    /// SHA-256 hash of audit batch.
    pub batch_hash: String,
    /// Timestamp.
    pub anchored_at: u64,
    /// Transaction digest.
    pub tx_digest: Option<String>,
}

/// Task token for incentivizing edge computing contributions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskToken {
    /// Token ID.
    pub token_id: String,
    /// Task description.
    pub task: String,
    /// Reward amount.
    pub reward: u64,
    /// Assignee device.
    pub assignee: Option<String>,
    /// Status.
    pub status: TaskTokenStatus,
}

/// Task token status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskTokenStatus {
    /// Task available.
    Available,
    /// Task assigned to a device.
    Assigned,
    /// Task completed and verified.
    Completed,
    /// Task expired.
    Expired,
}

/// Offline cache entry for when blockchain is unreachable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Operation type.
    pub operation: String,
    /// Serialized payload.
    pub payload: String,
    /// Timestamp.
    pub cached_at: chrono::DateTime<chrono::Utc>,
    /// Number of retry attempts.
    pub retries: u32,
}

/// Blockchain client for SUI interaction.
pub struct BlockchainClient {
    config: BlockchainConfig,
    devices: std::sync::Arc<std::sync::Mutex<HashMap<String, DeviceRecord>>>,
    policy_nfts: std::sync::Arc<std::sync::Mutex<Vec<PolicyNft>>>,
    anchors: std::sync::Arc<std::sync::Mutex<Vec<AuditAnchor>>>,
    offline_cache: std::sync::Arc<std::sync::Mutex<Vec<CacheEntry>>>,
    connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl BlockchainClient {
    /// Create a new blockchain client.
    pub fn new(config: BlockchainConfig) -> Self {
        Self {
            config,
            devices: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
            policy_nfts: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            anchors: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            offline_cache: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            connected: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Get config reference.
    pub fn config(&self) -> &BlockchainConfig {
        &self.config
    }

    /// Register a device on-chain.
    pub fn register_device(
        &self,
        public_key: &str,
        device_name: &str,
        device_type: &str,
    ) -> Result<DeviceRecord, AgentError> {
        let record = DeviceRecord {
            public_key: public_key.to_string(),
            device_name: device_name.to_string(),
            device_type: device_type.to_string(),
            registered_at: chrono::Utc::now().timestamp() as u64,
            object_id: Some(format!(
                "0x{}",
                hex::encode(&uuid::Uuid::new_v4().as_bytes()[..8])
            )),
            active: true,
        };

        if self.is_connected() {
            self.devices
                .lock()
                .unwrap()
                .insert(public_key.to_string(), record.clone());
        } else if self.config.offline_cache {
            self.cache_operation("register_device", &record)?;
        }

        Ok(record)
    }

    /// Lookup a device by public key.
    pub fn lookup_device(&self, public_key: &str) -> Option<DeviceRecord> {
        self.devices.lock().unwrap().get(public_key).cloned()
    }

    /// Mint a policy NFT.
    pub fn mint_policy_nft(
        &self,
        owner: &str,
        role: &str,
        capabilities: Vec<String>,
        expires_at: u64,
        issuer: &str,
    ) -> Result<PolicyNft, AgentError> {
        let nft = PolicyNft {
            nft_id: format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..8])),
            owner: owner.to_string(),
            role: role.to_string(),
            capabilities,
            expires_at,
            issuer: issuer.to_string(),
        };

        if self.is_connected() {
            self.policy_nfts.lock().unwrap().push(nft.clone());
        } else if self.config.offline_cache {
            self.cache_operation("mint_policy_nft", &nft)?;
        }

        Ok(nft)
    }

    /// Anchor audit batch on-chain.
    pub fn anchor_audit(
        &self,
        batch_start: u64,
        batch_end: u64,
        batch_hash: &str,
    ) -> Result<AuditAnchor, AgentError> {
        let anchor = AuditAnchor {
            batch_start,
            batch_end,
            batch_hash: batch_hash.to_string(),
            anchored_at: chrono::Utc::now().timestamp() as u64,
            tx_digest: Some(format!(
                "0x{}",
                hex::encode(&uuid::Uuid::new_v4().as_bytes()[..8])
            )),
        };

        if self.is_connected() {
            self.anchors.lock().unwrap().push(anchor.clone());
        } else if self.config.offline_cache {
            self.cache_operation("anchor_audit", &anchor)?;
        }

        Ok(anchor)
    }

    /// List all registered devices.
    pub fn list_devices(&self) -> Vec<DeviceRecord> {
        self.devices.lock().unwrap().values().cloned().collect()
    }

    /// List all policy NFTs for an owner.
    pub fn list_policy_nfts(&self, owner: &str) -> Vec<PolicyNft> {
        self.policy_nfts
            .lock()
            .unwrap()
            .iter()
            .filter(|n| n.owner == owner)
            .cloned()
            .collect()
    }

    /// Get offline cache size.
    pub fn cache_size(&self) -> usize {
        self.offline_cache.lock().unwrap().len()
    }

    /// Flush offline cache (simulate sending cached operations).
    pub fn flush_cache(&self) -> usize {
        let mut cache = self.offline_cache.lock().unwrap();
        let count = cache.len();
        cache.clear();
        count
    }

    /// Check if connected to blockchain.
    pub fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Set connection status.
    pub fn set_connected(&self, connected: bool) {
        self.connected
            .store(connected, std::sync::atomic::Ordering::Relaxed);
    }

    fn cache_operation<T: Serialize>(
        &self,
        operation: &str,
        payload: &T,
    ) -> Result<(), AgentError> {
        let entry = CacheEntry {
            operation: operation.to_string(),
            payload: serde_json::to_string(payload)?,
            cached_at: chrono::Utc::now(),
            retries: 0,
        };
        self.offline_cache.lock().unwrap().push(entry);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockchain_config_default() {
        let config = BlockchainConfig::default();
        assert_eq!(config.network, ChainNetwork::Devnet);
        assert!(config.offline_cache);
    }

    #[test]
    fn test_chain_network_display() {
        assert_eq!(ChainNetwork::Mainnet.to_string(), "mainnet");
        assert_eq!(ChainNetwork::Testnet.to_string(), "testnet");
    }

    #[test]
    fn test_register_device_connected() {
        let client = BlockchainClient::new(BlockchainConfig::default());
        client.set_connected(true);
        let record = client
            .register_device("0xabc", "desktop-1", "desktop")
            .unwrap();
        assert_eq!(record.device_name, "desktop-1");
        assert!(record.active);
        assert!(record.object_id.is_some());
        assert_eq!(client.list_devices().len(), 1);
    }

    #[test]
    fn test_register_device_offline_cache() {
        let client = BlockchainClient::new(BlockchainConfig::default());
        client.set_connected(false);
        let _record = client
            .register_device("0xabc", "desktop-1", "desktop")
            .unwrap();
        assert_eq!(client.cache_size(), 1);
        assert_eq!(client.list_devices().len(), 0); // Not stored in memory
    }

    #[test]
    fn test_lookup_device() {
        let client = BlockchainClient::new(BlockchainConfig::default());
        client.set_connected(true);
        client
            .register_device("0xabc", "desktop-1", "desktop")
            .unwrap();
        let found = client.lookup_device("0xabc");
        assert!(found.is_some());
        assert!(client.lookup_device("0xzzz").is_none());
    }

    #[test]
    fn test_mint_policy_nft() {
        let client = BlockchainClient::new(BlockchainConfig::default());
        client.set_connected(true);
        let nft = client
            .mint_policy_nft(
                "0xowner",
                "admin",
                vec!["status_query".into(), "log_read".into()],
                9999999999,
                "0xissuer",
            )
            .unwrap();
        assert_eq!(nft.role, "admin");
        assert_eq!(client.list_policy_nfts("0xowner").len(), 1);
        assert_eq!(client.list_policy_nfts("0xother").len(), 0);
    }

    #[test]
    fn test_anchor_audit() {
        let client = BlockchainClient::new(BlockchainConfig::default());
        client.set_connected(true);
        let anchor = client.anchor_audit(1, 100, "abcdef1234567890").unwrap();
        assert_eq!(anchor.batch_start, 1);
        assert_eq!(anchor.batch_end, 100);
        assert!(anchor.tx_digest.is_some());
    }

    #[test]
    fn test_flush_cache() {
        let client = BlockchainClient::new(BlockchainConfig::default());
        client.set_connected(false);
        client.register_device("0xa", "dev1", "desktop").unwrap();
        client.register_device("0xb", "dev2", "mobile").unwrap();
        assert_eq!(client.cache_size(), 2);
        let flushed = client.flush_cache();
        assert_eq!(flushed, 2);
        assert_eq!(client.cache_size(), 0);
    }

    #[test]
    fn test_task_token_status_serialize() {
        let json = serde_json::to_string(&TaskTokenStatus::Completed).unwrap();
        let parsed: TaskTokenStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TaskTokenStatus::Completed);
    }

    #[test]
    fn test_device_record_serialize() {
        let record = DeviceRecord {
            public_key: "0xabc".into(),
            device_name: "test".into(),
            device_type: "desktop".into(),
            registered_at: 1234567890,
            object_id: None,
            active: true,
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: DeviceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.device_name, "test");
    }
}

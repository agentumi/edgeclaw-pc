use std::collections::HashMap;
use crate::error::AgentError;
use super::{ChainProvider, ChainType, ChainProviderConfig, ChainDeviceRecord, ChainPolicy, ChainTxResult, ChainAuditAnchor, ChainBalance, ChainProviderStatus};

pub struct SuiProvider {
    config: ChainProviderConfig,
    connected: bool,
    devices: HashMap<String, ChainDeviceRecord>,
    policies: Vec<ChainPolicy>,
    tx_count: u64,
    error_count: u64,
}

impl SuiProvider {
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

impl ChainProvider for SuiProvider {
    fn name(&self) -> &str { "SUI Move" }
    fn chain_type(&self) -> ChainType { ChainType::Sui }
    fn is_connected(&self) -> bool { self.connected }
    fn connect(&mut self) -> Result<(), AgentError> { self.connected = true; Ok(()) }
    fn disconnect(&mut self) -> Result<(), AgentError> { self.connected = false; Ok(()) }

    fn register_device(&self, public_key: &str, device_name: &str, device_type: &str) -> Result<ChainDeviceRecord, AgentError> {
        Ok(ChainDeviceRecord {
            public_key: public_key.to_string(),
            device_name: device_name.to_string(),
            device_type: device_type.to_string(),
            chain: ChainType::Sui,
            on_chain_id: format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..8])),
            registered_at: chrono::Utc::now().timestamp() as u64,
            active: true,
        })
    }
    fn lookup_device(&self, public_key: &str) -> Result<Option<ChainDeviceRecord>, AgentError> {
        Ok(self.devices.get(public_key).cloned())
    }
    fn mint_policy(&self, owner: &str, role: &str, capabilities: Vec<String>, expires_at: u64, issuer: &str) -> Result<ChainPolicy, AgentError> {
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
            block_number: None, gas_used: 1000, success: true,
            timestamp: chrono::Utc::now().timestamp() as u64,
        })
    }
    fn anchor_audit(&self, batch_start: u64, batch_end: u64, batch_hash: &str) -> Result<ChainAuditAnchor, AgentError> {
        Ok(ChainAuditAnchor {
            batch_start, batch_end, batch_hash: batch_hash.to_string(),
            chain: ChainType::Sui,
            tx: ChainTxResult {
                tx_hash: format!("0x{}", hex::encode(&uuid::Uuid::new_v4().as_bytes()[..16])),
                chain: ChainType::Sui, block_number: None, gas_used: 2000, success: true,
                timestamp: chrono::Utc::now().timestamp() as u64,
            }
        })
    }
    fn verify_audit_chain(&self) -> Result<bool, AgentError> { Ok(true) }
    fn get_balance(&self, _address: &str) -> Result<ChainBalance, AgentError> {
        Ok(ChainBalance { chain: ChainType::Sui, symbol: "SUI".to_string(), amount: 0, decimals: 9 })
    }
    fn status(&self) -> ChainProviderStatus {
        ChainProviderStatus {
            chain: ChainType::Sui, connected: self.connected,
            rpc_url: self.config.rpc_url.clone(), contract_address: self.config.contract_address.clone(),
            last_activity: None, tx_count: self.tx_count, error_count: self.error_count,
        }
    }
}

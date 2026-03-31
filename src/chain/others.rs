use super::{
    ChainAuditAnchor, ChainBalance, ChainDeviceRecord, ChainPolicy, ChainProvider,
    ChainProviderConfig, ChainProviderStatus, ChainTxResult, ChainType,
};
use crate::error::AgentError;

// ─── NEAR Provider ─────────────────────────────────────────

pub struct NearProvider {
    pub config: ChainProviderConfig,
    pub connected: bool,
    pub tx_count: u64,
    pub error_count: u64,
}

impl NearProvider {
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
        pk: &str,
        name: &str,
        dtype: &str,
    ) -> Result<ChainDeviceRecord, AgentError> {
        Ok(ChainDeviceRecord {
            public_key: pk.into(),
            device_name: name.into(),
            device_type: dtype.into(),
            chain: ChainType::Near,
            on_chain_id: pk.into(),
            registered_at: 0,
            active: true,
        })
    }
    fn lookup_device(&self, _pk: &str) -> Result<Option<ChainDeviceRecord>, AgentError> {
        Ok(None)
    }
    fn mint_policy(
        &self,
        owner: &str,
        role: &str,
        caps: Vec<String>,
        exp: u64,
        iss: &str,
    ) -> Result<ChainPolicy, AgentError> {
        Ok(ChainPolicy {
            policy_id: "near-policy".into(),
            owner: owner.into(),
            role: role.into(),
            capabilities: caps,
            expires_at: exp,
            issuer: iss.into(),
            chain: ChainType::Near,
        })
    }
    fn verify_policy(&self, _pid: &str) -> Result<bool, AgentError> {
        Ok(true)
    }
    fn revoke_policy(&self, _pid: &str) -> Result<ChainTxResult, AgentError> {
        Ok(ChainTxResult {
            tx_hash: "near-hash".into(),
            chain: ChainType::Near,
            block_number: None,
            gas_used: 0,
            success: true,
            timestamp: 0,
        })
    }
    fn anchor_audit(&self, s: u64, e: u64, h: &str) -> Result<ChainAuditAnchor, AgentError> {
        Ok(ChainAuditAnchor {
            batch_start: s,
            batch_end: e,
            batch_hash: h.into(),
            chain: ChainType::Near,
            tx: ChainTxResult {
                tx_hash: "near-hash".into(),
                chain: ChainType::Near,
                block_number: None,
                gas_used: 0,
                success: true,
                timestamp: 0,
            },
        })
    }
    fn verify_audit_chain(&self) -> Result<bool, AgentError> {
        Ok(true)
    }
    fn get_balance(&self, _addr: &str) -> Result<ChainBalance, AgentError> {
        Ok(ChainBalance {
            chain: ChainType::Near,
            symbol: "NEAR".into(),
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

// ─── Cosmos Provider ───────────────────────────────────────

pub struct CosmosProvider {
    pub config: ChainProviderConfig,
    pub connected: bool,
    pub tx_count: u64,
    pub error_count: u64,
}

impl CosmosProvider {
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
        pk: &str,
        name: &str,
        dtype: &str,
    ) -> Result<ChainDeviceRecord, AgentError> {
        Ok(ChainDeviceRecord {
            public_key: pk.into(),
            device_name: name.into(),
            device_type: dtype.into(),
            chain: ChainType::Cosmos,
            on_chain_id: pk.into(),
            registered_at: 0,
            active: true,
        })
    }
    fn lookup_device(&self, _pk: &str) -> Result<Option<ChainDeviceRecord>, AgentError> {
        Ok(None)
    }
    fn mint_policy(
        &self,
        owner: &str,
        role: &str,
        caps: Vec<String>,
        exp: u64,
        iss: &str,
    ) -> Result<ChainPolicy, AgentError> {
        Ok(ChainPolicy {
            policy_id: "cosmos-policy".into(),
            owner: owner.into(),
            role: role.into(),
            capabilities: caps,
            expires_at: exp,
            issuer: iss.into(),
            chain: ChainType::Cosmos,
        })
    }
    fn verify_policy(&self, _pid: &str) -> Result<bool, AgentError> {
        Ok(true)
    }
    fn revoke_policy(&self, _pid: &str) -> Result<ChainTxResult, AgentError> {
        Ok(ChainTxResult {
            tx_hash: "cosmos-hash".into(),
            chain: ChainType::Cosmos,
            block_number: None,
            gas_used: 0,
            success: true,
            timestamp: 0,
        })
    }
    fn anchor_audit(&self, s: u64, e: u64, h: &str) -> Result<ChainAuditAnchor, AgentError> {
        Ok(ChainAuditAnchor {
            batch_start: s,
            batch_end: e,
            batch_hash: h.into(),
            chain: ChainType::Cosmos,
            tx: ChainTxResult {
                tx_hash: "cosmos-hash".into(),
                chain: ChainType::Cosmos,
                block_number: None,
                gas_used: 0,
                success: true,
                timestamp: 0,
            },
        })
    }
    fn verify_audit_chain(&self) -> Result<bool, AgentError> {
        Ok(true)
    }
    fn get_balance(&self, _addr: &str) -> Result<ChainBalance, AgentError> {
        Ok(ChainBalance {
            chain: ChainType::Cosmos,
            symbol: "ATOM".into(),
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

// ─── Aptos Provider ────────────────────────────────────────

pub struct AptosProvider {
    pub config: ChainProviderConfig,
    pub connected: bool,
    pub tx_count: u64,
    pub error_count: u64,
}

impl AptosProvider {
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
        pk: &str,
        name: &str,
        dtype: &str,
    ) -> Result<ChainDeviceRecord, AgentError> {
        Ok(ChainDeviceRecord {
            public_key: pk.into(),
            device_name: name.into(),
            device_type: dtype.into(),
            chain: ChainType::Aptos,
            on_chain_id: pk.into(),
            registered_at: 0,
            active: true,
        })
    }
    fn lookup_device(&self, _pk: &str) -> Result<Option<ChainDeviceRecord>, AgentError> {
        Ok(None)
    }
    fn mint_policy(
        &self,
        owner: &str,
        role: &str,
        caps: Vec<String>,
        exp: u64,
        iss: &str,
    ) -> Result<ChainPolicy, AgentError> {
        Ok(ChainPolicy {
            policy_id: "aptos-policy".into(),
            owner: owner.into(),
            role: role.into(),
            capabilities: caps,
            expires_at: exp,
            issuer: iss.into(),
            chain: ChainType::Aptos,
        })
    }
    fn verify_policy(&self, _pid: &str) -> Result<bool, AgentError> {
        Ok(true)
    }
    fn revoke_policy(&self, _pid: &str) -> Result<ChainTxResult, AgentError> {
        Ok(ChainTxResult {
            tx_hash: "aptos-hash".into(),
            chain: ChainType::Aptos,
            block_number: None,
            gas_used: 0,
            success: true,
            timestamp: 0,
        })
    }
    fn anchor_audit(&self, s: u64, e: u64, h: &str) -> Result<ChainAuditAnchor, AgentError> {
        Ok(ChainAuditAnchor {
            batch_start: s,
            batch_end: e,
            batch_hash: h.into(),
            chain: ChainType::Aptos,
            tx: ChainTxResult {
                tx_hash: "aptos-hash".into(),
                chain: ChainType::Aptos,
                block_number: None,
                gas_used: 0,
                success: true,
                timestamp: 0,
            },
        })
    }
    fn verify_audit_chain(&self) -> Result<bool, AgentError> {
        Ok(true)
    }
    fn get_balance(&self, _addr: &str) -> Result<ChainBalance, AgentError> {
        Ok(ChainBalance {
            chain: ChainType::Aptos,
            symbol: "APT".into(),
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

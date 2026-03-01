use cosmwasm_schema::{cw_serde, QueryResponses};

// ─── Instantiate ───────────────────────────────────────

#[cw_serde]
pub struct InstantiateMsg {}

// ─── Execute ───────────────────────────────────────────

#[cw_serde]
pub enum ExecuteMsg {
    // Device Registry
    RegisterDevice {
        public_key: String,
        device_name: String,
        device_type: String,
    },
    DeactivateDevice {
        public_key: String,
    },
    ReactivateDevice {
        public_key: String,
    },

    // Policy NFT
    MintPolicy {
        owner: String,
        role: String,
        capabilities: Vec<String>,
        expires_at: u64,
    },
    RevokePolicy {
        policy_id: u64,
    },

    // Task Token
    MintTokens {
        recipient: String,
        amount: u64,
    },
    RewardTask {
        task_id: String,
        executor: String,
        amount: u64,
    },

    // Audit Anchor
    AnchorAudit {
        batch_start: u64,
        batch_end: u64,
        batch_hash: String,
    },
}

// ─── Query ─────────────────────────────────────────────

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // Device Registry
    #[returns(DeviceResponse)]
    GetDevice { public_key: String },

    #[returns(CountResponse)]
    GetDeviceCount {},

    // Policy
    #[returns(PolicyResponse)]
    GetPolicy { policy_id: u64 },

    #[returns(BoolResponse)]
    VerifyPolicy { policy_id: u64 },

    // Token
    #[returns(BalanceResponse)]
    GetBalance { account: String },

    #[returns(SupplyResponse)]
    GetTotalSupply {},

    // Audit
    #[returns(CountResponse)]
    GetAnchorCount {},

    #[returns(AnchorResponse)]
    GetAnchor { index: u64 },

    #[returns(BoolResponse)]
    VerifyAuditChain {},
}

// ─── Response Types ────────────────────────────────────

#[cw_serde]
pub struct DeviceResponse {
    pub public_key: String,
    pub device_name: String,
    pub device_type: String,
    pub owner: String,
    pub registered_at: u64,
    pub active: bool,
}

#[cw_serde]
pub struct PolicyResponse {
    pub policy_id: u64,
    pub owner: String,
    pub role: String,
    pub capabilities: Vec<String>,
    pub expires_at: u64,
    pub issuer: String,
    pub created_at: u64,
    pub revoked: bool,
}

#[cw_serde]
pub struct AnchorResponse {
    pub index: u64,
    pub batch_start: u64,
    pub batch_end: u64,
    pub batch_hash: String,
    pub anchored_at: u64,
    pub submitter: String,
}

#[cw_serde]
pub struct CountResponse {
    pub count: u64,
}

#[cw_serde]
pub struct BoolResponse {
    pub result: bool,
}

#[cw_serde]
pub struct BalanceResponse {
    pub balance: u64,
}

#[cw_serde]
pub struct SupplyResponse {
    pub total_supply: u64,
}

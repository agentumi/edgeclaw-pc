use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

// ─── Config ────────────────────────────────────────────

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    pub device_count: u64,
    pub next_policy_id: u64,
    pub anchor_count: u64,
    pub last_batch_end: u64,
    pub total_supply: u128,
}

pub const CONFIG: Item<Config> = Item::new("config");

// ─── Device Registry ───────────────────────────────────

#[cw_serde]
pub struct DeviceRecord {
    pub public_key: String,
    pub device_name: String,
    pub device_type: String,
    pub owner: Addr,
    pub registered_at: u64,
    pub active: bool,
}

/// Keyed by public_key string.
pub const DEVICES: Map<&str, DeviceRecord> = Map::new("devices");

// ─── Policy NFT ────────────────────────────────────────

#[cw_serde]
pub struct PolicyRecord {
    pub policy_id: u64,
    pub owner: Addr,
    pub role: String,
    pub capabilities: Vec<String>,
    pub expires_at: u64,
    pub issuer: Addr,
    pub created_at: u64,
    pub revoked: bool,
}

/// Keyed by policy_id (u64 → string).
pub const POLICIES: Map<u64, PolicyRecord> = Map::new("policies");

// ─── Audit Anchor ──────────────────────────────────────

#[cw_serde]
pub struct AuditAnchorRecord {
    pub index: u64,
    pub batch_start: u64,
    pub batch_end: u64,
    pub batch_hash: String,
    pub anchored_at: u64,
    pub submitter: Addr,
}

/// Keyed by sequential index.
pub const AUDIT_ANCHORS: Map<u64, AuditAnchorRecord> = Map::new("audit_anchors");

// ─── Token Balances ────────────────────────────────────

/// Keyed by account address string.
pub const BALANCES: Map<&str, u128> = Map::new("balances");

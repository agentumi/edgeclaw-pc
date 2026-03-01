//! EdgeClaw NEAR Protocol Smart Contract
//!
//! Combined contract implementing:
//! - Device Registry
//! - Policy NFT (NEP-171 compatible)
//! - Task Token (ECLAW, NEP-141 compatible)
//! - Audit Anchor
//!
//! Deployed as a single NEAR contract with method-based routing.

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedMap, Vector};
use near_sdk::json_types::U64;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near_bindgen, AccountId, PanicOnDefault, BorshStorageKey};

// ─── Storage Keys ──────────────────────────────────────

#[derive(BorshStorageKey, BorshSerialize)]
enum StorageKey {
    Devices,
    Policies,
    AuditAnchors,
    TokenBalances,
}

// ─── Data Types ────────────────────────────────────────

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct DeviceRecord {
    pub public_key: String,
    pub device_name: String,
    pub device_type: String,
    pub owner: AccountId,
    pub registered_at: u64,
    pub active: bool,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct PolicyRecord {
    pub policy_id: u64,
    pub owner: AccountId,
    pub role: String,
    pub capabilities: Vec<String>,
    pub expires_at: u64,
    pub issuer: AccountId,
    pub created_at: u64,
    pub revoked: bool,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct AuditAnchorRecord {
    pub index: u64,
    pub batch_start: u64,
    pub batch_end: u64,
    pub batch_hash: String,
    pub anchored_at: u64,
    pub submitter: AccountId,
}

// ─── Contract ──────────────────────────────────────────

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct EdgeClawContract {
    pub admin: AccountId,

    // Device Registry
    pub devices: UnorderedMap<String, DeviceRecord>,
    pub device_count: u64,

    // Policy NFT
    pub policies: LookupMap<u64, PolicyRecord>,
    pub next_policy_id: u64,

    // Audit Anchor
    pub audit_anchors: Vector<AuditAnchorRecord>,
    pub last_batch_end: u64,

    // Task Token (ECLAW)
    pub token_balances: LookupMap<AccountId, u128>,
    pub total_supply: u128,
}

#[near_bindgen]
impl EdgeClawContract {
    // ─── Init ──────────────────────────────────────────

    #[init]
    pub fn new() -> Self {
        assert!(!env::state_exists(), "Already initialized");
        Self {
            admin: env::predecessor_account_id(),
            devices: UnorderedMap::new(StorageKey::Devices),
            device_count: 0,
            policies: LookupMap::new(StorageKey::Policies),
            next_policy_id: 0,
            audit_anchors: Vector::new(StorageKey::AuditAnchors),
            last_batch_end: 0,
            token_balances: LookupMap::new(StorageKey::TokenBalances),
            total_supply: 0,
        }
    }

    // ─── Device Registry ───────────────────────────────

    /// Register a new device.
    #[payable]
    pub fn register_device(
        &mut self,
        public_key: String,
        device_name: String,
        device_type: String,
    ) {
        assert!(
            self.devices.get(&public_key).is_none(),
            "Device already registered"
        );

        let record = DeviceRecord {
            public_key: public_key.clone(),
            device_name,
            device_type,
            owner: env::predecessor_account_id(),
            registered_at: env::block_timestamp() / 1_000_000_000, // ns → s
            active: true,
        };

        self.devices.insert(&public_key, &record);
        self.device_count += 1;

        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"edgeclaw\",\"event\":\"device_registered\",\"data\":{{\"public_key\":\"{}\"}}}}",
            public_key
        ));
    }

    /// Deactivate a device.
    pub fn deactivate_device(&mut self, public_key: String) {
        let mut record = self
            .devices
            .get(&public_key)
            .expect("Device not found");
        assert!(
            env::predecessor_account_id() == record.owner
                || env::predecessor_account_id() == self.admin,
            "Not authorized"
        );
        record.active = false;
        self.devices.insert(&public_key, &record);
    }

    /// Reactivate a device.
    pub fn reactivate_device(&mut self, public_key: String) {
        let mut record = self
            .devices
            .get(&public_key)
            .expect("Device not found");
        assert!(
            env::predecessor_account_id() == record.owner
                || env::predecessor_account_id() == self.admin,
            "Not authorized"
        );
        record.active = true;
        self.devices.insert(&public_key, &record);
    }

    /// View: get device.
    pub fn get_device(&self, public_key: String) -> Option<DeviceRecord> {
        self.devices.get(&public_key)
    }

    /// View: get device count.
    pub fn get_device_count(&self) -> U64 {
        U64(self.device_count)
    }

    // ─── Policy NFT ────────────────────────────────────

    /// Mint a new policy. Admin only.
    #[payable]
    pub fn mint_policy(
        &mut self,
        owner: AccountId,
        role: String,
        capabilities: Vec<String>,
        expires_at: U64,
    ) -> U64 {
        assert_eq!(
            env::predecessor_account_id(),
            self.admin,
            "Only admin can mint policies"
        );
        assert!(
            matches!(role.as_str(), "owner" | "admin" | "operator" | "viewer" | "guest"),
            "Invalid role"
        );

        let policy_id = self.next_policy_id;
        let record = PolicyRecord {
            policy_id,
            owner,
            role,
            capabilities,
            expires_at: expires_at.0,
            issuer: env::predecessor_account_id(),
            created_at: env::block_timestamp() / 1_000_000_000,
            revoked: false,
        };

        self.policies.insert(&policy_id, &record);
        self.next_policy_id += 1;

        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"edgeclaw\",\"event\":\"policy_minted\",\"data\":{{\"policy_id\":{}}}}}",
            policy_id
        ));

        U64(policy_id)
    }

    /// Revoke a policy. Issuer or admin only.
    pub fn revoke_policy(&mut self, policy_id: U64) {
        let mut record = self
            .policies
            .get(&policy_id.0)
            .expect("Policy not found");
        assert!(
            env::predecessor_account_id() == record.issuer
                || env::predecessor_account_id() == self.admin,
            "Not authorized"
        );
        assert!(!record.revoked, "Policy already revoked");
        record.revoked = true;
        self.policies.insert(&policy_id.0, &record);
    }

    /// View: verify policy validity.
    pub fn verify_policy(&self, policy_id: U64) -> bool {
        match self.policies.get(&policy_id.0) {
            Some(record) => {
                if record.revoked {
                    return false;
                }
                if record.expires_at > 0 {
                    let now = env::block_timestamp() / 1_000_000_000;
                    if now > record.expires_at {
                        return false;
                    }
                }
                true
            }
            None => false,
        }
    }

    /// View: get policy.
    pub fn get_policy(&self, policy_id: U64) -> Option<PolicyRecord> {
        self.policies.get(&policy_id.0)
    }

    // ─── Task Token (ECLAW NEP-141) ────────────────────

    /// Mint ECLAW tokens. Admin only.
    pub fn mint_tokens(&mut self, recipient: AccountId, amount: U64) {
        assert_eq!(
            env::predecessor_account_id(),
            self.admin,
            "Only admin can mint"
        );
        let balance = self.token_balances.get(&recipient).unwrap_or(0);
        self.token_balances
            .insert(&recipient, &(balance + amount.0 as u128));
        self.total_supply += amount.0 as u128;
    }

    /// Reward task executor with ECLAW tokens. Admin only.
    pub fn reward_task(&mut self, task_id: String, executor: AccountId, amount: U64) {
        assert_eq!(
            env::predecessor_account_id(),
            self.admin,
            "Only admin can reward"
        );
        let balance = self.token_balances.get(&executor).unwrap_or(0);
        self.token_balances
            .insert(&executor, &(balance + amount.0 as u128));
        self.total_supply += amount.0 as u128;

        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"edgeclaw\",\"event\":\"task_reward\",\"data\":{{\"task_id\":\"{}\",\"amount\":{}}}}}",
            task_id, amount.0
        ));
    }

    /// View: get token balance.
    pub fn get_balance(&self, account: AccountId) -> U64 {
        U64(self.token_balances.get(&account).unwrap_or(0) as u64)
    }

    /// View: get total supply.
    pub fn get_total_supply(&self) -> U64 {
        U64(self.total_supply as u64)
    }

    // ─── Audit Anchor ──────────────────────────────────

    /// Anchor an audit batch hash. Admin only.
    pub fn anchor_audit(
        &mut self,
        batch_start: U64,
        batch_end: U64,
        batch_hash: String,
    ) {
        assert_eq!(
            env::predecessor_account_id(),
            self.admin,
            "Only admin can anchor audits"
        );
        assert!(batch_start.0 <= batch_end.0, "Invalid range");
        if self.audit_anchors.len() > 0 {
            assert!(
                batch_start.0 > self.last_batch_end,
                "Batch overlaps with previous anchor"
            );
        }

        let record = AuditAnchorRecord {
            index: self.audit_anchors.len(),
            batch_start: batch_start.0,
            batch_end: batch_end.0,
            batch_hash,
            anchored_at: env::block_timestamp() / 1_000_000_000,
            submitter: env::predecessor_account_id(),
        };

        self.audit_anchors.push(&record);
        self.last_batch_end = batch_end.0;
    }

    /// View: get anchor count.
    pub fn get_anchor_count(&self) -> U64 {
        U64(self.audit_anchors.len())
    }

    /// View: get specific anchor.
    pub fn get_anchor(&self, index: U64) -> Option<AuditAnchorRecord> {
        if index.0 < self.audit_anchors.len() {
            Some(self.audit_anchors.get(index.0).unwrap())
        } else {
            None
        }
    }

    /// View: verify audit chain continuity.
    pub fn verify_audit_chain(&self) -> bool {
        if self.audit_anchors.len() <= 1 {
            return true;
        }
        for i in 1..self.audit_anchors.len() {
            let prev = self.audit_anchors.get(i - 1).unwrap();
            let curr = self.audit_anchors.get(i).unwrap();
            if curr.batch_start <= prev.batch_end {
                return false;
            }
        }
        true
    }
}

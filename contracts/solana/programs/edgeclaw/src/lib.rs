//! EdgeClaw Solana Programs (Anchor)
//!
//! Four programs in one: DeviceRegistry, PolicyNFT, TaskToken, AuditAnchor.
//! Compiled as a single Anchor program with instruction routing.

use anchor_lang::prelude::*;

declare_id!("ECLAWxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

pub mod device_registry;
pub mod policy_nft;
pub mod task_token;
pub mod audit_anchor;

use device_registry::*;
use policy_nft::*;
use task_token::*;
use audit_anchor::*;

#[program]
pub mod edgeclaw {
    use super::*;

    // ─── Device Registry ───────────────────────────────────

    /// Initialize the device registry.
    pub fn initialize_registry(ctx: Context<InitializeRegistry>) -> Result<()> {
        device_registry::initialize_registry(ctx)
    }

    /// Register a device on-chain.
    pub fn register_device(
        ctx: Context<RegisterDevice>,
        public_key: String,
        device_name: String,
        device_type: String,
    ) -> Result<()> {
        device_registry::register_device(ctx, public_key, device_name, device_type)
    }

    /// Deactivate a device.
    pub fn deactivate_device(ctx: Context<DeactivateDevice>) -> Result<()> {
        device_registry::deactivate_device(ctx)
    }

    /// Reactivate a device.
    pub fn reactivate_device(ctx: Context<ReactivateDevice>) -> Result<()> {
        device_registry::reactivate_device(ctx)
    }

    // ─── Policy NFT ────────────────────────────────────────

    /// Mint a policy NFT.
    pub fn mint_policy(
        ctx: Context<MintPolicy>,
        role: String,
        capabilities: Vec<String>,
        expires_at: i64,
    ) -> Result<()> {
        policy_nft::mint_policy(ctx, role, capabilities, expires_at)
    }

    /// Revoke a policy.
    pub fn revoke_policy(ctx: Context<RevokePolicy>) -> Result<()> {
        policy_nft::revoke_policy(ctx)
    }

    // ─── Task Token ────────────────────────────────────────

    /// Initialize the ECLAW token mint.
    pub fn initialize_token(ctx: Context<InitializeToken>, decimals: u8) -> Result<()> {
        task_token::initialize_token(ctx, decimals)
    }

    /// Mint ECLAW tokens.
    pub fn mint_tokens(ctx: Context<MintTokens>, amount: u64) -> Result<()> {
        task_token::mint_tokens(ctx, amount)
    }

    /// Reward task executor.
    pub fn reward_task(
        ctx: Context<RewardTask>,
        task_id: [u8; 32],
        amount: u64,
    ) -> Result<()> {
        task_token::reward_task(ctx, task_id, amount)
    }

    // ─── Audit Anchor ──────────────────────────────────────

    /// Initialize the audit store.
    pub fn initialize_audit(ctx: Context<InitializeAudit>) -> Result<()> {
        audit_anchor::initialize_audit(ctx)
    }

    /// Anchor an audit batch.
    pub fn anchor_audit(
        ctx: Context<AnchorAuditCtx>,
        batch_start: u64,
        batch_end: u64,
        batch_hash: [u8; 32],
    ) -> Result<()> {
        audit_anchor::anchor_audit(ctx, batch_start, batch_end, batch_hash)
    }
}

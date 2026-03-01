//! EdgeClaw Policy NFT — Solana Anchor
//!
//! RBAC policies as on-chain PDA accounts with Metaplex-compatible metadata.

use anchor_lang::prelude::*;

/// Maximum role string length.
const MAX_ROLE_LEN: usize = 32;
/// Maximum capabilities (count * avg_len).
const MAX_CAPS_LEN: usize = 512;

// ─── Accounts ──────────────────────────────────────────

/// Policy record (PDA derived from sequential ID).
#[account]
pub struct PolicyRecord {
    /// Sequential policy ID.
    pub policy_id: u64,
    /// Owner wallet.
    pub owner: Pubkey,
    /// Role string.
    pub role: String,
    /// Capabilities (serialized as joined string).
    pub capabilities: Vec<String>,
    /// Expiry timestamp (0 = never).
    pub expires_at: i64,
    /// Issuer wallet.
    pub issuer: Pubkey,
    /// Creation timestamp.
    pub created_at: i64,
    /// Revoked flag.
    pub revoked: bool,
    /// Bump seed.
    pub bump: u8,
}

impl PolicyRecord {
    pub const LEN: usize = 8    // discriminator
        + 8                      // policy_id
        + 32                     // owner
        + 4 + MAX_ROLE_LEN      // role
        + 4 + MAX_CAPS_LEN      // capabilities
        + 8                      // expires_at
        + 32                     // issuer
        + 8                      // created_at
        + 1                      // revoked
        + 1;                     // bump
}

/// Policy counter (PDA).
#[account]
pub struct PolicyCounter {
    pub next_id: u64,
    pub admin: Pubkey,
    pub bump: u8,
}

// ─── Contexts ──────────────────────────────────────────

#[derive(Accounts)]
pub struct MintPolicy<'info> {
    #[account(mut, seeds = [b"policy_counter"], bump = counter.bump)]
    pub counter: Account<'info, PolicyCounter>,
    #[account(
        init,
        payer = issuer,
        space = PolicyRecord::LEN,
        seeds = [b"policy", &counter.next_id.to_le_bytes()],
        bump,
    )]
    pub policy: Account<'info, PolicyRecord>,
    /// CHECK: Policy recipient (doesn't need to sign).
    pub owner: AccountInfo<'info>,
    #[account(mut)]
    pub issuer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevokePolicy<'info> {
    #[account(
        mut,
        constraint = policy.issuer == authority.key() || counter.admin == authority.key()
            @ PolicyError::NotIssuerOrAdmin,
    )]
    pub policy: Account<'info, PolicyRecord>,
    #[account(seeds = [b"policy_counter"], bump = counter.bump)]
    pub counter: Account<'info, PolicyCounter>,
    pub authority: Signer<'info>,
}

// ─── Errors ────────────────────────────────────────────

#[error_code]
pub enum PolicyError {
    #[msg("Not issuer or admin")]
    NotIssuerOrAdmin,
    #[msg("Policy already revoked")]
    AlreadyRevoked,
    #[msg("Invalid role")]
    InvalidRole,
}

// ─── Handlers ──────────────────────────────────────────

pub fn mint_policy(
    ctx: Context<MintPolicy>,
    role: String,
    capabilities: Vec<String>,
    expires_at: i64,
) -> Result<()> {
    require!(
        matches!(role.as_str(), "owner" | "admin" | "operator" | "viewer" | "guest"),
        PolicyError::InvalidRole
    );

    let clock = Clock::get()?;
    let counter = &mut ctx.accounts.counter;
    let policy = &mut ctx.accounts.policy;

    policy.policy_id = counter.next_id;
    policy.owner = ctx.accounts.owner.key();
    policy.role = role;
    policy.capabilities = capabilities;
    policy.expires_at = expires_at;
    policy.issuer = ctx.accounts.issuer.key();
    policy.created_at = clock.unix_timestamp;
    policy.revoked = false;
    policy.bump = ctx.bumps.policy;

    counter.next_id += 1;

    Ok(())
}

pub fn revoke_policy(ctx: Context<RevokePolicy>) -> Result<()> {
    let policy = &mut ctx.accounts.policy;
    require!(!policy.revoked, PolicyError::AlreadyRevoked);
    policy.revoked = true;
    Ok(())
}

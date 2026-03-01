//! EdgeClaw Audit Anchor — Solana Anchor
//!
//! On-chain audit log anchoring using sequential PDA accounts.

use anchor_lang::prelude::*;

// ─── Accounts ──────────────────────────────────────────

/// Global audit store (PDA).
#[account]
pub struct AuditStore {
    pub admin: Pubkey,
    pub anchor_count: u64,
    pub last_batch_end: u64,
    pub bump: u8,
}

/// Individual audit anchor record (PDA derived from index).
#[account]
pub struct AnchorRecord {
    pub index: u64,
    pub batch_start: u64,
    pub batch_end: u64,
    pub batch_hash: [u8; 32],
    pub anchored_at: i64,
    pub submitter: Pubkey,
    pub bump: u8,
}

impl AnchorRecord {
    pub const LEN: usize = 8      // discriminator
        + 8                        // index
        + 8                        // batch_start
        + 8                        // batch_end
        + 32                       // batch_hash
        + 8                        // anchored_at
        + 32                       // submitter
        + 1;                       // bump
}

// ─── Contexts ──────────────────────────────────────────

#[derive(Accounts)]
pub struct InitializeAudit<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 8 + 8 + 1,
        seeds = [b"audit_store"],
        bump,
    )]
    pub store: Account<'info, AuditStore>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AnchorAuditCtx<'info> {
    #[account(
        mut,
        seeds = [b"audit_store"],
        bump = store.bump,
        has_one = admin,
    )]
    pub store: Account<'info, AuditStore>,
    #[account(
        init,
        payer = admin,
        space = AnchorRecord::LEN,
        seeds = [b"anchor", &store.anchor_count.to_le_bytes()],
        bump,
    )]
    pub anchor_record: Account<'info, AnchorRecord>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

// ─── Errors ────────────────────────────────────────────

#[error_code]
pub enum AuditError {
    #[msg("Invalid batch range: start > end")]
    InvalidRange,
    #[msg("Batch overlaps with previous anchor")]
    BatchOverlap,
}

// ─── Handlers ──────────────────────────────────────────

pub fn initialize_audit(ctx: Context<InitializeAudit>) -> Result<()> {
    let store = &mut ctx.accounts.store;
    store.admin = ctx.accounts.admin.key();
    store.anchor_count = 0;
    store.last_batch_end = 0;
    store.bump = ctx.bumps.store;
    Ok(())
}

pub fn anchor_audit(
    ctx: Context<AnchorAuditCtx>,
    batch_start: u64,
    batch_end: u64,
    batch_hash: [u8; 32],
) -> Result<()> {
    require!(batch_start <= batch_end, AuditError::InvalidRange);

    let store = &mut ctx.accounts.store;
    if store.anchor_count > 0 {
        require!(batch_start > store.last_batch_end, AuditError::BatchOverlap);
    }

    let clock = Clock::get()?;
    let record = &mut ctx.accounts.anchor_record;
    record.index = store.anchor_count;
    record.batch_start = batch_start;
    record.batch_end = batch_end;
    record.batch_hash = batch_hash;
    record.anchored_at = clock.unix_timestamp;
    record.submitter = ctx.accounts.admin.key();
    record.bump = ctx.bumps.anchor_record;

    store.anchor_count += 1;
    store.last_batch_end = batch_end;

    Ok(())
}

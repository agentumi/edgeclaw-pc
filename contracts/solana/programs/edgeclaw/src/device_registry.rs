//! EdgeClaw Device Registry — Solana Anchor
//!
//! PDA-based device identity registry.

use anchor_lang::prelude::*;

/// Maximum public key string length.
const MAX_PK_LEN: usize = 128;
/// Maximum device name length.
const MAX_NAME_LEN: usize = 64;
/// Maximum device type length.
const MAX_TYPE_LEN: usize = 32;

// ─── Accounts ──────────────────────────────────────────

/// Global registry state (PDA).
#[account]
pub struct RegistryState {
    /// Admin pubkey.
    pub admin: Pubkey,
    /// Total registered devices.
    pub device_count: u64,
    /// Bump seed.
    pub bump: u8,
}

/// Individual device record (PDA derived from public_key).
#[account]
pub struct DeviceRecord {
    /// Ed25519 public key (hex string).
    pub public_key: String,
    /// Human-readable name.
    pub device_name: String,
    /// Device type.
    pub device_type: String,
    /// Owner wallet.
    pub owner: Pubkey,
    /// Registration timestamp (Unix).
    pub registered_at: i64,
    /// Active flag.
    pub active: bool,
    /// Bump seed.
    pub bump: u8,
}

impl DeviceRecord {
    pub const LEN: usize = 8  // discriminator
        + 4 + MAX_PK_LEN      // public_key
        + 4 + MAX_NAME_LEN    // device_name
        + 4 + MAX_TYPE_LEN    // device_type
        + 32                   // owner
        + 8                    // registered_at
        + 1                    // active
        + 1;                   // bump
}

// ─── Contexts ──────────────────────────────────────────

#[derive(Accounts)]
pub struct InitializeRegistry<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 8 + 1,
        seeds = [b"registry"],
        bump,
    )]
    pub registry: Account<'info, RegistryState>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(public_key: String)]
pub struct RegisterDevice<'info> {
    #[account(mut, seeds = [b"registry"], bump = registry.bump)]
    pub registry: Account<'info, RegistryState>,
    #[account(
        init,
        payer = owner,
        space = DeviceRecord::LEN,
        seeds = [b"device", public_key.as_bytes()],
        bump,
    )]
    pub device: Account<'info, DeviceRecord>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DeactivateDevice<'info> {
    #[account(mut, seeds = [b"registry"], bump = registry.bump)]
    pub registry: Account<'info, RegistryState>,
    #[account(
        mut,
        constraint = device.owner == authority.key() || registry.admin == authority.key()
            @ ErrorCode::Unauthorized,
    )]
    pub device: Account<'info, DeviceRecord>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReactivateDevice<'info> {
    #[account(seeds = [b"registry"], bump = registry.bump)]
    pub registry: Account<'info, RegistryState>,
    #[account(
        mut,
        constraint = device.owner == authority.key() || registry.admin == authority.key()
            @ ErrorCode::Unauthorized,
    )]
    pub device: Account<'info, DeviceRecord>,
    pub authority: Signer<'info>,
}

// ─── Errors ────────────────────────────────────────────

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized: not owner or admin")]
    Unauthorized,
    #[msg("Device is already inactive")]
    AlreadyInactive,
    #[msg("Device is already active")]
    AlreadyActive,
}

// ─── Handlers ──────────────────────────────────────────

pub fn initialize_registry(ctx: Context<InitializeRegistry>) -> Result<()> {
    let registry = &mut ctx.accounts.registry;
    registry.admin = ctx.accounts.admin.key();
    registry.device_count = 0;
    registry.bump = ctx.bumps.registry;
    Ok(())
}

pub fn register_device(
    ctx: Context<RegisterDevice>,
    public_key: String,
    device_name: String,
    device_type: String,
) -> Result<()> {
    let clock = Clock::get()?;
    let device = &mut ctx.accounts.device;
    device.public_key = public_key;
    device.device_name = device_name;
    device.device_type = device_type;
    device.owner = ctx.accounts.owner.key();
    device.registered_at = clock.unix_timestamp;
    device.active = true;
    device.bump = ctx.bumps.device;

    let registry = &mut ctx.accounts.registry;
    registry.device_count += 1;

    Ok(())
}

pub fn deactivate_device(ctx: Context<DeactivateDevice>) -> Result<()> {
    let device = &mut ctx.accounts.device;
    require!(device.active, ErrorCode::AlreadyInactive);
    device.active = false;
    Ok(())
}

pub fn reactivate_device(ctx: Context<ReactivateDevice>) -> Result<()> {
    let device = &mut ctx.accounts.device;
    require!(!device.active, ErrorCode::AlreadyActive);
    device.active = true;
    Ok(())
}

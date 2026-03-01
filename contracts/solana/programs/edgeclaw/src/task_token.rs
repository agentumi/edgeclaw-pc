//! EdgeClaw Task Token (ECLAW) — Solana Anchor
//!
//! SPL Token based utility token for task execution accounting.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, MintTo, Token, TokenAccount};

// ─── Accounts ──────────────────────────────────────────

/// Token authority state (PDA).
#[account]
pub struct TokenAuthority {
    pub admin: Pubkey,
    pub mint: Pubkey,
    pub total_minted: u64,
    pub bump: u8,
}

// ─── Contexts ──────────────────────────────────────────

#[derive(Accounts)]
#[instruction(decimals: u8)]
pub struct InitializeToken<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 32 + 8 + 1,
        seeds = [b"token_authority"],
        bump,
    )]
    pub authority: Account<'info, TokenAuthority>,
    #[account(
        init,
        payer = admin,
        mint::decimals = decimals,
        mint::authority = authority,
        seeds = [b"eclaw_mint"],
        bump,
    )]
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct MintTokens<'info> {
    #[account(
        seeds = [b"token_authority"],
        bump = authority.bump,
        has_one = admin,
    )]
    pub authority: Account<'info, TokenAuthority>,
    #[account(
        mut,
        seeds = [b"eclaw_mint"],
        bump,
    )]
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub recipient_token_account: Account<'info, TokenAccount>,
    pub admin: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct RewardTask<'info> {
    #[account(
        mut,
        seeds = [b"token_authority"],
        bump = authority.bump,
        has_one = admin,
    )]
    pub authority: Account<'info, TokenAuthority>,
    #[account(
        mut,
        seeds = [b"eclaw_mint"],
        bump,
    )]
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub executor_token_account: Account<'info, TokenAccount>,
    pub admin: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

// ─── Errors ────────────────────────────────────────────

#[error_code]
pub enum TokenError {
    #[msg("Unauthorized: not admin")]
    Unauthorized,
    #[msg("Amount must be > 0")]
    ZeroAmount,
}

// ─── Handlers ──────────────────────────────────────────

pub fn initialize_token(ctx: Context<InitializeToken>, _decimals: u8) -> Result<()> {
    let authority = &mut ctx.accounts.authority;
    authority.admin = ctx.accounts.admin.key();
    authority.mint = ctx.accounts.mint.key();
    authority.total_minted = 0;
    authority.bump = ctx.bumps.authority;
    Ok(())
}

pub fn mint_tokens(ctx: Context<MintTokens>, amount: u64) -> Result<()> {
    require!(amount > 0, TokenError::ZeroAmount);

    let seeds = &[b"token_authority".as_ref(), &[ctx.accounts.authority.bump]];
    let signer = &[&seeds[..]];

    token::mint_to(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
            signer,
        ),
        amount,
    )?;

    Ok(())
}

pub fn reward_task(
    ctx: Context<RewardTask>,
    _task_id: [u8; 32],
    amount: u64,
) -> Result<()> {
    require!(amount > 0, TokenError::ZeroAmount);

    let authority = &mut ctx.accounts.authority;
    let seeds = &[b"token_authority".as_ref(), &[authority.bump]];
    let signer = &[&seeds[..]];

    token::mint_to(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.executor_token_account.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
            signer,
        ),
        amount,
    )?;

    authority.total_minted += amount;

    Ok(())
}

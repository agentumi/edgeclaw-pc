/// EdgeClaw Micro Escrow — SUI Move
///
/// Handles task-based payments, deposits, and slashing logic.
/// Users deposit SUI or ECLAW into escrow; agents are paid upon success.
module edgeclaw::micro_escrow {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use edgeclaw::task_token::TASK_TOKEN;
    use edgeclaw::reputation::{Self, ReputationRegistry, ValidatorCap};
    use std::string::String;

    // ─── Errors ────────────────────────────────────────────

    const E_INSUFFICIENT_FUNDS: u64 = 1;
    const E_TASK_ALREADY_SETTLED: u64 = 2;

    // ─── Objects ───────────────────────────────────────────

    /// Individual escrow record for a task.
    public struct Escrow has key {
        id: UID,
        task_id: String,
        client: address,
        agent_key: String,
        amount: Balance<TASK_TOKEN>,
        is_settled: bool,
    }

    // ─── Public Functions ──────────────────────────────────

    /// Open a new escrow for a task.
    public fun open_escrow(
        task_id: String,
        agent_key: String,
        payment: Coin<TASK_TOKEN>,
        ctx: &mut TxContext,
    ) {
        let escrow = Escrow {
            id: object::new(ctx),
            task_id,
            client: tx_context::sender(ctx),
            agent_key,
            amount: coin::into_balance(payment),
            is_settled: false,
        };
        transfer::share_object(escrow);
    }

    /// Settle escrow: pay agent upon success.
    public fun settle_success(
        escrow: &mut Escrow,
        val_cap: &ValidatorCap,
        registry: &mut ReputationRegistry,
        agent_address: address,
        ctx: &mut TxContext,
    ) {
        assert!(!escrow.is_settled, E_TASK_ALREADY_SETTLED);
        escrow.is_settled = true;

        let total = balance::value(&escrow.amount);
        let payment = coin::from_balance(balance::split(&mut escrow.amount, total), ctx);
        transfer::public_transfer(payment, agent_address);

        // Boost reputation
        reputation::update_score(val_cap, registry, escrow.agent_key, 5, ctx);
    }

    /// Settle escrow: slash agent upon protocol violation / failure.
    public fun settle_slash(
        escrow: &mut Escrow,
        val_cap: &ValidatorCap,
        registry: &mut ReputationRegistry,
        ctx: &mut TxContext,
    ) {
        assert!(!escrow.is_settled, E_TASK_ALREADY_SETTLED);
        escrow.is_settled = true;

        // Return funds to client
        let total = balance::value(&escrow.amount);
        let refund = coin::from_balance(balance::split(&mut escrow.amount, total), ctx);
        transfer::public_transfer(refund, escrow.client);

        // Penalty to reputation
        reputation::update_score(val_cap, registry, escrow.agent_key, -20, ctx);
    }

    // ─── View Functions ────────────────────────────────────
    
    public fun amount(e: &Escrow): u64 {
        balance::value(&e.amount)
    }
}

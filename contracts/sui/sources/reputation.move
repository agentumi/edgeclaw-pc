/// EdgeClaw Reputation Registry — SUI Move
///
/// Manages proof-of-performance (PoP) scores for agents.
/// Scores are updated based on successful task completions or slashed for failures.
module edgeclaw::reputation {
    use std::string::String;
    use sui::table::{Self, Table};
    use sui::event;

    // ─── Errors ────────────────────────────────────────────

    const E_NOT_AUTHORIZED: u64 = 1;

    // ─── Objects ───────────────────────────────────────────

    /// Global reputation store.
    public struct ReputationRegistry has key {
        id: UID,
        /// Agent public_key (hex) -> current score.
        scores: Table<String, u64>,
    }

    /// Capability to update scores (granted to validators/escrow).
    public struct ValidatorCap has key, store {
        id: UID,
    }

    // ─── Events ────────────────────────────────────────────

    public struct ScoreUpdated has copy, drop {
        agent_key: String,
        delta: i64,
        new_score: u64,
    }

    // ─── Init ──────────────────────────────────────────────

    fun init(ctx: &mut TxContext) {
        let registry = ReputationRegistry {
            id: object::new(ctx),
            scores: table::new(ctx),
        };
        transfer::share_object(registry);

        let cap = ValidatorCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    // ─── Public Functions ──────────────────────────────────

    /// Update an agent's reputation score.
    public fun update_score(
        _cap: &ValidatorCap,
        registry: &mut ReputationRegistry,
        agent_key: String,
        delta: i64,
        _ctx: &mut TxContext,
    ) {
        if (!table::contains(&registry.scores, agent_key)) {
            table::add(&mut registry.scores, agent_key, 100); // Initial score 100
        };

        let current = table::borrow_mut(&mut registry.scores, agent_key);
        let mut new_val: u64;
        
        if (delta >= 0) {
            new_val = *current + (delta as u64);
        } else {
            let abs_delta = ((-delta) as u64);
            if (*current > abs_delta) {
                new_val = *current - abs_delta;
            } else {
                new_val = 0;
            }
        };

        *current = new_val;

        event::emit(ScoreUpdated {
            agent_key,
            delta,
            new_score: new_val,
        });
    }

    // ─── View Functions ────────────────────────────────────

    public fun get_score(registry: &ReputationRegistry, agent_key: String): u64 {
        if (!table::contains(&registry.scores, agent_key)) {
            return 100
        };
        *table::borrow(&registry.scores, agent_key)
    }
}

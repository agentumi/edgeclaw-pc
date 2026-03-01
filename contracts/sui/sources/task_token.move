/// EdgeClaw Task Token (ECLAW) — SUI Move
///
/// Fungible token used for task execution accounting, staking,
/// and reputation incentives within the EdgeClaw network.
module edgeclaw::task_token {
    use sui::coin::{Self, TreasuryCap, Coin};
    use sui::event;

    // ─── OTW ───────────────────────────────────────────────

    /// One-Time Witness for coin creation.
    public struct TASK_TOKEN has drop {}

    // ─── Events ────────────────────────────────────────────

    public struct TokensMinted has copy, drop {
        amount: u64,
        recipient: address,
    }

    public struct TokensBurned has copy, drop {
        amount: u64,
        burner: address,
    }

    public struct TaskReward has copy, drop {
        task_id: vector<u8>,
        amount: u64,
        executor: address,
    }

    // ─── Init ──────────────────────────────────────────────

    #[allow(deprecated_usage, lint(public_entry))]
    fun init(witness: TASK_TOKEN, ctx: &mut TxContext) {
        let (treasury_cap, metadata) = coin::create_currency(
            witness,
            9, // decimals
            b"ECLAW",
            b"EdgeClaw Task Token",
            b"Utility token for EdgeClaw edge-computing task execution",
            option::none(),
            ctx,
        );
        transfer::public_freeze_object(metadata);
        transfer::public_transfer(treasury_cap, tx_context::sender(ctx));
    }

    // ─── Minting ───────────────────────────────────────────

    /// Mint new ECLAW tokens to a recipient.
    public fun mint(
        treasury_cap: &mut TreasuryCap<TASK_TOKEN>,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext,
    ) {
        let minted = coin::mint(treasury_cap, amount, ctx);
        transfer::public_transfer(minted, recipient);

        event::emit(TokensMinted { amount, recipient });
    }

    /// Burn ECLAW tokens.
    public fun burn(
        treasury_cap: &mut TreasuryCap<TASK_TOKEN>,
        coin: Coin<TASK_TOKEN>,
        ctx: &mut TxContext,
    ) {
        let amount = coin::value(&coin);
        coin::burn(treasury_cap, coin);

        event::emit(TokensBurned { amount, burner: tx_context::sender(ctx) });
    }

    /// Reward a task executor.
    public fun reward_task(
        treasury_cap: &mut TreasuryCap<TASK_TOKEN>,
        task_id: vector<u8>,
        amount: u64,
        executor: address,
        ctx: &mut TxContext,
    ) {
        let minted = coin::mint(treasury_cap, amount, ctx);
        transfer::public_transfer(minted, executor);

        event::emit(TaskReward { task_id, amount, executor });
    }

    // ─── View ──────────────────────────────────────────────

    /// Get total supply.
    public fun total_supply(treasury_cap: &TreasuryCap<TASK_TOKEN>): u64 {
        coin::total_supply(treasury_cap)
    }
}

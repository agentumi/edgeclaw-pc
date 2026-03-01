/// EdgeClaw Task Token (ECLAW) — Aptos Move
///
/// Fungible asset (FA) token for task execution rewards.
/// Uses Aptos Coin standard for minting, burning, and transfer.
module edgeclaw::task_token {
    use std::string;
    use std::signer;
    use std::error;
    use aptos_framework::coin::{Self, MintCapability, BurnCapability};
    use aptos_framework::event;

    // ─── Errors ────────────────────────────────────────────

    const E_NOT_ADMIN: u64 = 200;
    const E_ZERO_AMOUNT: u64 = 201;
    const E_NOT_INITIALIZED: u64 = 202;

    // ─── Coin Type ─────────────────────────────────────────

    /// ECLAW coin type marker.
    struct ECLAW {}

    // ─── Resources ─────────────────────────────────────────

    struct TokenAdmin has key {
        mint_cap: MintCapability<ECLAW>,
        burn_cap: BurnCapability<ECLAW>,
        admin: address,
        total_minted: u64,
    }

    // ─── Events ────────────────────────────────────────────

    #[event]
    struct TokensMinted has drop, store {
        amount: u64,
        recipient: address,
    }

    #[event]
    struct TaskReward has drop, store {
        task_id: vector<u8>,
        amount: u64,
        executor: address,
    }

    // ─── Init ──────────────────────────────────────────────

    /// Initialize the ECLAW token. Must be called by the module publisher.
    public entry fun initialize(account: &signer) {
        let (burn_cap, freeze_cap, mint_cap) = coin::initialize<ECLAW>(
            account,
            string::utf8(b"EdgeClaw Task Token"),
            string::utf8(b"ECLAW"),
            9, // decimals
            true, // monitor supply
        );

        // We don't need freeze capability
        coin::destroy_freeze_cap(freeze_cap);

        move_to(account, TokenAdmin {
            mint_cap,
            burn_cap,
            admin: signer::address_of(account),
            total_minted: 0,
        });
    }

    // ─── Public Functions ──────────────────────────────────

    /// Mint ECLAW tokens to a recipient. Admin only.
    public entry fun mint(
        account: &signer,
        admin_addr: address,
        recipient: address,
        amount: u64,
    ) acquires TokenAdmin {
        let admin_store = borrow_global_mut<TokenAdmin>(admin_addr);
        assert!(signer::address_of(account) == admin_store.admin, error::permission_denied(E_NOT_ADMIN));
        assert!(amount > 0, error::invalid_argument(E_ZERO_AMOUNT));

        let coins = coin::mint(amount, &admin_store.mint_cap);
        coin::deposit(recipient, coins);
        admin_store.total_minted = admin_store.total_minted + amount;

        event::emit(TokensMinted { amount, recipient });
    }

    /// Reward a task executor. Admin only.
    public entry fun reward_task(
        account: &signer,
        admin_addr: address,
        task_id: vector<u8>,
        executor: address,
        amount: u64,
    ) acquires TokenAdmin {
        let admin_store = borrow_global_mut<TokenAdmin>(admin_addr);
        assert!(signer::address_of(account) == admin_store.admin, error::permission_denied(E_NOT_ADMIN));
        assert!(amount > 0, error::invalid_argument(E_ZERO_AMOUNT));

        let coins = coin::mint(amount, &admin_store.mint_cap);
        coin::deposit(executor, coins);
        admin_store.total_minted = admin_store.total_minted + amount;

        event::emit(TaskReward { task_id, amount, executor });
    }

    // ─── View ──────────────────────────────────────────────

    #[view]
    public fun total_minted(admin_addr: address): u64 acquires TokenAdmin {
        borrow_global<TokenAdmin>(admin_addr).total_minted
    }

    #[view]
    public fun balance(account_addr: address): u64 {
        if (coin::is_account_registered<ECLAW>(account_addr)) {
            coin::balance<ECLAW>(account_addr)
        } else {
            0
        }
    }
}

/// EdgeClaw Policy NFT — Aptos Move
///
/// RBAC policy NFTs using Aptos Token V2 standard concepts.
/// Each policy encodes a role, capabilities, expiry, and revocation status.
module edgeclaw::policy_nft {
    use std::string::{Self, String};
    use std::signer;
    use std::error;
    use std::vector;
    use aptos_std::table::{Self, Table};
    use aptos_framework::event;
    use aptos_framework::timestamp;

    // ─── Errors ────────────────────────────────────────────

    const E_NOT_ADMIN: u64 = 100;
    const E_INVALID_ROLE: u64 = 101;
    const E_POLICY_NOT_FOUND: u64 = 102;
    const E_ALREADY_REVOKED: u64 = 103;
    const E_NOT_ISSUER: u64 = 104;

    // ─── Resources ─────────────────────────────────────────

    struct PolicyStore has key {
        policies: Table<u64, PolicyRecord>,
        next_id: u64,
        admin: address,
    }

    struct PolicyRecord has store, drop, copy {
        policy_id: u64,
        owner: address,
        role: String,
        capabilities: vector<String>,
        expires_at: u64,
        issuer: address,
        created_at: u64,
        revoked: bool,
    }

    // ─── Events ────────────────────────────────────────────

    #[event]
    struct PolicyMinted has drop, store {
        policy_id: u64,
        owner: address,
        role: String,
        issuer: address,
    }

    #[event]
    struct PolicyRevoked has drop, store {
        policy_id: u64,
        revoked_by: address,
    }

    // ─── Init ──────────────────────────────────────────────

    public entry fun initialize(account: &signer) {
        let addr = signer::address_of(account);
        move_to(account, PolicyStore {
            policies: table::new(),
            next_id: 0,
            admin: addr,
        });
    }

    // ─── Public Functions ──────────────────────────────────

    /// Mint a new policy NFT. Admin only.
    public entry fun mint_policy(
        account: &signer,
        store_addr: address,
        owner: address,
        role: String,
        capabilities: vector<String>,
        expires_at: u64,
    ) acquires PolicyStore {
        let store = borrow_global_mut<PolicyStore>(store_addr);
        let sender = signer::address_of(account);
        assert!(sender == store.admin, error::permission_denied(E_NOT_ADMIN));
        assert!(is_valid_role(&role), error::invalid_argument(E_INVALID_ROLE));

        let policy_id = store.next_id;
        let record = PolicyRecord {
            policy_id,
            owner,
            role,
            capabilities,
            expires_at,
            issuer: sender,
            created_at: timestamp::now_seconds(),
            revoked: false,
        };

        table::add(&mut store.policies, policy_id, record);
        store.next_id = policy_id + 1;

        event::emit(PolicyMinted { policy_id, owner, role, issuer: sender });
    }

    /// Revoke a policy. Issuer or admin only.
    public entry fun revoke_policy(
        account: &signer,
        store_addr: address,
        policy_id: u64,
    ) acquires PolicyStore {
        let store = borrow_global_mut<PolicyStore>(store_addr);
        assert!(table::contains(&store.policies, policy_id), error::not_found(E_POLICY_NOT_FOUND));

        let record = table::borrow_mut(&mut store.policies, policy_id);
        let sender = signer::address_of(account);
        assert!(sender == record.issuer || sender == store.admin, error::permission_denied(E_NOT_ISSUER));
        assert!(!record.revoked, error::invalid_state(E_ALREADY_REVOKED));

        record.revoked = true;
        event::emit(PolicyRevoked { policy_id, revoked_by: sender });
    }

    // ─── View ──────────────────────────────────────────────

    #[view]
    public fun is_policy_valid(store_addr: address, policy_id: u64): bool acquires PolicyStore {
        let store = borrow_global<PolicyStore>(store_addr);
        if (!table::contains(&store.policies, policy_id)) return false;
        let record = table::borrow(&store.policies, policy_id);
        if (record.revoked) return false;
        if (record.expires_at > 0 && timestamp::now_seconds() > record.expires_at) return false;
        true
    }

    #[view]
    public fun policy_count(store_addr: address): u64 acquires PolicyStore {
        borrow_global<PolicyStore>(store_addr).next_id
    }

    // ─── Internal ──────────────────────────────────────────

    fun is_valid_role(role: &String): bool {
        *role == string::utf8(b"owner") ||
        *role == string::utf8(b"admin") ||
        *role == string::utf8(b"operator") ||
        *role == string::utf8(b"viewer") ||
        *role == string::utf8(b"guest")
    }
}

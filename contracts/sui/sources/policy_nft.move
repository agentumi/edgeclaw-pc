/// EdgeClaw Policy NFT — SUI Move
///
/// RBAC policies are minted as non-fungible tokens. Each PolicyNFT encodes
/// a role, a set of capabilities, an expiry epoch, and the issuer identity.
/// Policies can be verified on-chain and revoked by the issuer or admin.
module edgeclaw::policy_nft {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;
    use std::string::{Self, String};
    use std::vector;

    // ─── Errors ────────────────────────────────────────────

    const E_NOT_ISSUER: u64 = 100;
    const E_POLICY_EXPIRED: u64 = 101;
    const E_POLICY_REVOKED: u64 = 102;
    const E_INVALID_ROLE: u64 = 103;

    // ─── Objects ───────────────────────────────────────────

    /// Admin capability — granted to deployer.
    struct AdminCap has key, store {
        id: UID,
    }

    /// A Policy NFT representing an RBAC assignment.
    struct PolicyNFT has key, store {
        id: UID,
        /// Owner address.
        owner: address,
        /// Role string ("owner", "admin", "operator", "viewer", "guest").
        role: String,
        /// Granted capability strings.
        capabilities: vector<String>,
        /// Expiry epoch (0 = never).
        expires_at: u64,
        /// Issuer address.
        issuer: address,
        /// Creation epoch.
        created_at: u64,
        /// Revocation flag.
        revoked: bool,
    }

    // ─── Events ────────────────────────────────────────────

    struct PolicyMinted has copy, drop {
        policy_id: address,
        owner: address,
        role: String,
        issuer: address,
    }

    struct PolicyRevoked has copy, drop {
        policy_id: address,
        revoked_by: address,
    }

    // ─── Init ──────────────────────────────────────────────

    fun init(ctx: &mut TxContext) {
        let admin_cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin_cap, tx_context::sender(ctx));
    }

    // ─── Public Functions ──────────────────────────────────

    /// Mint a new Policy NFT and transfer it to `owner`.
    public entry fun mint_policy(
        _admin: &AdminCap,
        owner: address,
        role: vector<u8>,
        capabilities: vector<vector<u8>>,
        expires_at: u64,
        ctx: &mut TxContext,
    ) {
        let role_str = string::utf8(role);
        assert!(is_valid_role(&role_str), E_INVALID_ROLE);

        let caps = vector::empty<String>();
        let i = 0;
        let len = vector::length(&capabilities);
        while (i < len) {
            vector::push_back(&mut caps, string::utf8(*vector::borrow(&capabilities, i)));
            i = i + 1;
        };

        let uid = object::new(ctx);
        let policy_id = object::uid_to_address(&uid);

        let nft = PolicyNFT {
            id: uid,
            owner,
            role: role_str,
            capabilities: caps,
            expires_at,
            issuer: tx_context::sender(ctx),
            created_at: tx_context::epoch(ctx),
            revoked: false,
        };

        event::emit(PolicyMinted {
            policy_id,
            owner,
            role: role_str,
            issuer: tx_context::sender(ctx),
        });

        transfer::transfer(nft, owner);
    }

    /// Revoke a policy NFT. Only the original issuer or admin can revoke.
    public entry fun revoke_policy(
        policy: &mut PolicyNFT,
        ctx: &mut TxContext,
    ) {
        assert!(tx_context::sender(ctx) == policy.issuer, E_NOT_ISSUER);
        assert!(!policy.revoked, E_POLICY_REVOKED);
        policy.revoked = true;
        event::emit(PolicyRevoked {
            policy_id: object::uid_to_address(&policy.id),
            revoked_by: tx_context::sender(ctx),
        });
    }

    /// Admin-force revoke (for emergency revocations).
    public entry fun admin_revoke(
        _admin: &AdminCap,
        policy: &mut PolicyNFT,
        ctx: &mut TxContext,
    ) {
        policy.revoked = true;
        event::emit(PolicyRevoked {
            policy_id: object::uid_to_address(&policy.id),
            revoked_by: tx_context::sender(ctx),
        });
    }

    // ─── View Functions ────────────────────────────────────

    /// Check if policy is still valid (not revoked, not expired).
    public fun is_valid(policy: &PolicyNFT, current_epoch: u64): bool {
        if (policy.revoked) return false;
        if (policy.expires_at > 0 && current_epoch > policy.expires_at) return false;
        true
    }

    /// Get the role of a policy.
    public fun role(policy: &PolicyNFT): String {
        policy.role
    }

    /// Check revocation status.
    public fun is_revoked(policy: &PolicyNFT): bool {
        policy.revoked
    }

    // ─── Internal ──────────────────────────────────────────

    fun is_valid_role(role: &String): bool {
        let r = role;
        *r == string::utf8(b"owner") ||
        *r == string::utf8(b"admin") ||
        *r == string::utf8(b"operator") ||
        *r == string::utf8(b"viewer") ||
        *r == string::utf8(b"guest")
    }
}

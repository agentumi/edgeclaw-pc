/// EdgeClaw Agent Passport — SUI Move
///
/// An Agent Passport is a non-transferable NFT (soulbound-like) that represents
/// an AI agent's identity, tier, and verified status.
module edgeclaw::agent_passport {
    use std::string::{Self, String};
    use sui::event;

    // ─── Errors ────────────────────────────────────────────

    const E_NOT_AUTHORIZED: u64 = 1;
    const E_ALREADY_VERIFIED: u64 = 2;

    // ─── Objects ───────────────────────────────────────────

    /// The Passport NFT.
    public struct AgentPassport has key, store {
        id: UID,
        /// Agent's unique name/identifier.
        name: String,
        /// Public key (hex) corresponding to the agent's identity.
        public_key: String,
        /// Agent tier (e.g., "L1", "L2", "L3").
        tier: String,
        /// Whether the agent is verified by a trusted authority.
        verified: bool,
        /// Current reputation score (mirrored from reputation module).
        reputation: u64,
        /// Time of creation.
        created_at: u64,
    }

    /// Authority capability to manage/verify passports.
    public struct AuthorityCap has key {
        id: UID,
    }

    // ─── Events ────────────────────────────────────────────

    public struct PassportMinted has copy, drop {
        id: ID,
        owner: address,
        name: String,
    }

    public struct PassportVerified has copy, drop {
        id: ID,
        by: address,
    }

    // ─── Init ──────────────────────────────────────────────

    fun init(ctx: &mut TxContext) {
        let cap = AuthorityCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    // ─── Public Functions ──────────────────────────────────

    /// Mint a new Agent Passport.
    public fun mint(
        name: vector<u8>,
        public_key: vector<u8>,
        ctx: &mut TxContext,
    ) {
        let id = object::new(ctx);
        let passport_id = object::uid_to_inner(&id);
        let sender = tx_context::sender(ctx);

        let passport = AgentPassport {
            id,
            name: string::utf8(name),
            public_key: string::utf8(public_key),
            tier: string::utf8(b"L1"),
            verified: false,
            reputation: 0,
            created_at: tx_context::epoch(ctx),
        };

        event::emit(PassportMinted {
            id: passport_id,
            owner: sender,
            name: string::utf8(name),
        });

        transfer::transfer(passport, sender);
    }

    /// Verify an agent passport. Requires AuthorityCap.
    public fun verify(
        _cap: &AuthorityCap,
        passport: &mut AgentPassport,
        ctx: &mut TxContext,
    ) {
        assert!(!passport.verified, E_ALREADY_VERIFIED);
        passport.verified = true;
        passport.tier = string::utf8(b"L2"); // Upgrade to L2 upon verification

        event::emit(PassportVerified {
            id: object::uid_to_inner(&passport.id),
            by: tx_context::sender(ctx),
        });
    }

    /// Update reputation (internal use or by authority).
    public fun update_reputation(
        _cap: &AuthorityCap,
        passport: &mut AgentPassport,
        new_score: u64,
    ) {
        passport.reputation = new_score;
    }

    // ─── View Functions ────────────────────────────────────

    public fun name(p: &AgentPassport): String { p.name }
    public fun tier(p: &AgentPassport): String { p.tier }
    public fun is_verified(p: &AgentPassport): bool { p.verified }
}

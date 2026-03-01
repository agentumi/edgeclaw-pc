/// EdgeClaw Audit Anchor — Aptos Move
///
/// On-chain anchoring of audit log batch hashes for immutable verification.
module edgeclaw::audit_anchor {
    use std::string::{Self, String};
    use std::signer;
    use std::error;
    use aptos_std::table::{Self, Table};
    use aptos_framework::event;
    use aptos_framework::timestamp;

    // ─── Errors ────────────────────────────────────────────

    const E_NOT_ADMIN: u64 = 300;
    const E_INVALID_RANGE: u64 = 301;
    const E_BATCH_OVERLAP: u64 = 302;

    // ─── Resources ─────────────────────────────────────────

    struct AuditStore has key {
        anchors: Table<u64, AnchorRecord>,
        anchor_count: u64,
        last_batch_end: u64,
        admin: address,
    }

    struct AnchorRecord has store, drop, copy {
        index: u64,
        batch_start: u64,
        batch_end: u64,
        batch_hash: String,
        anchored_at: u64,
        submitter: address,
    }

    // ─── Events ────────────────────────────────────────────

    #[event]
    struct AuditAnchored has drop, store {
        index: u64,
        batch_start: u64,
        batch_end: u64,
        batch_hash: String,
        submitter: address,
    }

    // ─── Init ──────────────────────────────────────────────

    public entry fun initialize(account: &signer) {
        let addr = signer::address_of(account);
        move_to(account, AuditStore {
            anchors: table::new(),
            anchor_count: 0,
            last_batch_end: 0,
            admin: addr,
        });
    }

    // ─── Public Functions ──────────────────────────────────

    /// Anchor an audit batch hash. Admin only.
    public entry fun anchor_audit(
        account: &signer,
        store_addr: address,
        batch_start: u64,
        batch_end: u64,
        batch_hash: String,
    ) acquires AuditStore {
        let store = borrow_global_mut<AuditStore>(store_addr);
        let sender = signer::address_of(account);
        assert!(sender == store.admin, error::permission_denied(E_NOT_ADMIN));
        assert!(batch_start <= batch_end, error::invalid_argument(E_INVALID_RANGE));

        if (store.anchor_count > 0) {
            assert!(batch_start > store.last_batch_end, error::invalid_state(E_BATCH_OVERLAP));
        };

        let index = store.anchor_count;
        let record = AnchorRecord {
            index,
            batch_start,
            batch_end,
            batch_hash,
            anchored_at: timestamp::now_seconds(),
            submitter: sender,
        };

        table::add(&mut store.anchors, index, record);
        store.anchor_count = index + 1;
        store.last_batch_end = batch_end;

        event::emit(AuditAnchored {
            index,
            batch_start,
            batch_end,
            batch_hash,
            submitter: sender,
        });
    }

    // ─── View ──────────────────────────────────────────────

    #[view]
    public fun anchor_count(store_addr: address): u64 acquires AuditStore {
        borrow_global<AuditStore>(store_addr).anchor_count
    }

    #[view]
    public fun last_batch_end(store_addr: address): u64 acquires AuditStore {
        borrow_global<AuditStore>(store_addr).last_batch_end
    }

    #[view]
    public fun verify_chain(store_addr: address): bool acquires AuditStore {
        let store = borrow_global<AuditStore>(store_addr);
        if (store.anchor_count <= 1) return true;

        let i = 1;
        while (i < store.anchor_count) {
            let prev = table::borrow(&store.anchors, i - 1);
            let curr = table::borrow(&store.anchors, i);
            if (curr.batch_start <= prev.batch_end) return false;
            i = i + 1;
        };
        true
    }
}

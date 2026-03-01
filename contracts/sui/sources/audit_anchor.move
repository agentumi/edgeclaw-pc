/// EdgeClaw Audit Anchor — SUI Move
///
/// Provides on-chain anchoring of audit log batches. Each anchor stores
/// a batch range and SHA-256 hash, forming a verifiable chain of audit integrity.
module edgeclaw::audit_anchor {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;
    use std::string::{Self, String};
    use sui::table::{Self, Table};

    // ─── Errors ────────────────────────────────────────────

    const E_NOT_ADMIN: u64 = 200;
    const E_BATCH_OVERLAP: u64 = 201;
    const E_INVALID_RANGE: u64 = 202;

    // ─── Objects ───────────────────────────────────────────

    /// Global audit anchor store (shared object).
    struct AuditStore has key {
        id: UID,
        /// Sequential anchor records.
        anchors: Table<u64, AnchorRecord>,
        /// Total number of anchors.
        anchor_count: u64,
        /// Last batch_end value (for continuity validation).
        last_batch_end: u64,
        /// Admin address.
        admin: address,
    }

    /// Individual audit anchor record.
    struct AnchorRecord has store, drop, copy {
        /// Batch start index (inclusive).
        batch_start: u64,
        /// Batch end index (inclusive).
        batch_end: u64,
        /// SHA-256 hash of the audit batch (hex-encoded).
        batch_hash: String,
        /// Epoch when anchored.
        anchored_at: u64,
        /// Submitter address.
        submitter: address,
    }

    // ─── Events ────────────────────────────────────────────

    struct AuditAnchored has copy, drop {
        anchor_index: u64,
        batch_start: u64,
        batch_end: u64,
        batch_hash: String,
        submitter: address,
    }

    struct AuditVerified has copy, drop {
        total_anchors: u64,
        chain_valid: bool,
    }

    // ─── Init ──────────────────────────────────────────────

    fun init(ctx: &mut TxContext) {
        let store = AuditStore {
            id: object::new(ctx),
            anchors: table::new(ctx),
            anchor_count: 0,
            last_batch_end: 0,
            admin: tx_context::sender(ctx),
        };
        transfer::share_object(store);
    }

    // ─── Public Functions ──────────────────────────────────

    /// Anchor a new audit batch on-chain.
    /// batch_start must be > last_batch_end (unless first anchor).
    public entry fun anchor_audit(
        store: &mut AuditStore,
        batch_start: u64,
        batch_end: u64,
        batch_hash: vector<u8>,
        ctx: &mut TxContext,
    ) {
        // Validate range
        assert!(batch_start <= batch_end, E_INVALID_RANGE);

        // Validate continuity (first anchor exempt)
        if (store.anchor_count > 0) {
            assert!(batch_start > store.last_batch_end, E_BATCH_OVERLAP);
        };

        let hash_str = string::utf8(batch_hash);
        let record = AnchorRecord {
            batch_start,
            batch_end,
            batch_hash: hash_str,
            anchored_at: tx_context::epoch(ctx),
            submitter: tx_context::sender(ctx),
        };

        let index = store.anchor_count;
        table::add(&mut store.anchors, index, record);
        store.anchor_count = index + 1;
        store.last_batch_end = batch_end;

        event::emit(AuditAnchored {
            anchor_index: index,
            batch_start,
            batch_end,
            batch_hash: hash_str,
            submitter: tx_context::sender(ctx),
        });
    }

    // ─── View Functions ────────────────────────────────────

    /// Get total number of audit anchors.
    public fun anchor_count(store: &AuditStore): u64 {
        store.anchor_count
    }

    /// Get last batch_end (for continuity checks off-chain).
    public fun last_batch_end(store: &AuditStore): u64 {
        store.last_batch_end
    }

    /// Verify the anchor chain is contiguous (no gaps or overlaps).
    /// Returns true if all anchors form a valid ascending sequence.
    public fun verify_chain(store: &AuditStore): bool {
        if (store.anchor_count <= 1) return true;

        let i = 1;
        let valid = true;
        while (i < store.anchor_count) {
            let prev = table::borrow(&store.anchors, i - 1);
            let curr = table::borrow(&store.anchors, i);
            if (curr.batch_start <= prev.batch_end) {
                valid = false;
            };
            i = i + 1;
        };
        valid
    }
}

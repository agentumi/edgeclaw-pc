/// EdgeClaw Device Registry — SUI Move
///
/// Manages on-chain device identity registration, lookup, and lifecycle.
/// Each device is represented as a shared object storing its Ed25519 public key,
/// name, type, and active status.
module edgeclaw::device_registry {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;
    use std::string::{Self, String};
    use sui::table::{Self, Table};

    // ─── Errors ────────────────────────────────────────────

    const E_ALREADY_REGISTERED: u64 = 1;
    const E_NOT_FOUND: u64 = 2;
    const E_NOT_OWNER: u64 = 3;
    const E_DEVICE_INACTIVE: u64 = 4;

    // ─── Objects ───────────────────────────────────────────

    /// Global registry (shared object).
    struct Registry has key {
        id: UID,
        /// public_key (hex string) → DeviceRecord
        devices: Table<String, DeviceRecord>,
        /// Total registered device count.
        device_count: u64,
        /// Admin address (deployer).
        admin: address,
    }

    /// Individual device record.
    struct DeviceRecord has store, drop, copy {
        /// Ed25519 public key (hex-encoded).
        public_key: String,
        /// Human-readable device name.
        device_name: String,
        /// Device type (e.g., "desktop", "mobile", "iot").
        device_type: String,
        /// Owner address that registered the device.
        owner: address,
        /// Registration epoch.
        registered_at: u64,
        /// Whether the device is active.
        active: bool,
    }

    // ─── Events ────────────────────────────────────────────

    struct DeviceRegistered has copy, drop {
        public_key: String,
        device_name: String,
        device_type: String,
        owner: address,
    }

    struct DeviceDeactivated has copy, drop {
        public_key: String,
        deactivated_by: address,
    }

    struct DeviceReactivated has copy, drop {
        public_key: String,
        reactivated_by: address,
    }

    // ─── Init ──────────────────────────────────────────────

    fun init(ctx: &mut TxContext) {
        let registry = Registry {
            id: object::new(ctx),
            devices: table::new(ctx),
            device_count: 0,
            admin: tx_context::sender(ctx),
        };
        transfer::share_object(registry);
    }

    // ─── Public Functions ──────────────────────────────────

    /// Register a new device. Aborts if public_key already registered.
    public entry fun register_device(
        registry: &mut Registry,
        public_key: vector<u8>,
        device_name: vector<u8>,
        device_type: vector<u8>,
        ctx: &mut TxContext,
    ) {
        let pk_str = string::utf8(public_key);
        assert!(!table::contains(&registry.devices, pk_str), E_ALREADY_REGISTERED);

        let record = DeviceRecord {
            public_key: pk_str,
            device_name: string::utf8(device_name),
            device_type: string::utf8(device_type),
            owner: tx_context::sender(ctx),
            registered_at: tx_context::epoch(ctx),
            active: true,
        };

        table::add(&mut registry.devices, pk_str, record);
        registry.device_count = registry.device_count + 1;

        event::emit(DeviceRegistered {
            public_key: pk_str,
            device_name: string::utf8(device_name),
            device_type: string::utf8(device_type),
            owner: tx_context::sender(ctx),
        });
    }

    /// Deactivate a device. Only owner or admin may do this.
    public entry fun deactivate_device(
        registry: &mut Registry,
        public_key: vector<u8>,
        ctx: &mut TxContext,
    ) {
        let pk_str = string::utf8(public_key);
        assert!(table::contains(&registry.devices, pk_str), E_NOT_FOUND);

        let record = table::borrow_mut(&mut registry.devices, pk_str);
        let sender = tx_context::sender(ctx);
        assert!(sender == record.owner || sender == registry.admin, E_NOT_OWNER);

        record.active = false;
        event::emit(DeviceDeactivated { public_key: pk_str, deactivated_by: sender });
    }

    /// Reactivate a device. Only owner or admin may do this.
    public entry fun reactivate_device(
        registry: &mut Registry,
        public_key: vector<u8>,
        ctx: &mut TxContext,
    ) {
        let pk_str = string::utf8(public_key);
        assert!(table::contains(&registry.devices, pk_str), E_NOT_FOUND);

        let record = table::borrow_mut(&mut registry.devices, pk_str);
        let sender = tx_context::sender(ctx);
        assert!(sender == record.owner || sender == registry.admin, E_NOT_OWNER);

        record.active = true;
        event::emit(DeviceReactivated { public_key: pk_str, reactivated_by: sender });
    }

    // ─── View Functions ────────────────────────────────────

    /// Check if a device is registered.
    public fun is_registered(registry: &Registry, public_key: String): bool {
        table::contains(&registry.devices, public_key)
    }

    /// Get device count.
    public fun device_count(registry: &Registry): u64 {
        registry.device_count
    }

    /// Get device active status. Aborts if not found.
    public fun is_active(registry: &Registry, public_key: String): bool {
        assert!(table::contains(&registry.devices, public_key), E_NOT_FOUND);
        let record = table::borrow(&registry.devices, public_key);
        record.active
    }
}

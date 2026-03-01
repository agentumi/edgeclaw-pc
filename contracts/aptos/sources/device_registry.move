/// EdgeClaw Device Registry — Aptos Move
///
/// On-chain device identity management for the Aptos blockchain.
/// Uses a global resource for the registry with Table-based device storage.
module edgeclaw::device_registry {
    use std::string::{Self, String};
    use std::signer;
    use std::error;
    use aptos_std::table::{Self, Table};
    use aptos_framework::event;
    use aptos_framework::timestamp;

    // ─── Errors ────────────────────────────────────────────

    const E_ALREADY_REGISTERED: u64 = 1;
    const E_NOT_FOUND: u64 = 2;
    const E_NOT_AUTHORIZED: u64 = 3;
    const E_NOT_INITIALIZED: u64 = 4;

    // ─── Resources ─────────────────────────────────────────

    struct Registry has key {
        devices: Table<String, DeviceRecord>,
        device_count: u64,
        admin: address,
    }

    struct DeviceRecord has store, drop, copy {
        public_key: String,
        device_name: String,
        device_type: String,
        owner: address,
        registered_at: u64,
        active: bool,
    }

    // ─── Events ────────────────────────────────────────────

    #[event]
    struct DeviceRegistered has drop, store {
        public_key: String,
        device_name: String,
        owner: address,
    }

    #[event]
    struct DeviceStatusChanged has drop, store {
        public_key: String,
        active: bool,
        changed_by: address,
    }

    // ─── Init ──────────────────────────────────────────────

    /// Initialize the device registry. Must be called by the module publisher.
    public entry fun initialize(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<Registry>(addr), error::already_exists(E_ALREADY_REGISTERED));

        move_to(account, Registry {
            devices: table::new(),
            device_count: 0,
            admin: addr,
        });
    }

    // ─── Public Functions ──────────────────────────────────

    /// Register a new device.
    public entry fun register_device(
        account: &signer,
        registry_addr: address,
        public_key: String,
        device_name: String,
        device_type: String,
    ) acquires Registry {
        let registry = borrow_global_mut<Registry>(registry_addr);
        assert!(!table::contains(&registry.devices, public_key), error::already_exists(E_ALREADY_REGISTERED));

        let owner = signer::address_of(account);
        let record = DeviceRecord {
            public_key,
            device_name,
            device_type,
            owner,
            registered_at: timestamp::now_seconds(),
            active: true,
        };

        table::add(&mut registry.devices, public_key, record);
        registry.device_count = registry.device_count + 1;

        event::emit(DeviceRegistered {
            public_key,
            device_name,
            owner,
        });
    }

    /// Deactivate a device.
    public entry fun deactivate_device(
        account: &signer,
        registry_addr: address,
        public_key: String,
    ) acquires Registry {
        let registry = borrow_global_mut<Registry>(registry_addr);
        assert!(table::contains(&registry.devices, public_key), error::not_found(E_NOT_FOUND));

        let record = table::borrow_mut(&mut registry.devices, public_key);
        let sender = signer::address_of(account);
        assert!(sender == record.owner || sender == registry.admin, error::permission_denied(E_NOT_AUTHORIZED));

        record.active = false;
        event::emit(DeviceStatusChanged { public_key, active: false, changed_by: sender });
    }

    /// Reactivate a device.
    public entry fun reactivate_device(
        account: &signer,
        registry_addr: address,
        public_key: String,
    ) acquires Registry {
        let registry = borrow_global_mut<Registry>(registry_addr);
        assert!(table::contains(&registry.devices, public_key), error::not_found(E_NOT_FOUND));

        let record = table::borrow_mut(&mut registry.devices, public_key);
        let sender = signer::address_of(account);
        assert!(sender == record.owner || sender == registry.admin, error::permission_denied(E_NOT_AUTHORIZED));

        record.active = true;
        event::emit(DeviceStatusChanged { public_key, active: true, changed_by: sender });
    }

    // ─── View ──────────────────────────────────────────────

    #[view]
    public fun device_count(registry_addr: address): u64 acquires Registry {
        borrow_global<Registry>(registry_addr).device_count
    }

    #[view]
    public fun is_device_active(registry_addr: address, public_key: String): bool acquires Registry {
        let registry = borrow_global<Registry>(registry_addr);
        if (!table::contains(&registry.devices, public_key)) return false;
        table::borrow(&registry.devices, public_key).active
    }
}

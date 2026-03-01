/// EdgeClaw SUI Move — Unit Tests
///
/// Tests for all 4 modules: device_registry, policy_nft, task_token, audit_anchor.
/// Run: `sui move test`

#[test_only]
module edgeclaw::device_registry_tests {
    use sui::test_scenario::{Self as ts, Scenario};
    use edgeclaw::device_registry::{Self, Registry};

    const ADMIN: address = @0xAD;
    const USER1: address = @0xA1;
    const USER2: address = @0xA2;

    fun setup(scenario: &mut Scenario) {
        ts::next_tx(scenario, ADMIN);
        {
            device_registry::init_for_testing(ts::ctx(scenario));
        };
    }

    #[test]
    fun test_register_device() {
        let mut scenario = ts::begin(ADMIN);
        setup(&mut scenario);

        // Register a device as USER1
        ts::next_tx(&mut scenario, USER1);
        {
            let mut registry = ts::take_shared<Registry>(&scenario);
            device_registry::register_device(
                &mut registry,
                b"ed25519_pubkey_hex_001",
                b"desktop-alpha",
                b"desktop",
                ts::ctx(&mut scenario),
            );
            assert!(device_registry::device_count(&registry) == 1, 0);
            assert!(device_registry::is_registered(&registry, std::string::utf8(b"ed25519_pubkey_hex_001")), 1);
            ts::return_shared(registry);
        };

        ts::end(scenario);
    }

    #[test]
    fun test_register_multiple_devices() {
        let mut scenario = ts::begin(ADMIN);
        setup(&mut scenario);

        ts::next_tx(&mut scenario, USER1);
        {
            let mut registry = ts::take_shared<Registry>(&scenario);
            device_registry::register_device(
                &mut registry, b"key_001", b"dev1", b"desktop", ts::ctx(&mut scenario),
            );
            device_registry::register_device(
                &mut registry, b"key_002", b"dev2", b"mobile", ts::ctx(&mut scenario),
            );
            assert!(device_registry::device_count(&registry) == 2, 0);
            ts::return_shared(registry);
        };

        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 1)] // E_ALREADY_REGISTERED
    fun test_duplicate_registration_fails() {
        let mut scenario = ts::begin(ADMIN);
        setup(&mut scenario);

        ts::next_tx(&mut scenario, USER1);
        {
            let mut registry = ts::take_shared<Registry>(&scenario);
            device_registry::register_device(
                &mut registry, b"same_key", b"dev1", b"desktop", ts::ctx(&mut scenario),
            );
            device_registry::register_device(
                &mut registry, b"same_key", b"dev2", b"mobile", ts::ctx(&mut scenario),
            );
            ts::return_shared(registry);
        };

        ts::end(scenario);
    }

    #[test]
    fun test_deactivate_device() {
        let mut scenario = ts::begin(ADMIN);
        setup(&mut scenario);

        ts::next_tx(&mut scenario, USER1);
        {
            let mut registry = ts::take_shared<Registry>(&scenario);
            device_registry::register_device(
                &mut registry, b"key_deact", b"dev", b"desktop", ts::ctx(&mut scenario),
            );
            ts::return_shared(registry);
        };

        ts::next_tx(&mut scenario, USER1);
        {
            let mut registry = ts::take_shared<Registry>(&scenario);
            device_registry::deactivate_device(&mut registry, b"key_deact", ts::ctx(&mut scenario));
            assert!(!device_registry::is_active(&registry, std::string::utf8(b"key_deact")), 0);
            ts::return_shared(registry);
        };

        ts::end(scenario);
    }

    #[test]
    fun test_reactivate_device() {
        let mut scenario = ts::begin(ADMIN);
        setup(&mut scenario);

        ts::next_tx(&mut scenario, USER1);
        {
            let mut registry = ts::take_shared<Registry>(&scenario);
            device_registry::register_device(
                &mut registry, b"key_react", b"dev", b"desktop", ts::ctx(&mut scenario),
            );
            device_registry::deactivate_device(&mut registry, b"key_react", ts::ctx(&mut scenario));
            device_registry::reactivate_device(&mut registry, b"key_react", ts::ctx(&mut scenario));
            assert!(device_registry::is_active(&registry, std::string::utf8(b"key_react")), 0);
            ts::return_shared(registry);
        };

        ts::end(scenario);
    }

    #[test]
    fun test_admin_can_deactivate() {
        let mut scenario = ts::begin(ADMIN);
        setup(&mut scenario);

        ts::next_tx(&mut scenario, USER1);
        {
            let mut registry = ts::take_shared<Registry>(&scenario);
            device_registry::register_device(
                &mut registry, b"key_admin_deact", b"dev", b"desktop", ts::ctx(&mut scenario),
            );
            ts::return_shared(registry);
        };

        // Admin deactivates USER1's device
        ts::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = ts::take_shared<Registry>(&scenario);
            device_registry::deactivate_device(&mut registry, b"key_admin_deact", ts::ctx(&mut scenario));
            assert!(!device_registry::is_active(&registry, std::string::utf8(b"key_admin_deact")), 0);
            ts::return_shared(registry);
        };

        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 3)] // E_NOT_OWNER
    fun test_unauthorized_deactivate_fails() {
        let mut scenario = ts::begin(ADMIN);
        setup(&mut scenario);

        ts::next_tx(&mut scenario, USER1);
        {
            let mut registry = ts::take_shared<Registry>(&scenario);
            device_registry::register_device(
                &mut registry, b"key_unauth", b"dev", b"desktop", ts::ctx(&mut scenario),
            );
            ts::return_shared(registry);
        };

        // USER2 tries to deactivate USER1's device
        ts::next_tx(&mut scenario, USER2);
        {
            let mut registry = ts::take_shared<Registry>(&scenario);
            device_registry::deactivate_device(&mut registry, b"key_unauth", ts::ctx(&mut scenario));
            ts::return_shared(registry);
        };

        ts::end(scenario);
    }
}

#[test_only]
module edgeclaw::audit_anchor_tests {
    use sui::test_scenario::{Self as ts, Scenario};
    use edgeclaw::audit_anchor::{Self, AuditStore};

    const ADMIN: address = @0xAD;

    fun setup(scenario: &mut Scenario) {
        ts::next_tx(scenario, ADMIN);
        {
            audit_anchor::init_for_testing(ts::ctx(scenario));
        };
    }

    #[test]
    fun test_anchor_first_batch() {
        let mut scenario = ts::begin(ADMIN);
        setup(&mut scenario);

        ts::next_tx(&mut scenario, ADMIN);
        {
            let mut store = ts::take_shared<AuditStore>(&scenario);
            audit_anchor::anchor_audit(&mut store, 0, 99, b"abcdef1234567890abcdef1234567890", ts::ctx(&mut scenario));
            assert!(audit_anchor::anchor_count(&store) == 1, 0);
            assert!(audit_anchor::last_batch_end(&store) == 99, 1);
            ts::return_shared(store);
        };

        ts::end(scenario);
    }

    #[test]
    fun test_anchor_sequential_batches() {
        let mut scenario = ts::begin(ADMIN);
        setup(&mut scenario);

        ts::next_tx(&mut scenario, ADMIN);
        {
            let mut store = ts::take_shared<AuditStore>(&scenario);
            audit_anchor::anchor_audit(&mut store, 0, 99, b"hash_batch_1_xxxxxxxxxxxxxxxx", ts::ctx(&mut scenario));
            audit_anchor::anchor_audit(&mut store, 100, 199, b"hash_batch_2_xxxxxxxxxxxxxxxx", ts::ctx(&mut scenario));
            audit_anchor::anchor_audit(&mut store, 200, 299, b"hash_batch_3_xxxxxxxxxxxxxxxx", ts::ctx(&mut scenario));
            assert!(audit_anchor::anchor_count(&store) == 3, 0);
            assert!(audit_anchor::last_batch_end(&store) == 299, 1);
            assert!(audit_anchor::verify_chain(&store), 2);
            ts::return_shared(store);
        };

        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 201)] // E_BATCH_OVERLAP
    fun test_overlapping_batch_fails() {
        let mut scenario = ts::begin(ADMIN);
        setup(&mut scenario);

        ts::next_tx(&mut scenario, ADMIN);
        {
            let mut store = ts::take_shared<AuditStore>(&scenario);
            audit_anchor::anchor_audit(&mut store, 0, 99, b"hash_1_xxxxxxxxxxxxxxxxxxxxxxxxx", ts::ctx(&mut scenario));
            audit_anchor::anchor_audit(&mut store, 50, 149, b"hash_2_xxxxxxxxxxxxxxxxxxxxxxxxx", ts::ctx(&mut scenario)); // overlap!
            ts::return_shared(store);
        };

        ts::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = 202)] // E_INVALID_RANGE
    fun test_invalid_range_fails() {
        let mut scenario = ts::begin(ADMIN);
        setup(&mut scenario);

        ts::next_tx(&mut scenario, ADMIN);
        {
            let mut store = ts::take_shared<AuditStore>(&scenario);
            audit_anchor::anchor_audit(&mut store, 100, 50, b"hash_inv_xxxxxxxxxxxxxxxxxxxxxxx", ts::ctx(&mut scenario)); // start > end
            ts::return_shared(store);
        };

        ts::end(scenario);
    }

    #[test]
    fun test_verify_empty_chain() {
        let mut scenario = ts::begin(ADMIN);
        setup(&mut scenario);

        ts::next_tx(&mut scenario, ADMIN);
        {
            let store = ts::take_shared<AuditStore>(&scenario);
            assert!(audit_anchor::verify_chain(&store), 0);
            ts::return_shared(store);
        };

        ts::end(scenario);
    }
}

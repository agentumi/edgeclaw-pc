#![no_main]
use libfuzzer_sys::fuzz_target;
use edgeclaw_agent::policy::PolicyEngine;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string for role/capability
    if data.len() < 2 {
        return;
    }
    let mid = data.len() / 2;
    let role = String::from_utf8_lossy(&data[..mid]);
    let capability = String::from_utf8_lossy(&data[mid..]);

    // Policy evaluation must never panic on arbitrary inputs
    let engine = PolicyEngine::new();
    let _ = engine.evaluate(&capability, &role);
});

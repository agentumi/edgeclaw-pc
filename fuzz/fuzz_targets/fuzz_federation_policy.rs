#![no_main]
use libfuzzer_sys::fuzz_target;
use edgeclaw_agent::federation::{DataSharingLevel, ConfidentialLevel, FederationPolicy};

fuzz_target!(|data: &[u8]| {
    // Fuzz federation policy JSON deserialization — must never panic
    let _ = serde_json::from_slice::<FederationPolicy>(data);
    let _ = serde_json::from_slice::<DataSharingLevel>(data);
    let _ = serde_json::from_slice::<ConfidentialLevel>(data);
});

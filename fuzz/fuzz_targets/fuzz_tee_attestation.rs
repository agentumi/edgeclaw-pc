#![no_main]
use libfuzzer_sys::fuzz_target;
use edgeclaw_agent::tee::{AttestationReport, SealedData, EnclaveConfig, TeePlatform};

fuzz_target!(|data: &[u8]| {
    // Fuzz TEE attestation report deserialization — must never panic
    let _ = serde_json::from_slice::<AttestationReport>(data);
    let _ = serde_json::from_slice::<SealedData>(data);
    let _ = serde_json::from_slice::<EnclaveConfig>(data);
    let _ = serde_json::from_slice::<TeePlatform>(data);
});

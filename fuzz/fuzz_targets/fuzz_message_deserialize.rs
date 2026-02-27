#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to parse arbitrary bytes as JSON messages — must never panic
    let _ = serde_json::from_slice::<edgeclaw_agent::protocol::EcmPayload>(data);
    let _ = serde_json::from_slice::<edgeclaw_agent::protocol::EapPayload>(data);
    let _ = serde_json::from_slice::<edgeclaw_agent::protocol::HeartbeatPayload>(data);
    let _ = serde_json::from_slice::<edgeclaw_agent::sync::SyncMessage>(data);
    let _ = serde_json::from_slice::<edgeclaw_agent::updater::UpdateManifest>(data);
});

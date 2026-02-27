#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the WASM ECNP encode/decode roundtrip — must never panic
    if data.is_empty() {
        return;
    }
    let msg_type = data[0];
    let payload = &data[1..];
    let frame = edgeclaw_agent::wasm::wasm_ecnp_encode(msg_type, payload);
    let _ = edgeclaw_agent::wasm::wasm_ecnp_decode(&frame);
    let _ = edgeclaw_agent::wasm::wasm_ecnp_validate(&frame);
    let _ = edgeclaw_agent::wasm::wasm_ecnp_validate(data);
});

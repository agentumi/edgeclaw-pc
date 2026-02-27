#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to decode arbitrary bytes as ECNP frames — must never panic
    let _ = edgeclaw_agent::ecnp::FrameCodec::decode(data);
});
